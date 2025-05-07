import paramiko
import socket
import os
import datetime
import time
from collections import defaultdict

# Giriş izleme ve saldırı tespiti için veri yapıları
login_attempts = defaultdict(list)
ddos_tracker = defaultdict(list)

# Log fonksiyonu
def log_connection(honeypot_type, ip, port, details="Connection attempt"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{honeypot_type}] [IP: {ip}] [Port: {port}] {details}\n"
    with open("honeynet_logs.txt", "a") as log_file:
        log_file.write(log_line)

# DDoS tespiti: 10 saniyede >20 bağlantı
def detect_ddos(ip):
    now = time.time()
    ddos_tracker[ip].append(now)
    ddos_tracker[ip] = [t for t in ddos_tracker[ip] if now - t <= 10]
    return len(ddos_tracker[ip]) > 20

# Brute-force tespiti: 1 dakikada >6 deneme
def detect_brute_force(ip):
    now = time.time()
    login_attempts[ip].append(now)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t <= 60]
    return len(login_attempts[ip]) > 6

# Sahte terminal kabuğu
def fake_shell(channel, username):
    try:
        channel.send(f"Welcome to fake SSH shell, {username}!\n")
        channel.send("Type 'help' for available commands.\n\n")

        while True:
            channel.send(f"{username}@honeypot:~$ ")
            command = ""
            while not command.endswith("\n"):
                data = channel.recv(1024).decode("utf-8")
                if not data:
                    return
                command += data

            command = command.strip()
            if not command:
                continue

            log_connection("SSH", channel.getpeername()[0], channel.getpeername()[1], f"Command executed: {command}")

            if command == "help":
                channel.send("Available commands: ls, pwd, whoami, uptime, cat, echo, exit\n")
            elif command == "ls":
                channel.send("bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  tmp  usr  var\n")
            elif command == "pwd":
                channel.send("/root\n")
            elif command == "whoami":
                channel.send(f"{username}\n")
            elif command == "uptime":
                channel.send(" 10:23:45 up 5 days,  2:34,  1 user,  load average: 0.00, 0.01, 0.05\n")
            elif command.startswith("cat "):
                channel.send(f"cat: {command.split(' ', 1)[1]}: No such file or directory\n")
            elif command.startswith("echo "):
                message = command.split(" ", 1)[1]
                channel.send(message + "\n")
            elif command == "exit":
                channel.send("Bye!\n")
                break
            else:
                channel.send(f"bash: {command}: command not found\n")
    except Exception as e:
        print(f"[!] Fake shell hatası: {str(e)}")

# SSH Honeypot Server
class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None

    def check_auth_password(self, username, password):
        print(f"[*] Deneme: Kullanıcı={username} Parola={password}")

        # DDoS kontrolü
        if detect_ddos(self.client_ip):
            log_connection("SSH", self.client_ip, self.client_port, "!!! DDoS DETECTED !!!")
            return paramiko.AUTH_FAILED

        # Brute-force kontrolü
        if detect_brute_force(self.client_ip):
            log_connection("SSH", self.client_ip, self.client_port, "!!! Brute Force DETECTED !!!")

        valid_users = {
            "testuser": "password123",
            "root": "toor",
            "admin": "admin123"
        }

        if username in valid_users and password == valid_users[username]:
            print(f"[+] Doğru giriş: {username} [SUCCESS]")
            log_connection("SSH", self.client_ip, self.client_port, f"User: {username} Password: {password} [RESULT: SUCCESS]")
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[-] Hatalı giriş: {username} [FAIL]")
            log_connection("SSH", self.client_ip, self.client_port, f"User: {username} Password: {password} [RESULT: FAIL]")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

# RSA anahtar yükle/oluştur
def load_rsa_key():
    if not os.path.exists("id_rsa"):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file("id_rsa")
    return paramiko.RSAKey(filename="id_rsa")

# Honeypot başlatıcı
def start_ssh_honeypot(host="0.0.0.0", port=2222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)
    print(f"[+] SSH Honeypot listening on {host}:{port}...")

    host_key = load_rsa_key()

    while True:
        client_socket, addr = server_socket.accept()
        client_ip, client_port = addr
        print(f"[!] SSH connection attempt from {client_ip}:{client_port}")

        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(host_key)
            server = SSHHoneypotServer(client_ip, client_port)
            transport.start_server(server=server)

            channel = transport.accept(20)
            if channel is None:
                print("[!] Kanal oluşturulamadı.")
                continue

            # Fake shell başlat
            fake_shell(channel, server.username)
            channel.close()

        except Exception as e:
            print(f"[!] Hata oluştu: {str(e)}")

if __name__ == "__main__":
    start_ssh_honeypot()
