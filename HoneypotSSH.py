import paramiko
import socket
import os
import datetime
import time
from collections import defaultdict

start_time = time.time()

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
        channel.sendall(f"Welcome to fake SSH shell, {username}!\n")
        channel.sendall("Type 'help' for available commands.\n\n")

        while True:
            channel.sendall(f"{username}@honeypot:~$ ")
            command = ""

            try:
                while True:
                    data = channel.recv(1024)
                    if not data:
                        print("[!] Boş veri algılandı, bağlantı kesilmiş olabilir.")
                        return

                    decode = data.decode("utf-8", errors="ignore")

                    if decode == "\r": 
                         channel.sendall("\r\n")
                         break

                    elif decode == "\x7f" or decode == "\b":
                         if len(command) > 0 :
                              command = command[:-1]
                              channel.sendall("\b")
                    else:
                         command += decode
                         channel.sendall(decode)

            except Exception as e:
                print(f"[!] recv() hatası: {str(e)}")
                return

            command = command.strip()
            if not command:
                continue

            log_connection("SSH", channel.getpeername()[0], channel.getpeername()[1], f"Command executed: {command}")
            if command == "help":
                channel.sendall("Available commands: ls, pwd, whoami, uptime, echo, ls /home, ls /root, cat /etc/passwd, cat /etc/shadow, ps aux, ip a, reboot, exit\n")
            elif command == "ls":
                channel.sendall("bin  boot  dev  etc  lib  media  mnt  opt  proc  root  run  sbin  srv  tmp  usr  var\n")
            elif command == "pwd":
                channel.sendall("/home\n")
            elif command == "whoami":
                channel.sendall(f"{username}\n")
            elif command == "uptime":
                uptime_sec = int(time.time() - start_time)
                days       = uptime_sec // 86400
                hours      = (uptime_sec % 86400) // 3600
                minutes    = (uptime_sec % 3600) // 60

                # Basit sahte yük ortalaması:
                load1  = round(0.05 + (uptime_sec % 13) * 0.01, 2)
                load5  = round(load1 + 0.02, 2)
                load15 = round(load5 + 0.03, 2)

                now_str = time.strftime("%H:%M:%S")
                out = (f" {now_str} up {days} days, {hours}:{minutes:02d},  1 user,  "
                     f"load average: {load1:.2f}, {load5:.2f}, {load15:.2f}\n")
                channel.sendall(out)
            elif command.startswith("echo "):
                message = command.split(" ", 1)[1]
                channel.sendall(message + "\n")
            elif command == "ls /home":
                channel.sendall("admin  Users  Users2\n")
            elif command == "ls /root":
                channel.sendall(".bashrc  .profile  .bash_history  scripts  backups  secrets.txt  notes.txt\n")
            elif command == "ls /etc":
                channel.sendall("passwd  shadow  hostname  hosts  network  ssh  cron.d  resolv.conf  systemd\n")
            elif command == "cat /etc/passwd":
                channel.sendall("root:x:0:0:root:/root:/bin/bash\nuser1:x:1001:1001:User One:/home/user1:/bin/bash\n")
            elif command == "cat /etc/shadow":
                channel.sendall("root:$6$abcdefgh$...:18000:0:99999:7:::\nuser1:$6$ijklmnop$...:18000:0:99999:7:::\n")
            elif command == "ps aux":
                channel.sendall("root       1  0.0  0.1  51234  1234 ?        Ss   15:23   0:01 /sbin/init\nuser1     1234  0.0  0.1  12345  6789 ?        S    15:25   0:00 sshd\n")
            elif command == "ip a":
                output = (
                     "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                     "\tlink/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                     "\tinet 127.0.0.1/8 scope host lo\n"
                     "\tvalid_lft forever preferred_lft forever\n"
                     "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000\n"
                     "link/ether 00:0c:29:68:22:5c brd ff:ff:ff:ff:ff:ff\n"
                     "inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0\n"
                     "valid_lft 86398sec preferred_lft 86398sec\n"
                )
                channel.sendall(output)
            elif command == "reboot":
                channel.sendall("System rebooting...\n")
                time.sleep(5)
                channel.sendall("System rebooted successfully.\n")

            elif command == "exit":
                channel.sendall("Bye!\n")
                break
            else:
                channel.sendall(f"bash: {command}: command not found\n")
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

    def check_channel_request(self, kind, chanid): 
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True  # pty desteğini burada sağlıyoruz.

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
            print("Channel:", channel)
            if channel is None:
                print("[!] Kanal oluşturulamadı.")
                continue

            # Fake shell başlat
            print("[+] Kanal açıldı.")
            fake_shell(channel, server.username)
            channel.close()

        except Exception as e:
            print(f"[!] Hata oluştu: {str(e)}")

if __name__ == "__main__":
    start_ssh_honeypot()
