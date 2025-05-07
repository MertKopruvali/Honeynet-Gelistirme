from http.server import BaseHTTPRequestHandler, HTTPServer
import datetime
import urllib.parse
from collections import defaultdict, deque
import time

# Başarısız girişleri takip için
failed_logins = defaultdict(int)

# DDoS tespiti için
request_times = defaultdict(lambda: deque())

# Log fonksiyonu
def log_connection(honeypot_type, ip, port, details="Connection attempt"):
    log_file = "honeynet_logs.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{honeypot_type}] [IP: {ip}] [Port: {port}] {details}\n"
    
    with open(log_file, "a") as log:
        log.write(log_entry)

# DDoS kontrol fonksiyonu
def check_ddos(ip):
    now = time.time()
    request_times[ip].append(now)

    # Son 10 saniye dışındaki istekleri temizle
    while request_times[ip] and now - request_times[ip][0] > 10:
        request_times[ip].popleft()

    # Eğer 20'den fazla istek varsa şüpheli
    if len(request_times[ip]) >= 20:
        log_connection("HTML", ip, "-", f"Possible DDoS Attack Detected! {len(request_times[ip])} requests in 10 seconds.")

# HTML Honeypot handler
class MyHoneypot(BaseHTTPRequestHandler):

    def log_and_respond(self, method, post_data=None):
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        request_line = self.requestline

        if "favicon.ico" not in request_line:
            log_connection("HTML", client_ip, client_port, f"{method} Request: {request_line}")
            if post_data:
                log_connection("HTML", client_ip, client_port, f"POST Data: {post_data}")
            print(f"[LOG] {client_ip}:{client_port} {request_line}")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        fake_html = """
            <html>
            <head><title>DevOps Admin Panel</title></head>
            <body>
                <h1>Welcome to DevOps Control Panel</h1>
                <p>Please login to manage your infrastructure.</p>
                <form action="/" method="post">
                    <label>Username:</label><br>
                    <input type="text" name="username"><br>
                    <label>Password:</label><br>
                    <input type="password" name="password"><br><br>
                    <input type="submit" value="Login">
                </form>
            </body>
            </html>
        """
        self.wfile.write(fake_html.encode('utf-8'))

    def do_GET(self):
        client_ip = self.client_address[0]
        check_ddos(client_ip)
        self.log_and_respond("GET")

    def do_POST(self):
        client_ip = self.client_address[0]
        check_ddos(client_ip)

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        parsed_data = urllib.parse.parse_qs(post_data)

        client_port = self.client_address[1]
        request_line = self.requestline

        if "favicon.ico" not in request_line:
            log_connection("HTML", client_ip, client_port, f"POST Request: {request_line}, Data: {parsed_data}")

        username = parsed_data.get('username', [''])[0]
        password = parsed_data.get('password', [''])[0]

        success = (username == "admin" and password == "password")

        if success:
            log_connection("HTML", client_ip, client_port, f"Login attempt (Successful): {username}")
            response = "<html><body><h1>Login Successful!</h1></body></html>"
            if client_ip in failed_logins:
                del failed_logins[client_ip]
        else:
            log_connection("HTML", client_ip, client_port, f"Login attempt (Failed): {username}")
            failed_logins[client_ip] += 1

            if failed_logins[client_ip] >= 5:
                log_connection("HTML", client_ip, client_port, f"Possible Brute Force Attack Detected! Failed attempts: {failed_logins[client_ip]}")
        
            response = "<html><body><h1>Login failed. Invalid credentials.</h1></body></html>"

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

# Sunucuyu başlat
if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8081), MyHoneypot)
    print("[*] HTML Honeypot started on port 8081...")
    server.serve_forever()
