import socket
import datetime
import time
from collections import defaultdict

# IP istek sayısını takip etmek için bir sözlük
request_counter = defaultdict(list)

# İşletim sistemi tespiti için fonksiyon
def detect_os(user_agent):
    user_agent = user_agent.lower()

    if "windows nt" in user_agent:
        return "Windows"
    elif "mac os x" in user_agent or "macintosh" in user_agent:
        return "macOS"
    elif "android" in user_agent:
        return "Android"
    elif "iphone" in user_agent or "ipad" in user_agent:
        return "iOS"
    elif "linux" in user_agent:
        return "Linux"
    elif "curl" in user_agent or "wget" in user_agent:
        if "win" in user_agent:
            return "Windows"
        else:
            return "Komut Satırı (Linux/macOS)"
    else:
        return "Bilinmiyor"

# Heuristik işletim sistemi tespiti
def heuristic_os_detection(ip, user_agent):
    ua = user_agent.lower()

    if any(os in ua for os in ["windows", "mac", "linux", "android", "iphone", "ipad"]):
        return detect_os(user_agent)

    if "curl" in ua or "wget" in ua:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return "Windows (curl/wget tahmini)"
        else:
            return "Komut Satırı (Linux/macOS)"

    return detect_os(user_agent)

# Exploit tespiti
def detect_exploit(request_data):
    # Directory Traversal Tespiti
    if "GET" in request_data:
        request_lines = request_data.splitlines()
        first_line = request_lines[0]  # GET satırı

        print(f"[DEBUG] İlk satır: {first_line}")

        # Path'i al
        path = first_line.split()[1]  # GET /path HTTP/1.1 formatından path'i al

        # Path'te /etc/passwd kontrolü
        if "/etc/passwd" in path:
            print(f"[DEBUG] Directory traversal tespit edildi: Hassas dosya erişimi")
            return "Directory Traversal Attack"

        # Encoded veya normal directory traversal kontrolü
        if (".." in path or 
            "%2E%2E" in path or 
            "../" in path or 
            "/.." in path):
            print(f"[DEBUG] Directory traversal tespit edildi: {path}")
            return "Directory Traversal Attack"
    
    # SQL Injection Tespiti
    if any(payload in request_data.lower() for payload in [
        "' or '1'='1",
        "' or '1'='1' --",
        "' OR '1'='1'",
        "' OR '1'='1' --",
        "' or 'a'='a",
        "\" or \"1\"=\"1",
        "' or 1=1/*",
        "' or 'x'='x",
        "'or'1'='1",
        "'or'1'='1' --",
        "'OR'1'='1'",
        "'OR'1'='1' --"
    ]):
        return "SQL Injection Attack"

    # XSS Tespiti
    elif any(payload in request_data.lower() for payload in [
        "<script>",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "alert(",
        "<img",
        "<iframe",
        "document.cookie",
        "eval(",
        "src=",
    ]):

        return "XSS (Cross-Site Scripting) Attack"

    if ip is not None and detect_ddos(ip):
        return "DDoS Attack"


    return None
# DDoS Tespiti: IP'den gelen istek sayısını kontrol eder
def detect_ddos(ip):
    current_time = time.time()
    # IP'den gelen isteği kaydet
    request_counter[ip].append(current_time)

    # Sadece son 10 saniye içindeki istekleri say
    request_counter[ip] = [timestamp for timestamp in request_counter[ip] if current_time - timestamp <= 10]

    if len(request_counter[ip]) > 20:
        return True
    return False

# Bağlantıların loglanması
def log_connection(honeypot_type, ip, port, details="Connection attempt", os="Bilinmiyor", exploit_type=None):
    log_file = "honeynet_logs.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if exploit_type:
        log_entry = f"[{timestamp}] [{honeypot_type}] [IP:{ip}] [Port:{port}] {details} [OS: {os}] [Exploit: {exploit_type}]\n"
    else:
        log_entry = f"[{timestamp}] [{honeypot_type}] [IP:{ip}] [Port:{port}] {details} [OS: {os}]\n"
    
    try:
        with open(log_file, "a") as log:
            log.write(log_entry)
    except Exception as e:
        print(f"Log kaydedilirken hata oluştu: {e}")

# HTTP Honeypot
def start_honeypot(host='0.0.0.0', port=8080):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        print(f"[*] Honeypot {port} portunda dinliyor...")

        while True:
            client, addr = server.accept()
            print(f"[!] Bağlantı tespit edildi: {addr[0]}:{addr[1]}")

            # DDoS tespiti
            if detect_ddos(addr[0]):
                print(f"[DDoS] {addr[0]} IP'sinden gelen çok fazla istek tespit edildi.")
                log_connection("HTTP", addr[0], addr[1], "DDoS Attack Detected", os="Bilinmiyor")
                client.close()
                continue  # DDoS tespit edildiyse, bağlantıyı kes

            try:
                request_data = client.recv(4096).decode('utf-8', errors='ignore')
                request_line = request_data.splitlines()[0] if request_data else "Boş istek"
                method = request_line.split()[0]
            except Exception as e:
                request_line = f"İstek alınamadı: {e}"
                method = None

            headers, _, body = request_data.partition("\r\n\r\n")

            # User-Agent çekme ve OS tespiti
            user_agent = ""
            for line in headers.splitlines():
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break
            os_name = heuristic_os_detection(addr[0], user_agent)

            # Exploit tespiti
            exploit_type = detect_exploit(request_data)

            # Loglama
            if method in ["POST", "PUT", "PATCH"]:
                form_data = {}
                for pair in body.strip().split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        form_data[key] = value
                log_connection("HTTP", addr[0], addr[1], f"Request: {method} Form Data: {form_data}", os=os_name, exploit_type=exploit_type)
            else:
                log_connection("HTTP", addr[0], addr[1], f"Request: {request_line} [User-Agent: {user_agent}]", os=os_name, exploit_type=exploit_type)

            # Yanıtlar
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n\r\n"
                "<html><body><h1>HTTP Honeypot</h1></body></html>"
            )

            client.sendall(response.encode('utf-8'))
            client.close()

    except Exception as e:
        print(f"Bir hata oluştu: {e}")

# Honeypot başlatma
if __name__ == "__main__":
    start_honeypot()
