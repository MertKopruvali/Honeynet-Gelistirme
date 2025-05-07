import re
from collections import defaultdict

# Dosya yolu
log_file_path = 'honeynet_logs.txt'

# HTTP analiz fonksiyonu
def analyze_http(logs):
    ip_count = defaultdict(int)
    request_types = defaultdict(int)

    for log in logs:
        ip = log.get('ip')
        request_type = log.get('request_type', 'Bilinmeyen')

        ip_count[ip] += 1
        request_types[request_type] += 1

    print("HTTP Analizi:")
    print(f"Toplam Erişim Sayısı: {len(logs)}")
    print("IP Adresi Dağılımı:")
    for ip, count in ip_count.items():
        print(f"{ip}: {count} kez")
    print("İstek Türleri:")
    for request, count in request_types.items():
        print(f"{request}: {count} kez")
    print("\n")

# HTML analiz fonksiyonu
def analyze_html(logs):
    ip_count = defaultdict(int)

    for log in logs:
        ip = log.get('ip')
        ip_count[ip] += 1

    print("HTML Analizi:")
    print(f"Toplam Erişim Sayısı: {len(logs)}")
    print("IP Adresi Dağılımı:")
    for ip, count in ip_count.items():
        print(f"{ip}: {count} kez")
    print("\n")

# SSH analiz fonksiyonu (başarı bilgisi dahil)
def analyze_ssh(logs):
    ip_count = defaultdict(int)
    user_attempts = defaultdict(int)
    result_count = {"SUCCESS": 0, "FAIL": 0}

    for log in logs:
        ip = log.get('ip')
        user = log.get('user', 'Bilinmeyen')
        result = log.get('result', 'Bilinmiyor')

        ip_count[ip] += 1
        user_attempts[user] += 1

        if result in result_count:
            result_count[result] += 1

    print("SSH Analizi:")
    print(f"Toplam Erişim Sayısı: {len(logs)}")
    print("IP Adresi Dağılımı:")
    for ip, count in ip_count.items():
        print(f"{ip}: {count} kez")
    print("Kullanıcı Adı Denemeleri:")
    for user, count in user_attempts.items():
        print(f"{user}: {count} kez")
    print("Başarılı / Başarısız Girişler:")
    print(f"Başarılı: {result_count['SUCCESS']}")
    print(f"Başarısız: {result_count['FAIL']}")
    print("\n")

# Log dosyasını oku
def read_log_file():
    logs_http = []
    logs_html = []
    logs_ssh = []

    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(r'\[(.*?)\] \[(HTTP|HTML|SSH)\] \[IP: ?([\d\.]+)\] \[Port: ?(\d+)\] (.*)', line.strip())
            if match:
                timestamp = match.group(1)
                honeypot_type = match.group(2)
                ip = match.group(3)
                port = match.group(4)
                request_info = match.group(5)

                log_data = {
                    'timestamp': timestamp,
                    'honeypot_type': honeypot_type,
                    'ip': ip,
                    'port': port,
                    'request_info': request_info
                }

                if honeypot_type == 'HTTP':
                    request_match = re.search(r'Request:\s*(GET|POST|PUT|DELETE|HEAD)', request_info)
                    if request_match:
                        log_data['request_type'] = request_match.group(1)
                    else:
                        log_data['request_type'] = 'Bilinmeyen'
                    logs_http.append(log_data)

                elif honeypot_type == 'HTML':
                    logs_html.append(log_data)

                elif honeypot_type == 'SSH':
                    user_match = re.search(r'User: (\S+)', request_info)
                    result_match = re.search(r'\[RESULT:\s*(\w+)\]', request_info)

                    if user_match:
                        log_data['user'] = user_match.group(1)
                    else:
                        log_data['user'] = 'Bilinmeyen'

                    if result_match:
                        log_data['result'] = result_match.group(1)
                    else:
                        log_data['result'] = 'Bilinmiyor'

                    logs_ssh.append(log_data)

    return logs_http, logs_html, logs_ssh

# Ana fonksiyon
def main():
    logs_http, logs_html, logs_ssh = read_log_file()
    analyze_http(logs_http)
    analyze_html(logs_html)
    analyze_ssh(logs_ssh)

# Kodun çalışmasını başlat
if __name__ == "__main__":
    main()
