from flask import Flask, render_template, request
from matplotlib.ticker import MaxNLocator
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import os
import re
import csv
from collections import defaultdict
from flask import redirect, url_for
from datetime import timedelta


app = Flask(__name__)


def generate_csv_files():
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

    # SSH analiz fonksiyonu
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

    # CSV'ye yazma fonksiyonu
    def export_to_csv(logs, filename, headers):
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            for log in logs:
                writer.writerow({key: log.get(key, "") for key in headers})

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
                        log_data['request_type'] = request_match.group(1) if request_match else 'Bilinmeyen'
                        logs_http.append(log_data)

                    elif honeypot_type == 'HTML':
                        logs_html.append(log_data)

                    elif honeypot_type == 'SSH':
                        user_match = re.search(r'User: (\S+)', request_info)
                        result_match = re.search(r'\[RESULT:\s*(\w+)\]', request_info)

                        log_data['user'] = user_match.group(1) if user_match else 'Bilinmeyen'
                        log_data['result'] = result_match.group(1) if result_match else 'Bilinmiyor'
                        logs_ssh.append(log_data)

        return logs_http, logs_html, logs_ssh

    # Ana fonksiyon
    def main():
        logs_http, logs_html, logs_ssh = read_log_file()

        # Analizleri yap
        analyze_http(logs_http)
        analyze_html(logs_html)
        analyze_ssh(logs_ssh)

        # CSV'ye yaz
        export_to_csv(logs_http, 'http_logs.csv', ['timestamp', 'ip', 'port', 'request_type', 'request_info'])
        export_to_csv(logs_html, 'html_logs.csv', ['timestamp', 'ip', 'port', 'request_info'])
        export_to_csv(logs_ssh, 'ssh_logs.csv', ['timestamp', 'ip', 'port', 'user', 'result', 'request_info'])

        print("CSV dosyaları oluşturuldu.")

    main()



def load_csv_data():
    data = {
        'ssh': pd.read_csv('ssh_logs.csv'),
        'http': pd.read_csv('http_logs.csv'),
        'html': pd.read_csv('html_logs.csv')
    }
    
    # Convert timestamp strings to datetime objects
    for key in data:
        data[key]['timestamp'] = pd.to_datetime(data[key]['timestamp'])
    
    return data

def get_statistics(data):
    stats = {}
    for honeypot_type, df in data.items():
        stats[honeypot_type] = {
            'total_attacks': len(df),
            'unique_ips': df['ip'].nunique(),
            'latest_attack': df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S'),
            'top_ips': df['ip'].value_counts().head(5).to_dict()
        }
    return stats

# Veri yükleme fonksiyonu
def load_data(log_type, days=7):
    filename = {
        "http": "http_logs.csv",
        "html": "html_logs.csv",
        "ssh": "ssh_logs.csv"
    }.get(log_type, "http_logs.csv")

    df = pd.read_csv(filename)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
    df = df.dropna(subset=["timestamp"])

    cutoff_date = pd.Timestamp.now() - pd.Timedelta(days=days)
    df = df[df["timestamp"] >= cutoff_date]

    return df

# Zaman ve IP tabanlı grafik çizme fonksiyonu
def plot_graphs(df, graph_type):
    plt.style.use('dark_background')
    df.set_index("timestamp", inplace=True)

    # Zaman tabanlı veri
    time_series = df.resample("1h").size().astype(int)

    # IP tabanlı veri
    if "ip" in df.columns:
        ip_counts = df["ip"].value_counts().head(10)
    else:
        ip_counts = pd.Series()

    # Request tipi veya Success/Fail grafiği
    if graph_type in ['http', 'html']:
        if 'request_info' in df.columns:
            request_types = df['request_info'].str.extract(r'^(GET|POST|PUT|DELETE)').fillna('OTHER')
            request_counts = request_types[0].value_counts()
            has_request_data = not request_counts.empty
        else:
            has_request_data = False
    else:  # SSH için
        if 'request_info' in df.columns:
            success_counts = df['request_info'].str.contains('success', case=False, na=False).value_counts()
            success_counts.index = ['Başarılı' if x else 'Başarısız' for x in success_counts.index]
            has_request_data = not success_counts.empty
        else:
            has_request_data = False

    # Zaman grafiği
    fig_time, ax1 = plt.subplots(figsize=(10, 4), facecolor='none')
    time_series.plot(ax=ax1, marker='o', linestyle='-', color='#00FFD1', linewidth=2, markersize=6)
    ax1.set_title(f"{graph_type.upper()} - Zaman Tabanlı Saldırı Sayısı", fontsize=14, color='#FFFFFF')
    ax1.set_xlabel("Zaman", fontsize=12, color='#AAAAAA')
    ax1.set_ylabel("İstek Sayısı", fontsize=12, color='#AAAAAA')
    ax1.tick_params(colors='#AAAAAA')
    ax1.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax1.spines['bottom'].set_color('#444444')
    ax1.spines['top'].set_color('#444444')
    ax1.spines['right'].set_color('#444444')
    ax1.spines['left'].set_color('#444444')
    ax1.grid(True, linestyle='--', alpha=0.3)
    time_path = f"static/{graph_type}_time_graph.png"
    fig_time.savefig(time_path, bbox_inches='tight', facecolor='none')
    plt.close(fig_time)

    # IP grafiği
    if not ip_counts.empty:
        fig_ip, ax2 = plt.subplots(figsize=(10, 4), facecolor='none')
        ip_counts.plot(kind="bar", ax=ax2, color="#FF5733")
        ax2.set_title(f"{graph_type.upper()} - IP Tabanlı Saldırı Sayısı", fontsize=14, color='#FFFFFF')
        ax2.set_xlabel("IP Adresi", fontsize=12, color='#AAAAAA')
        ax2.set_ylabel("İstek Sayısı", fontsize=12, color='#AAAAAA')
        ax2.tick_params(colors='#AAAAAA', rotation=45)
        ax2.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax2.spines['bottom'].set_color('#444444')
        ax2.spines['top'].set_color('#444444')
        ax2.spines['right'].set_color('#444444')
        ax2.spines['left'].set_color('#444444')
        ax2.grid(True, linestyle='--', alpha=0.3)
        ip_path = f"static/{graph_type}_ip_graph.png"
        fig_ip.savefig(ip_path, bbox_inches='tight', facecolor='none')
        plt.close(fig_ip)
    else:
        ip_path = None

    # Request tipi veya Success/Fail grafiği
    request_path = None
    if has_request_data:
        fig_req, ax3 = plt.subplots(figsize=(10, 4), facecolor='none')
        if graph_type in ['http', 'html']:
            request_counts.plot(kind="bar", ax=ax3, color="#4CAF50")
            ax3.set_title(f"{graph_type.upper()} - İstek Tipleri", fontsize=14, color='#FFFFFF')
            ax3.set_xlabel("İstek Tipi", fontsize=12, color='#AAAAAA')
        else:  # SSH için
            success_counts.plot(kind="bar", ax=ax3, color=["#4CAF50", "#FF5733"])
            ax3.set_title(f"SSH - Giriş Denemeleri", fontsize=14, color='#FFFFFF')
            ax3.set_xlabel("Sonuç", fontsize=12, color='#AAAAAA')
        
        ax3.set_ylabel("Sayı", fontsize=12, color='#AAAAAA')
        ax3.tick_params(colors='#AAAAAA', rotation=0)
        ax3.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax3.spines['bottom'].set_color('#444444')
        ax3.spines['top'].set_color('#444444')
        ax3.spines['right'].set_color('#444444')
        ax3.spines['left'].set_color('#444444')
        ax3.grid(True, linestyle='--', alpha=0.3)
        request_path = f"static/{graph_type}_request_graph.png"
        fig_req.savefig(request_path, bbox_inches='tight', facecolor='none')
        plt.close(fig_req)

    return time_path, ip_path, request_path

@app.route('/', methods=["GET"])
def index():
    graph_type = request.args.get("type", "http").lower()
    days = int(request.args.get("days",7))

    df = load_data(graph_type, days)
    time_graph, ip_graph, request_graph = plot_graphs(df, graph_type)

    return render_template('index.html',
                         time_graph=time_graph,
                         ip_graph=ip_graph,
                         request_graph=request_graph,
                         selected=graph_type,
                         days=str(days))

@app.route('/refresh')
def refresh():
    generate_csv_files()
    return redirect(url_for('index'))

if __name__ == '__main__':
    generate_csv_files()
    app.run(debug=True, host='0.0.0.0') 

