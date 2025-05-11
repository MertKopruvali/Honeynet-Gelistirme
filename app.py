from flask import Flask, render_template, request
import matplotlib.pyplot as plt
import pandas as pd
import os

app = Flask(__name__)

# Veri yükleme fonksiyonu
def load_data(log_type):
    filename = {
        "http": "http_logs.csv",
        "html": "html_logs.csv",
        "ssh": "ssh_logs.csv"
    }.get(log_type, "http_logs.csv")

    df = pd.read_csv(filename)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
    return df.dropna(subset=["timestamp"])

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

    # Zaman grafiği
    fig_time, ax1 = plt.subplots(figsize=(10, 4), facecolor='none')
    time_series.plot(ax=ax1, marker='o', linestyle='-', color='#00FFD1', linewidth=2, markersize=6)
    ax1.set_title(f"{graph_type.upper()} - Zaman Tabanlı Saldırı Sayısı", fontsize=14, color='#FFFFFF')
    ax1.set_xlabel("Zaman", fontsize=12, color='#AAAAAA')
    ax1.set_ylabel("İstek Sayısı", fontsize=12, color='#AAAAAA')
    ax1.tick_params(colors='#AAAAAA')
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

    return time_path, ip_path

@app.route('/', methods=["GET"])
def index():
    graph_type = request.args.get("type", "http").lower()
    df = load_data(graph_type)
    time_graph, ip_graph = plot_graphs(df, graph_type)
    return render_template('index.html',
                           time_graph=time_graph,
                           ip_graph=ip_graph,
                           selected=graph_type)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
