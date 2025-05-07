import pandas as pd
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.dates as mdates
import re



# Veri yükleme fonksiyonları
def load_http_data():
    try:
        df = pd.read_csv("http_logs.csv")
        df["request_type"] = df["request_info"].str.extract(r'(GET|POST|PUT|DELETE|HEAD)')
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        return df
    except Exception as e:
        print("HTTP verisi yüklenemedi:", e)
        return pd.DataFrame()

def load_html_data():
    try:
        df = pd.read_csv("html_logs.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        return df
    except Exception as e:
        print("HTML verisi yüklenemedi:", e)
        return pd.DataFrame()

def load_ssh_data():
    try:
        df = pd.read_csv("ssh_logs.csv")
        df["result"] = df["request_info"].str.extract(r'\[RESULT:\s*(\w+)\]')
        df["user"] = df["request_info"].str.extract(r'User: (\S+)')
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        return df
    except Exception as e:
        print("SSH verisi yüklenemedi:", e)
        return pd.DataFrame()

# Grafik çizim fonksiyonu
def plot_selected_honeypot(event=None):
    honeypot_type = honeypot_selector.get()
    view_type = view_selector.get()
    ax.clear()

    # Veri seçimi
    if honeypot_type == "HTTP":
        df = load_http_data()
    elif honeypot_type == "HTML":
        df = load_html_data()
    elif honeypot_type == "SSH":
        df = load_ssh_data()
    else:
        df = pd.DataFrame()

    # Eğer veri yoksa
    if df.empty or "timestamp" not in df.columns:
        ax.text(0.5, 0.5, "Veri bulunamadı", ha='center', va='center')
        canvas.draw()
        return

    # Grafik türü seçimi
    if view_type == "IP Tabanlı":
        if "ip" in df.columns:
            ip_counts = df["ip"].value_counts()
            ip_counts.plot(kind='bar', ax=ax)
            ax.set_title(f"{honeypot_type} Honeypot - IP Erişim Sayısı")
            ax.set_ylabel("İstek Sayısı")
            ax.set_xlabel("IP Adresi")
            ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right', fontsize=9)
            ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        else:
            ax.text(0.5, 0.5, "IP sütunu bulunamadı", ha='center', va='center')
    elif view_type == "Zaman Tabanlı":
        df = df.dropna(subset=["timestamp"])
        if df.empty:
            ax.text(0.5, 0.5, "Zaman verisi eksik", ha='center', va='center')
            canvas.draw()
            return
        df.set_index("timestamp", inplace=True)
        zaman_seriesi = df.resample("1h").size().astype(int)

        if zaman_seriesi.empty:
            ax.text(0.5, 0.5, "Yeterli zaman verisi yok", ha='center', va='center')
        else:
            zaman_seriesi.plot(ax=ax, marker='o', linestyle='-')
            ax.set_title(f"{honeypot_type} Honeypot - Saatlik Saldırı Sayısı")
            ax.set_ylabel("İstek Sayısı")
            ax.set_xlabel("Zaman")
            ax.tick_params(axis='x', rotation=45)
            ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
            
            
            

    fig.tight_layout()
    fig.subplots_adjust(bottom=0.2)
    canvas.draw()

# Arayüz başlat
root = tk.Tk()
root.title("Honeypot Log Görselleştirme")
ekran_genislik = root.winfo_screenwidth()
ekran_yukseklik = root.winfo_screenheight()
root.geometry(f"{ekran_genislik}x{ekran_yukseklik}")

# Honeypot seçici
honeypot_selector = ttk.Combobox(root, values=["HTTP", "HTML", "SSH"])
honeypot_selector.set("HTTP")
honeypot_selector.pack(pady=10)
honeypot_selector.bind("<<ComboboxSelected>>", plot_selected_honeypot)

# Görünüm tipi (IP / Zaman)
view_selector = ttk.Combobox(root, values=["IP Tabanlı", "Zaman Tabanlı"])
view_selector.set("IP Tabanlı")
view_selector.pack(pady=10)
view_selector.bind("<<ComboboxSelected>>", plot_selected_honeypot)

# Grafik alanı
fig, ax = plt.subplots(figsize=(10, 6))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(padx=100, pady=50, expand=True, fill="both")

plot_selected_honeypot()  # Başlangıç grafiği

root.mainloop()
