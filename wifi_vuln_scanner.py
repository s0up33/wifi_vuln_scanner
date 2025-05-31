
#!/usr/bin/env python3

import subprocess
import pandas as pd
import tkinter as tk
from tkinter import ttk
import threading
import time
import os
import re
import glob
from io import StringIO

INTERFACE = "wlan0"

def start_monitor_mode(interface):
    subprocess.run(["sudo", "airmon-ng", "start", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_monitor_mode(interface):
    subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_airodump(interface, duration=15):
    for f in glob.glob("/tmp/scan_results-*.csv"):
        os.remove(f)
    cmd = ["sudo", "airodump-ng", "--write-interval", "1", "-w", "/tmp/scan_results", "--output-format", "csv", interface]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    time.sleep(2)

def get_latest_csv():
    files = glob.glob("/tmp/scan_results-*.csv")
    if not files:
        raise FileNotFoundError("No scan result CSVs found.")
    return sorted(files)[-1]

def parse_csv(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    parts = content.split("Station MAC")
    networks_csv = parts[0].strip()
    df = pd.read_csv(StringIO(networks_csv), skipinitialspace=True)
    df = df[df.columns[:14]]
    df.columns = [c.strip() for c in df.columns]
    return df

def compute_score(row):
    score = 0
    try:
        power = int(row.get("Power", -100))
        score += max(0, 30 + power)
    except:
        pass

    privacy = str(row.get("Privacy", "")).strip().upper()
    if "OPN" in privacy:
        score += 50
    elif "WEP" in privacy:
        score += 40
    elif "WPA" in privacy:
        score += 10

    ssid = str(row.get("ESSID", "")).strip()
    if not ssid:
        score += 15
    elif re.search(r"TP[-_]?LINK", ssid, re.IGNORECASE):
        score += 10

    return score

def update_gui(tree, data):
    for row in tree.get_children():
        tree.delete(row)
    for _, row in data.iterrows():
        tree.insert("", "end", values=(
            row.get("BSSID", ""),
            row.get("Channel", ""),
            row.get("Privacy", ""),
            row.get("Power", ""),
            row.get("ESSID", ""),
            row.get("Score", 0)
        ))


scan_event = threading.Event()

def analyze_and_display(tree):
    scan_event.set()
    try:
        start_monitor_mode(INTERFACE)
        run_airodump(INTERFACE)
        if not scan_event.is_set():
            return
        csv_path = get_latest_csv()
        df = parse_csv(csv_path)
        df["Score"] = df.apply(compute_score, axis=1)
        df_sorted = df.sort_values(by="Score", ascending=False)
        update_gui(tree, df_sorted)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop_monitor_mode(INTERFACE)

    try:
        start_monitor_mode(INTERFACE)
        run_airodump(INTERFACE)
        csv_path = get_latest_csv()
        df = parse_csv(csv_path)
        df["Score"] = df.apply(compute_score, axis=1)
        df_sorted = df.sort_values(by="Score", ascending=False)
        update_gui(tree, df_sorted)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop_monitor_mode(INTERFACE)


def stop_scan():
    scan_event.clear()
    stop_monitor_mode(INTERFACE)


def get_interface_state(interface):
    try:
        output = subprocess.check_output(["iwconfig", interface], stderr=subprocess.STDOUT).decode()
        if "Monitor" in output:
            return "Monitor Mode"
        else:
            return "Managed Mode"
    except subprocess.CalledProcessError:
        return "Unavailable"

def update_status_label(label):
    state = get_interface_state(INTERFACE)
    label.config(text=f"Interface {INTERFACE}: {state}")

def run_gui():


    root = tk.Tk()
    root.title("WiFi Exploitability Scanner")
    root.geometry("800x440")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    columns = ("BSSID", "Channel", "Privacy", "Power", "ESSID", "Score")
    tree = ttk.Treeview(frame, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="center")
    tree.pack(fill="both", expand=True)

    def scan():
        threading.Thread(target=analyze_and_display, args=(tree,), daemon=True).start()

    btn_start = ttk.Button(root, text="Start Scan", command=lambda: [scan(), update_status_label(status_label)])
    btn_stop = ttk.Button(root, text="Stop Scan", command=lambda: [stop_scan(), update_status_label(status_label)])
    btn_start.pack(pady=5)
    btn_stop.pack(pady=5)

    status_label = ttk.Label(root, text="", anchor="center")
    status_label.pack(pady=5)
    update_status_label(status_label)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
