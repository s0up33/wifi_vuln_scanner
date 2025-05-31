# WiFi Vulnerability Scanner

A Linux tool that scans nearby wireless networks and ranks them based on their potential exploitability. It provides a simple graphical interface for viewing target networks, scoring them based on security and signal metrics, and managing monitor mode.

---

## Features

- **Scans for nearby WiFi networks** using `airodump-ng`
- **Scores networks** based on:
  - Signal strength
  - Encryption type (Open, WEP, WPA/WPA2)
  - SSID visibility
  - Vendor patterns (i.e., default names like TP-LINK)
- **Graphical Interface**
  - Live display of scan results
  - Start and stop scan with button controls
  - Status label showing interface mode
- Automatically enables/disables monitor mode (`airmon-ng`)
- Compatible adapters that remain as `wlan0`

---

## Requirements

- Python 3
- Kali Linux (or other Linux with `aircrack-ng` suite)
- `airodump-ng`, `airmon-ng`, `iwconfig`

Install Python dependencies:

- sudo apt update
- sudo apt install python3 python3-tk aircrack-ng -y

---

## Usage

```bash
python3 wifi_vuln_scanner.py

