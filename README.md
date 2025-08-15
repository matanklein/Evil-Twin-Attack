# Evil Twin Attack Tool

A modular toolkit to perform a Wi‑Fi “Evil Twin” attack, combining:

- **Network Discovery & Sniffing** (Scapy)  
- **Deauthentication** of a selected client  
- **Rogue AP Creation** (hostapd + dnsmasq) matching the victim’s SSID  
- **Captive‑Portal Phishing** (Apache2 or custom HTTP server)   
- **Init/Cleanup Scripts** for interface setup & teardown  

---

## 🚀 Features

1. **Scan & Select**  
   - Continuous 802.11 beacon sniffing to list APs and their clients  
   - Interactive menu to choose target AP and client  

2. **Attack Stages**  
   - **Deauth** the victim to force reconnection  
   - **Evil AP** with identical SSID + open or WPA‑Enterprise/PSK modes  
   - **Captive Portal** that intercepts HTTP probes and harvests credentials  
   - **RADIUS Server** support for WPA2‑Enterprise  

3. **Persistence**  
   - `init.sh` / `cleanup.sh` to manage interfaces, iptables, services  

---

## ⚙️ Prerequisites

- **Linux** with two Wi‑Fi adapters (monitor + AP modes)  
- **Root** or sudo access  

## 🔧 Setup

1. **Clone the repository**  
```bash
git clone https://github.com/youruser/Evil-Twin-Attack.git
cd Evil-Twin-Attack
```

2. Install dependencies
```bash
sudo apt update
sudo apt install -y hostapd dnsmasq apache2 dnsspoof sqlite3 python3 python3‑pip
sudo pip3 install scapy pyrad
```

3. Prepare captive‑portal files
    - Place your portal files (`index.html` and `login.php`) in in `/var/www/html/`:
```bash
sudo mkdir -p /var/www/html
sudo mv index.html /var/www/html/
sudo mv login.php /var/www/html/
```

## 🚀 Usage

1. **Prepare interfaces**
   
   Run the initialization script to set up your Wi-Fi cards:
```bash
sudo ./init.sh
```

- This script will:

    - Kill interfering processes (e.g., NetworkManager, wpa_supplicant)

    - Put your sniffer interface into monitor mode

    - Create or configure your AP interface (e.g., `ap0`) in AP mode

2. Start the Attack
    Launch the main attack script:
```bash
sudo python3 main.py
```

## 🧹 Cleanup

Run the Cleanup Script
```bash
sudo ./cleanup.sh
```
