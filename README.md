# Evil Twin Attack Tool

A modular toolkit to perform a Wi‑Fi “Evil Twin” attack, combining:

- **Network Discovery & Sniffing** (Scapy)  
- **Deauthentication** of a selected client  
- **Rogue AP Creation** (hostapd + dnsmasq) matching the victim’s SSID  
- **Captive‑Portal Phishing** (custom HTTP server)   
- **Init/Cleanup Scripts** for interface setup & teardown  

---

## 🚀 Features

## 🚀 Features

### 1. **Network Discovery**  
   - Real-time 802.11 beacon frame sniffing
   - Automatic client detection and association tracking
   - Interactive network and client selection interface

### 2. **Evil Twin Attack Chain**  
   - **Target Selection**: Choose specific AP and client for attack
   - **Rogue AP Setup**: Create fake AP with identical SSID
   - **Deauthentication**: Force victim to disconnect from legitimate AP
   - **Captive Portal**: Intercept HTTP traffic and harvest credentials
   - **Credential Logging**: Save captured passwords to file

### 3. **Advanced Capabilities**  
   - **Multi-device Support**: Uses two WiFi interfaces (monitor + AP mode)
   - **Cross-platform Detection**: Handles Android, iOS, Windows captive portal detection
   - **Network Isolation**: Preserves internet connectivity during attack
   - **Clean Teardown**: Automated cleanup and interface restoration  

---

# Evil Twin Attack Tool

A comprehensive toolkit for performing Wi‑Fi "Evil Twin" attacks, featuring:

- **📡 Network Discovery & Sniffing** (Scapy-based packet capture)  
- **⚡ Targeted Deauthentication** of selected clients
- **🎭 Rogue AP Creation** (hostapd + dnsmasq) with identical SSID  
- **🕸️ Captive Portal** with credential harvesting (custom HTTP server)   
- **🔧 Automated Setup/Cleanup** scripts for interface management

> **⚠️ LEGAL DISCLAIMER**: This tool is for educational and authorized security testing purposes only. Only use on networks you own or have explicit permission to test.

---

## 🚀 Features

### 1. **Network Discovery**  
   - Real-time 802.11 beacon frame sniffing
   - Automatic client detection and association tracking
   - Interactive network and client selection interface

### 2. **Evil Twin Attack Chain**  
   - **Target Selection**: Choose specific AP and client for attack
   - **Rogue AP Setup**: Create fake AP with identical SSID on different channel
   - **Deauthentication**: Force victim to disconnect from legitimate AP
   - **Captive Portal**: Intercept HTTP traffic and harvest credentials
   - **Credential Logging**: Save captured passwords to file

### 3. **Advanced Capabilities**  
   - **Multi-device Support**: Uses two WiFi interfaces (monitor + AP mode)
   - **Cross-platform Detection**: Handles Android, iOS, Windows captive portal detection
   - **Network Isolation**: Preserves internet connectivity during attack
   - **Clean Teardown**: Automated cleanup and interface restoration

---

## ⚙️ Prerequisites

### Hardware Requirements
- **Linux system** (tested on Ubuntu/Kali Linux)
- **Two WiFi adapters**:
  - One for monitoring/deauth (must support monitor mode)
  - One for creating fake AP (must support AP mode)
- **Root access** (required for interface manipulation)

### Software Dependencies  
```bash
# Required system packages
sudo apt update
sudo apt install -y hostapd dnsmasq python3 python3-pip iw

# Python dependencies
sudo pip3 install scapy
```

---

## 🔧 Setup & Configuration

### Step 1: Identify Your WiFi Interfaces

First, identify your available wireless interfaces:
```bash
# List all wireless interfaces
iw dev

# Example output:
# phy#0: wlo1 (built-in WiFi)
# phy#1: wlxe84e06aed7ca (USB WiFi adapter)
```

### Step 2: Configure Interface Names in init.sh

Edit the `init.sh` file to match your specific WiFi interface names:
```bash
nano init.sh
```

Find and update these lines (around line 60-65):
```bash
# Update these with YOUR interface names
MON_IF=wlxe84e06aed7ca    # Your USB WiFi adapter (monitor mode)
AP_PHY=phy0               # Physical interface for AP (usually phy0)  
AP_DEV=wlo1               # Your built-in WiFi (will become AP)
```

**Interface Selection Guide:**
- `MON_IF`: External USB WiFi adapter (for monitoring/deauth)
- `AP_DEV`: Built-in WiFi card (will create the fake AP)
- `AP_PHY`: Physical layer (usually `phy0` for built-in WiFi)

### Step 3: Initialize Attack Environment

Run the initialization script to configure interfaces:
```bash
sudo ./init.sh
```

This script will:
- ✅ Clean up previous attack remnants
- ✅ Configure NetworkManager to ignore attack interfaces  
- ✅ Set monitor interface to monitor mode
- ✅ Create virtual AP interface (`ap0`)
- ✅ Preserve internet connectivity on ethernet

---

## 🚀 Running the Attack

### Method 1: Interactive Mode (Recommended)
```bash
# Start the interactive attack tool
sudo python3 main.py
```

This provides a guided interface where you can:
1. Select target network from discovered APs
2. Choose specific client to target  
3. Launch coordinated Evil Twin attack

### Method 2: Quick Test Mode
```bash
# Test captive portal functionality
sudo python3 test_attack.py
```

This creates a test AP called "TestAP" for testing the captive portal.

---

## 📱 Testing the Captive Portal

Once the attack is running:

1. **Connect a test device** to the fake AP (will appear as target SSID)
2. **Open a web browser** - you should be redirected to captive portal
3. **Enter credentials** on the fake login page
4. **Check captured data**:
   ```bash
   # View captured credentials (if using interactive mode)
   cat captured.txt
   
   # Monitor attack logs in real-time
   tail -f /var/log/syslog | grep -E "(hostapd|dnsmasq)"
   ```

### Expected Behavior by Device Type:
- **Android**: Automatic captive portal popup notification
- **iOS/macOS**: "Sign in to Wi-Fi" notification  
- **Windows**: Network authentication prompt
- **Manual**: Navigate to any HTTP website to trigger portal

---

## 🔍 Troubleshooting

### Common Issues:

**"Address already in use" error:**
```bash
# Kill conflicting processes
sudo ./cleaning.sh
sudo fuser -k 80/tcp
sudo systemctl stop apache2 nginx
```

**Captive portal not appearing:**
- Verify device connects to fake AP: `iwconfig ap0`
- Check HTTP redirection: `iptables -t nat -L PREROUTING`
- Test DNS hijacking: `nslookup google.com 192.168.0.1`

**Monitor mode setup fails:**
```bash
# Check if interface supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Try manual monitor mode setup
sudo ip link set wlxe84e06aed7ca down
sudo iw dev wlxe84e06aed7ca set type monitor
sudo ip link set wlxe84e06aed7ca up
```

**No clients appear:**
- Ensure monitor interface is on correct channel
- Verify packets are being received: `tcpdump -i wlxe84e06aed7ca`
- Try channel hopping: manually change channels in scan.py

---

## 🧹 Cleanup

Always run cleanup after testing:
```bash
sudo ./cleaning.sh
```

This will:
- 🛑 Stop all attack services (hostapd, dnsmasq)
- 🔄 Restore original interface configurations  
- 🧹 Clear firewall rules and routing tables
- 🔌 Re-enable NetworkManager on WiFi interfaces
- 📡 Return interfaces to normal operation

---

## 📁 Project Structure

```
Evil-Twin-Attack/
├── main.py              # Interactive attack interface
├── test_attack.py       # Quick testing script  
├── attack.py            # Core attack functions
├── scan.py              # WiFi scanning and monitoring
├── init.sh              # Interface setup script
├── cleaning.sh          # Cleanup script
├── CaptivePortal.py     # HTTP server for captive portal
├── index.html           # Captive portal login page
├── success.html         # Post-login success page
├── template_hostapd.conf    # hostapd configuration template
└── template_dnsmasq.conf    # dnsmasq configuration template
```

---

## 🔒 Security & Ethics

This tool is designed for:
- ✅ **Authorized penetration testing**
- ✅ **Educational cybersecurity training**  
- ✅ **Red team exercises with proper authorization**
- ✅ **Testing your own network security**

**Unauthorized use is illegal and unethical.**

---

## 🤝 Contributing

Issues and pull requests welcome! Please ensure all contributions maintain the educational focus and include appropriate legal disclaimers.
