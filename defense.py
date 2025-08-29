#!/usr/bin/env python3
import time
import threading
from collections import defaultdict, deque
from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, get_if_list

'''
This module implements defense mechanisms against Evil Twin attacks and deauthentication floods.
It continuously monitors WiFi traffic to detect suspicious activities and alerts the user.
'''

# ——— Configuration ———
REPORT_INTERVAL   = 10    # seconds between SSID/BSSID reports
DEAUTH_WINDOW     = 5     # seconds sliding window for counting deauths
DEAUTH_THRESHOLD  = 20    # deauth frames within window → alert
# ————————————————————

# SSID -> { BSSID -> { 'last_seen': timestamp, 'secure': bool } }
ssids        = defaultdict(dict)
deauth_times = deque()
lock         = threading.Lock()

def is_secured_beacon(pkt):
    """Return True if beacon includes an RSN or WPA element."""
    for elt in pkt.iterpayloads():
        if isinstance(elt, Dot11Elt):
            # RSN IE has ID 48
            if elt.ID == 48:
                return True
            # WPA IE is a vendor-specific (ID 221) with Microsoft OUI/type
            if elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01'):  # WPA OUI
                return True
    return False

def packet_handler(pkt):
    ts = time.time()

    # — Beacon frames: track SSID ↔ BSSID mappings & security info
    if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt):
        bssid  = pkt[Dot11].addr2
        ssid   = pkt[Dot11Elt].info.decode(errors='ignore') or "<hidden>"
        secure = is_secured_beacon(pkt)
        with lock:
            ssids[ssid][bssid] = {'last_seen': ts, 'secure': secure}

    # — Deauth frames: record timestamp
    elif pkt.haslayer(Dot11Deauth):
        with lock:
            deauth_times.append(ts)

def report_loop():
    """Every REPORT_INTERVAL, print alerts for Evil‑Twin and deauth floods."""
    while True:
        time.sleep(REPORT_INTERVAL)
        now = time.time()

        with lock:
            # — Purge old SSID entries (>3×REPORT_INTERVAL) —
            for ssid in list(ssids):
                for b in list(ssids[ssid]):
                    if now - ssids[ssid][b]['last_seen'] > REPORT_INTERVAL * 3:
                        del ssids[ssid][b]
                if not ssids[ssid]:
                    del ssids[ssid]

            # — Check for Evil‑Twin SSIDs (one open + one secured) —
            for ssid, bmap in ssids.items():
                has_open   = any(not info['secure'] for info in bmap.values())
                has_secure = any(info['secure']     for info in bmap.values())
                if has_open and has_secure:
                    open_bssids   = [b for b,info in bmap.items() if not info['secure']]
                    secure_bssids = [b for b,info in bmap.items() if info['secure']]
                    print(
                        f"\n  Evil‑Twin Alert for SSID “{ssid}”:\n"
                        f"    Open BSSID(s):   {', '.join(open_bssids)}\n"
                        f"    Secured BSSID(s): {', '.join(secure_bssids)}"
                    )

            # — Purge old deauth timestamps (>DEAUTH_WINDOW) —
            while deauth_times and now - deauth_times[0] > DEAUTH_WINDOW:
                deauth_times.popleft()

            # — Check for deauth flood —
            if len(deauth_times) >= DEAUTH_THRESHOLD:
                print(f"\n  Deauth Flood Alert: {len(deauth_times)} frames in last {DEAUTH_WINDOW}s")

def select_interface():
    ifaces = [i for i in get_if_list() if 'mon' in i or 'wlan' in i]
    print("Available interfaces:")
    for idx, iface in enumerate(ifaces):
        print(f"[{idx}] {iface}")
    while True:
        choice = input("Select interface number: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]
        print("Invalid choice.")

def main():
    iface = select_interface()
    print(f"Starting defense on {iface}:")
    print(f"  • Evil‑Twin check every {REPORT_INTERVAL}s (open + secured APs)\n"
          f"  • Deauth flood window {DEAUTH_WINDOW}s, threshold ≥{DEAUTH_THRESHOLD} frames\n")

    # Start sniffing
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()

    # Start reporting thread
    reporter = threading.Thread(target=report_loop, daemon=True)
    reporter.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping defense.")
    finally:
        sniffer.stop()

if __name__ == "__main__":
    main()
