#!/usr/bin/env python3
import time
import threading
from collections import defaultdict, deque

from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, get_if_list

# ——— Configuration ———
REPORT_INTERVAL   = 10    # seconds between SSID/BSSID reports
ALERT_THRESHOLD   = 2     # distinct BSSIDs on same SSID → Evil Twin
DEAUTH_WINDOW     = 5     # seconds sliding window for counting deauths
DEAUTH_THRESHOLD  = 20    # deauth frames within window → alert
# ————————————————————

ssids = defaultdict(dict)           # SSID -> { BSSID -> last_seen_time }
deauth_times = deque()              # timestamps of recent deauth frames
lock = threading.Lock()

def packet_handler(pkt):
    ts = time.time()

    # — Beacon frames: track SSID ↔ BSSID mappings
    if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt):
        bssid = pkt[Dot11].addr2
        ssid  = pkt[Dot11Elt].info.decode(errors='ignore') or "<hidden>"
        with lock:
            ssids[ssid][bssid] = ts

    # — Deauth frames: record timestamp
    elif pkt.haslayer(Dot11Deauth):
        with lock:
            deauth_times.append(ts)

def report_loop():
    """Every REPORT_INTERVAL, print Evil-Twin alerts and deauth alerts."""
    while True:
        time.sleep(REPORT_INTERVAL)
        now = time.time()

        with lock:
            # — Purge old SSID entries (>3×REPORT_INTERVAL) —
            for ssid in list(ssids):
                for b in list(ssids[ssid]):
                    if now - ssids[ssid][b] > REPORT_INTERVAL * 3:
                        del ssids[ssid][b]
                if not ssids[ssid]:
                    del ssids[ssid]

            # — Check for Evil-Twin SSIDs —
            for ssid, bmap in ssids.items():
                if len(bmap) >= ALERT_THRESHOLD:
                    print(f"\n⚠️  Evil-Twin Alert: SSID “{ssid}” on BSSIDs {', '.join(bmap)}")

            # — Purge old deauth timestamps (>DEAUTH_WINDOW) —
            while deauth_times and now - deauth_times[0] > DEAUTH_WINDOW:
                deauth_times.popleft()

            # — Check for deauth flood —
            if len(deauth_times) >= DEAUTH_THRESHOLD:
                print(f"\n⚠️  Deauth Flood Alert: {len(deauth_times)} deauth frames in last {DEAUTH_WINDOW}s")

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
    print(f"  • Evil-Twin check every {REPORT_INTERVAL}s (threshold ≥{ALERT_THRESHOLD} BSSIDs)")
    print(f"  • Deauth flood window {DEAUTH_WINDOW}s, threshold ≥{DEAUTH_THRESHOLD} frames\n")

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
