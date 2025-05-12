from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list
from collections import defaultdict
import threading
import time
import sys
import os

# Global data stores
networks = {}  # BSSID -> {SSID, Signal, Security, Channel}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()

# --- Function: Extract Security Algorithm ---
def get_security_algorithm(pkt):
    """Return the AP's security algorithm (Open, WEP, WPA, WPA2, WPA3) from a beacon packet."""
    cap_info = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}').lower()
    has_privacy = 'privacy' in cap_info

    # Detect IE flags
    has_wpa = False
    has_rsn = False
    has_wpa3 = False

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        # RSN IE indicates WPA2
        if elt.ID == 48:
            has_rsn = True
            # Check for WPA3 SAE AKM suite: 0x00 0x0f 0xac 0x08
            if b'\x00\x0f\xac\x08' in elt.info:
                has_wpa3 = True
        # Vendor Specific IE with WPA OUI subtype -> WPA
        if elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x01'):
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)

    if not has_privacy:
        return 'Open'
    if has_wpa3:
        return 'WPA3'
    if has_rsn:
        return 'WPA2'
    if has_wpa:
        return 'WPA'
    return 'WEP'

# Sniffer handler
def packet_handler(pkt):
    """Handle sniffed packets: update networks and clients info."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else '<Hidden>'
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'

        # Channel extraction
        channel = 'N/A'
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:
                channel = elt.info[0]
                break
            elt = elt.payload.getlayer(Dot11Elt)

        # Use dedicated function for security
        security = get_security_algorithm(pkt)

        prev = networks.get(bssid)
        if not prev or (signal != 'N/A' and prev['Signal'] != 'N/A' and signal > prev['Signal']):
            networks[bssid] = {
                'SSID': ssid,
                'Signal': signal,
                'Security': security,
                'Channel': channel
            }

    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield
        to_ds = bool(fcf & 0x1)
        from_ds = bool(fcf & 0x2)
        if to_ds and not from_ds and pkt.addr1:
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds and pkt.addr2:
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        if bssid in networks and client:
            info = clients[bssid][client]
            info['last_seen'] = timestamp
            info['pkt_count'] += 1

# Channel hopper function
def channel_hopper(iface, delay=0.5):
    """Continuously hop through channels on iface until stop event."""
    # Common 2.4GHz channels
    channels = list(range(1, 15))
    idx = 0
    while not stop_sniff.is_set():
        ch = channels[idx % len(channels)]
        os.system(f"iwconfig {iface} channel {ch} 2>/dev/null")
        idx += 1
        time.sleep(delay)

# Start sniffing thread
def start_sniff(iface):
    """Starts continuous sniffing in background until stop is signaled."""
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    try:
        while not stop_sniff.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    sniffer.stop()

# Interface selection
def select_interface():
    ifaces = get_if_list()
    print("Available interfaces:")
    for idx, iface in enumerate(ifaces):
        print(f"[{idx}] {iface}")
    while True:
        try:
            choice = int(input("Select interface number: "))
            if 0 <= choice < len(ifaces):
                return ifaces[choice]
        except ValueError:
            pass
        print("Invalid selection, try again.")

# Display functions
def display_networks():
    print("\nDiscovered Networks (with client counts):")
    print(f"{'Index':<6}{'BSSID':<20}{'SSID':<30}{'Signal':<8}{'Channel':<8}{'Sec':<10}{'Clients'}")
    for idx, (bssid, det) in enumerate(networks.items()):
        count = len(clients[bssid])
        print(f"{idx:<6}{bssid:<20}{det['SSID']:<30}{det['Signal']:<8}{det['Channel']:<8}{det['Security']:<10}{count}")

def display_clients(bssid):
    print(f"\nClients for BSSID {bssid}:")
    print(f"{'Index':<6}{'MAC':<20}{'Packets':<10}{'Last Seen'}")
    for idx, (mac, info) in enumerate(clients[bssid].items()):
        print(f"{idx:<6}{mac:<20}{info['pkt_count']:<10}{info['last_seen']}")

# Main logic
def main():
    iface = select_interface()
    print(f"Starting continuous sniffing and channel hopping on {iface}...")

    # Start channel hopper
    hopper_thread = threading.Thread(target=channel_hopper, args=(iface,), daemon=True)
    hopper_thread.start()

    # Start sniffing
    sniff_thread = threading.Thread(target=start_sniff, args=(iface,), daemon=True)
    sniff_thread.start()

    # Initial warm-up
    warmup = 60  # seconds
    print(f"Gathering data for {warmup}s before showing menu...")
    time.sleep(warmup)

    try:
        while True:
            display_networks()
            choice = input("Enter network index to inspect, 'r' to refresh, 'q' to quit: ").strip().lower()
            if choice == 'q':
                break
            if choice == 'r':
                refresh = 5
                print(f"Refreshing data for {refresh}s...")
                time.sleep(refresh)
                continue
            if choice.isdigit() and int(choice) < len(networks):
                idx = int(choice)
                bssid_list = list(networks.keys())
                target_bssid = bssid_list[idx]
                info = networks[target_bssid]
                print(f"\nSelected AP:\n  SSID: {info['SSID']}\n  BSSID: {target_bssid}\n  Signal: {info['Signal']}\n  Channel: {info['Channel']}\n  Security: {info['Security']}")

                # Client menu
                while True:
                    display_clients(target_bssid)
                    sub = input("Select client index, 'b' to go back, 'q' to quit: ").strip().lower()
                    if sub == 'q':
                        stop_sniff.set()
                        sniff_thread.join()
                        sys.exit(0)
                    if sub == 'b':
                        break
                    if sub.isdigit() and int(sub) < len(clients[target_bssid]):
                        client_mac = list(clients[target_bssid].keys())[int(sub)]
                        cinfo = clients[target_bssid][client_mac]
                        print("\n--- Selection Complete ---")
                        print(f"\nSelected AP:\n  SSID: {info['SSID']}\n  BSSID: {target_bssid}\n  Signal: {info['Signal']}\n  Channel: {info['Channel']}\n  Security: {info['Security']}")
                        print(f"\nChosen Client:\n  MAC: {client_mac}\n  Packets Seen: {cinfo['pkt_count']}\n  Last Seen: {cinfo['last_seen']}")
                        stop_sniff.set()
                        sniff_thread.join()
                        sys.exit(0)
            else:
                print("Invalid choice.")
    except KeyboardInterrupt:
        pass
    finally:
        stop_sniff.set()
        sniff_thread.join()
        print("\nExiting.")

if __name__ == '__main__':
    main()