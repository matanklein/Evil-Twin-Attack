from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list
from collections import defaultdict
import threading
import time
import sys

# Global data stores
networks = {}  # BSSID -> {SSID, Signal, Security}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()

# Sniffer handler
def packet_handler(pkt):
    """Handle sniffed packets: update networks and clients info."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    # Beacon frames: discover networks
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2 # BSSID of the AP
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else '<Hidden>' # SSID
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A' # Signal strength
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
        security = 'Encrypted' if 'privacy' in cap.lower() else 'Open' # Security type
        prev = networks.get(bssid) # Previous info for this BSSID
        if not prev or (signal != 'N/A' and prev['Signal'] != 'N/A' and signal > prev['Signal']):
            networks[bssid] = {'SSID': ssid, 'Signal': signal, 'Security': security}
    # Data frames: track clients under AP
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield # Frame Control Field
        to_ds = bool(fcf & 0x1) # To DS bit
        from_ds = bool(fcf & 0x2) # From DS bit
        if to_ds and not from_ds and pkt.addr1: # To DS and not From DS then addr1 is BSSID and addr2 is client
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds and pkt.addr2: # From DS and not To DS then addr2 is BSSID and addr1 is client
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        if bssid in networks and client: # Only track clients for known networks
            info = clients[bssid][client] # Get or create client info
            info['last_seen'] = timestamp
            info['pkt_count'] += 1

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
    print(f"{'Index':<6}{'BSSID':<20}{'SSID':<30}{'Signal':<8}{'Sec':<10}{'Clients'}")
    for idx, (bssid, det) in enumerate(networks.items()):
        count = len(clients[bssid])
        print(f"{idx:<6}{bssid:<20}{det['SSID']:<30}{det['Signal']:<8}{det['Security']:<10}{count}")

def display_clients(bssid):
    print(f"\nClients for BSSID {bssid}:")
    print(f"{'Index':<6}{'MAC':<20}{'Packets':<10}{'Last Seen'}")
    for idx, (mac, info) in enumerate(clients[bssid].items()):
        print(f"{idx:<6}{mac:<20}{info['pkt_count']:<10}{info['last_seen']}")

# Main logic
def main():
    iface = select_interface()
    print(f"Starting continuous sniffing on {iface}... (data collection runs in background)")
    sniff_thread = threading.Thread(target=start_sniff, args=(iface,), daemon=True)
    sniff_thread.start()

    # Initial sniffing warm-up
    warmup = 5  # seconds to gather initial data
    print(f"Gathering data for {warmup}s before showing menu...")
    time.sleep(warmup)

    try:
        while True:
            # Note: sniffing continues while in this menu
            display_networks()
            choice = input("Enter network index to inspect, 'r' to refresh, 'q' to quit: ").strip().lower()
            if choice == 'q':
                break
            if choice == 'r':
                refresh = 5  # seconds to collect more data
                print(f"Refreshing data for {refresh}s...")
                time.sleep(refresh)
                continue
            if choice.isdigit() and int(choice) < len(networks):
                idx = int(choice)
                bssid_list = list(networks.keys())
                target_bssid = bssid_list[idx]
                info = networks[target_bssid]
                print(f"\nSelected AP:\n  SSID: {info['SSID']}\n  BSSID: {target_bssid}\n  Signal: {info['Signal']}\n  Security: {info['Security']}")

                # Client menu
                while True:
                    # Still gathering data in background
                    display_clients(target_bssid)
                    sub = input("Select client index, 'b' to go back, 'q' to quit: ").strip().lower()
                    if sub == 'q':
                        stop_sniff.set()
                        sniff_thread.join()
                        sys.exit(0)
                    if sub == 'b':
                        break  # go back to network selection
                    if sub.isdigit() and int(sub) < len(clients[target_bssid]):
                        client_mac = list(clients[target_bssid].keys())[int(sub)]
                        cinfo = clients[target_bssid][client_mac]
                        print("\n--- Selection Complete ---")
                        print(f"\nSelected AP:\n  SSID: {info['SSID']}\n  BSSID: {target_bssid}\n  Signal: {info['Signal']}\n  Security: {info['Security']}")
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