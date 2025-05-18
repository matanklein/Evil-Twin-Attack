from scapy.all import AsyncSniffer, Dot11Beacon, Dot11Elt, Dot11, get_if_list
from collections import defaultdict
import threading, time, os

# Shared data stores
networks = {}  # BSSID -> {SSID, Signal, Security, Channel}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()


def get_security_algorithm(pkt):
    """Return the AP's security algorithm (Open, WEP, WPA, WPA2, WPA3)"""
    cap_info = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}').lower()
    has_privacy = 'privacy' in cap_info
    has_wpa = False; has_rsn = False; has_wpa3 = False
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48: has_rsn = True
        if elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x01'): has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)
    if not has_privacy: return 'Open'
    if has_wpa3: return 'WPA3'
    if has_rsn: return 'WPA2'
    if has_wpa: return 'WPA'
    return 'WEP'


def packet_handler(pkt):
    """Update networks and clients from sniffed packets"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') or '<Hidden>'
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'
        # channel IE
        channel = 'N/A'; elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:
                channel = elt.info[0]
                break
            elt = elt.payload.getlayer(Dot11Elt)
        security = get_security_algorithm(pkt)
        prev = networks.get(bssid)
        if not prev or (signal!='N/A' and prev['Signal']!='N/A' and signal>prev['Signal']):
            networks[bssid] = {'SSID': ssid,'Signal': signal,'Security': security,'Channel': channel}
    elif pkt.haslayer(Dot11) and pkt.type==2: # Data frame
        fcf = pkt.FCfield # Frame Control Field
        to_ds=bool(fcf&0x1); from_ds=bool(fcf&0x2) # ToDS and FromDS
        if to_ds and not from_ds: # AP to client
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds: # Client to AP
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        if bssid in networks:
            info = clients[bssid][client]
            info['last_seen']=timestamp; info['pkt_count']+=1


def start_sniff(iface, channel_hop=True):
    """Starts background sniffing and optional channel hopping"""
    def hop():
        chs=range(1,15); i=0
        while not stop_sniff.is_set():
            os.system(f"iwconfig {iface} channel {chs[i%len(chs)]} 2>/dev/null")
            i+=1; time.sleep(0.5)
    if channel_hop:
        threading.Thread(target=hop,daemon=True).start()
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    return sniffer


def select_interface():
    ifaces = get_if_list()
    print("Available interfaces:")
    for i,iface in enumerate(ifaces): print(f"[{i}] {iface}")
    while True:
        try: choice=int(input("Select interface number: "))
        except: continue
        if 0<=choice<len(ifaces): return ifaces[choice]


def get_networks():
    return networks


def get_clients(bssid):
    return clients[bssid]