from scapy.all import *
import os

found_ssids = []

def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        if ssid not in found_ssids:
            found_ssids.append(ssid)
            print(f"[+] SSID: {ssid}, BSSID: {bssid}")

def find_wifi_networks(interface):
    # Memindai seluruh saluran 2.4 GHz (Saluran 1 hingga 13)
    for channel in range(1, 14):
        os.system(f"iwconfig {interface} channel {channel}")
        print(f"Scanning on channel {channel}...")
        sniff(iface=interface, prn=handle_packet, timeout=5)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
find_wifi_networks(interface_name)
