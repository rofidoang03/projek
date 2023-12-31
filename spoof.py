from scapy.all import *

found_ssids = []

def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        if ssid not in found_ssids:
            found_ssids.append(ssid)
            print(f"SSID: {ssid}, BSSID: {bssid}")

def find_wifi_networks(interface, channels):
    for channel in channels:
        os.system(f"iwconfig {interface} channel {channel}")
        print(f"Scanning on channel {channel}...")
        sniff(iface=interface, prn=handle_packet, timeout=10)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
# List saluran yang ingin dipindai secara bergantian
scan_channels = [1, 6, 11]  # Misalnya, saluran 1, 6, dan 11

find_wifi_networks(interface_name, scan_channels)
