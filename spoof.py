from scapy.all import *
import os

found_networks = []

def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        channel = int(ord(pkt[Dot11Elt:3].info))
        network_info = (ssid, bssid, channel)
        if network_info not in found_networks:
            found_networks.append(network_info)
            print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

def find_wifi_networks(interface):
    for channel in range(1, 14):
        os.system(f"iwconfig {interface} channel {channel}")
        # print(f"Scanning on channel {channel}...")
        sniff(iface=interface, prn=handle_packet, timeout=5)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
find_wifi_networks(interface_name)
