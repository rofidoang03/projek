from scapy.all import *
import os

found_networks = []

def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        channel = int(ord(pkt[Dot11Elt:3].info))
        capabilities = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                   "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        auth_type = None
        if capabilities is not None and 'privacy' in capabilities:
            auth_type = "WPA/WPA2"
        else:
            auth_type = "Open"

        network_info = (ssid, bssid, channel, auth_type)
        if network_info not in found_networks:
            found_networks.append(network_info)
            print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Auth: {auth_type}")

def find_wifi_networks(interface):
    for channel in range(1, 14):
        os.system(f"iwconfig {interface} channel {channel}")
        print(f"Scanning on channel {channel}...")
        sniff(iface=interface, prn=handle_packet, timeout=5)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
find_wifi_networks(interface_name)
