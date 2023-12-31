from scapy.all import *

# List untuk menyimpan SSID yang sudah ditemukan
found_ssids = []

# Fungsi untuk menangani paket Beacon (untuk menemukan jaringan Wi-Fi)
def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        if ssid not in found_ssids:
            found_ssids.append(ssid)
            print(f"SSID: {ssid}, BSSID: {bssid}")

# Memulai sniffing pada interface wireless
def find_wifi_networks(interface):
    sniff(iface=interface, prn=handle_packet)

# Ganti "wlan0" dengan interface wireless Anda
find_wifi_networks("wlan0")
