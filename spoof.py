from scapy.all import *
import os

handshake_captured = False
handshake_packets = []

def handle_packet(pkt):
    global handshake_captured, handshake_packets

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

    if pkt.haslayer(Dot11EAPOL):
        if not handshake_captured:
            handshake_packets.append(pkt)
            print("Captured EAPOL packet for handshake.")
            if len(handshake_packets) == 4:  # Menyimpan 4 paket handshake (dua dari AP, dua dari client)
                wrpcap("handshake.cap", handshake_packets)
                print("Handshake capture completed.")
                handshake_captured = True
                
                # Menjalankan tshark untuk mengecek apakah file handshake memiliki paket EAPOL
                tshark_check_command = f"tshark -r handshake.cap -Y 'eapol'"
                tshark_check_result = os.popen(tshark_check_command).read()
                if 'EAPOL' in tshark_check_result:
                    print("File handshake memiliki paket EAPOL.")
                else:
                    print("File handshake tidak memiliki paket EAPOL.")

def find_wifi_networks(interface):
    for channel in range(1, 14):
        os.system(f"iwconfig {interface} channel {channel}")
        print(f"Scanning on channel {channel}...")
        sniff(iface=interface, prn=handle_packet, timeout=10)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
find_wifi_networks(interface_name)
