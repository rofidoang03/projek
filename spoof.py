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

def capture_handshake(pkt):
    global ssid_to_capture, handshake_captured, handshake_packets

    if pkt.haslayer(Dot11EAPOL) and ssid_to_capture is not None:
        if not handshake_captured:
            if pkt[Dot11].addr3 == ssid_to_capture:
                handshake_packets.append(pkt)
                print("Captured EAPOL packet for handshake.")
                if len(handshake_packets) == 4:  # Menyimpan 4 paket handshake (dua dari AP, dua dari client)
                    wrpcap("handshake.cap", handshake_packets)
                    print("Handshake capture completed.")
                    handshake_captured = True

def find_wifi_networks(interface):
    global ssid_to_capture, handshake_captured, handshake_packets

    ssid_to_capture = None
    handshake_captured = False
    handshake_packets = []

    sniff(iface=interface, prn=handle_packet, timeout=10)

    ssid_input = input("Masukkan SSID yang ingin Anda capture handshake-nya: ")
    for network in found_networks:
        if ssid_input == network[0]:
            ssid_to_capture = network[1]
            break

    if ssid_to_capture is not None:
        sniff(iface=interface, prn=capture_handshake, timeout=30)

# Ganti "wlan0" dengan interface wireless Anda
interface_name = "wlan0"
find_wifi_networks(interface_name)
