import subprocess
from scapy.all import *

# Fungsi untuk memeriksa apakah ada paket EAPOL di file pcap
def check_eapol(file_path):
    packets = rdpcap(file_path)
    for packet in packets:
        if packet.haslayer(EAPOL):
            return True
    return False

# Eksekusi perintah tshark untuk menangkap file handshake
command = ['tshark', '-i', 'interface_name', '-w', 'output_file.pcap', 'wlan.fc.type_subtype == 0x08']
subprocess.run(command)

# Cek apakah file pcap sudah memiliki paket EAPOL
if check_eapol('output_file.pcap'):
    print("File pcap sudah memiliki paket EAPOL, berhenti.")
    # Lakukan tindakan lain atau hentikan proses di sini
