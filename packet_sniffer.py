from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"\n[+] {protocol} Packet")
        print(f"Source: {src_ip}")
        print(f"Destination: {dst_ip}")

print("Starting Packet Sniffer...")
print("Press CTRL+C to stop.\n")

sniff(prn=process_packet, store=False)