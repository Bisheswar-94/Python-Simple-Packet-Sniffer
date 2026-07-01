from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from colorama import Fore, init
from datetime import datetime

init(autoreset=True)

packet_count = 0
suspicious_ips = {}

LOG_FILE = "packets_log.txt"

def log_packet(data):
    with open(LOG_FILE, "a") as file:
        file.write(data + "\n")


def process_packet(packet):

    global packet_count
    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    # ARP Monitoring
    if packet.haslayer(ARP):

        arp_src = packet[ARP].psrc
        arp_dst = packet[ARP].pdst

        output = (
            f"[{timestamp}] [ARP] "
            f"{arp_src} -> {arp_dst}"
        )

        print(Fore.MAGENTA + output)
        log_packet(output)
        return

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        src_port = ""
        dst_port = ""

        # TCP
        if packet.haslayer(TCP):

            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # HTTP Detection
            if packet.haslayer(HTTPRequest):

                print(Fore.CYAN + f"\n[HTTP TRAFFIC DETECTED]")

        # UDP
        elif packet.haslayer(UDP):

            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # ICMP
        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        # DNS Monitoring
        if packet.haslayer(DNS):

            print(Fore.YELLOW + "[DNS QUERY DETECTED]")

        # Suspicious Traffic Detection
        suspicious_ports = [22, 23, 3389]

        if dst_port in suspicious_ports:

            suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1

            print(
                Fore.RED +
                f"[ALERT] Suspicious connection from {src_ip} "
                f"to port {dst_port}"
            )

        output = (
            f"[{timestamp}] "
            f"{protocol} | "
            f"{src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port}"
        )

        print(Fore.GREEN + output)

        log_packet(output)

        print(Fore.WHITE + f"Packets Captured: {packet_count}")


print(Fore.BLUE + "=" * 50)
print(Fore.BLUE + "ADVANCED PACKET SNIFFER V2")
print(Fore.BLUE + "=" * 50)

print(Fore.WHITE + "\nStarting capture...")
print(Fore.WHITE + "Press CTRL + C to stop\n")

# Filter only useful protocols
sniff(
    filter="ip or arp",
    prn=process_packet,
    store=False
)