import socket
from struct import unpack
from datetime import datetime
import csv
from rich.console import Console
from rich.table import Table

# ---------------------------
# SETTINGS
# ---------------------------

# Protocol filter: "TCP", "UDP", "ICMP", or "ALL"
FILTER_PROTOCOL = "ALL"

# IP filters: leave empty "" to allow all
FILTER_SRC_IP = ""
FILTER_DST_IP = ""

# CSV file
CSV_FILE = "captured_packets.csv"

# ---------------------------
# INITIAL SETUP
# ---------------------------

console = Console()

# Prepare CSV file
with open(CSV_FILE, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP", "TTL", "Packet Length"])

# Packet counters
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Protocol mapping
def get_protocol(proto_num):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto_num, str(proto_num))

# Create raw socket (Linux)
sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

console.print("[bold green][*][/bold green] Packet sniffer started. Press Ctrl+C to stop.\n")

# ---------------------------
# MAIN LOOP
# ---------------------------

try:
    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        # Ethernet header (first 14 bytes)
        eth_header = raw_data[:14]
        eth_proto = int.from_bytes(eth_header[12:14], byteorder='big')

        # Only process IP packets
        if eth_proto == 0x0800:
            # IP header (next 20 bytes)
            ip_header = raw_data[14:34]
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0xF) * 4
            ttl = iph[5]
            proto = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            packet_protocol = get_protocol(proto)

            # Protocol filter
            if FILTER_PROTOCOL != "ALL" and packet_protocol != FILTER_PROTOCOL:
                continue

            # IP filters
            if FILTER_SRC_IP and src_ip != FILTER_SRC_IP:
                continue
            if FILTER_DST_IP and dst_ip != FILTER_DST_IP:
                continue

            # Update counters
            if packet_protocol in packet_counts:
                packet_counts[packet_protocol] += 1
            else:
                packet_counts["Other"] += 1

            # Save to CSV
            with open(CSV_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([datetime.now(), packet_protocol, src_ip, dst_ip, ttl, len(raw_data)])

            # ---------------------------
            # PRETTY TERMINAL OUTPUT
            # ---------------------------

            # Packet table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Time", style="dim")
            table.add_column("Protocol")
            table.add_column("Source IP")
            table.add_column("Destination IP")
            table.add_column("TTL")
            table.add_column("Length")

            table.add_row(str(datetime.now()), packet_protocol, src_ip, dst_ip, str(ttl), str(len(raw_data)))

            # Summary table
            summary_table = Table(show_header=True, header_style="bold cyan")
            summary_table.add_column("Protocol")
            summary_table.add_column("Count")
            for proto_name, count in packet_counts.items():
                summary_table.add_row(proto_name, str(count))

            # Clear console and print tables
            console.clear()
            console.print(table)
            console.print(summary_table)

except KeyboardInterrupt:
    console.print(f"\n[bold red][*][/bold red] Sniffer stopped. All packets saved to {CSV_FILE}")
