
📡 Pretty Packet Sniffer

A Linux-compatible Python packet sniffer with filters, CSV logging, and a live, colorful terminal dashboard.

This tool is perfect for learning network behavior, practicing cybersecurity monitoring, or just seeing your network traffic in a clean, visual way.

Features

✅ Protocol Filtering – Capture only TCP, UDP, ICMP, or all packets.

✅ IP Filtering – Focus on specific source or destination IPs.

✅ CSV Logging – Save all captured packets for later analysis.

✅ Pretty Terminal Output – Live tables with packet info and protocol stats using Rich
.

✅ Linux Ready – Works on Ubuntu and other Linux systems.

Requirements

Python 3.x

Rich
 library for pretty terminal output

Install Rich with:

sudo pip3 install rich

Usage

Clone the repository:

git clone https://github.com/<your-username>/packet-sniffer.git
cd packet-sniffer


Run the sniffer (Linux requires sudo for raw sockets):

sudo python3 sniffer.py


Customize filters at the top of sniffer.py:

FILTER_PROTOCOL = "ALL"  # "TCP", "UDP", "ICMP"
FILTER_SRC_IP = ""        # e.g., "192.168.1.2"
FILTER_DST_IP = ""        # e.g., "8.8.8.8"


Press Ctrl+C to stop the sniffer. All captured packets are saved to captured_packets.csv.

Example Output
Time                      Protocol  Source IP       Destination IP  TTL  Length
2026-02-14 14:30:12.123   TCP       192.168.1.2    172.217.0.14    64   74
2026-02-14 14:30:12.223   UDP       192.168.1.2    8.8.8.8         128  60

Protocol Counts:
TCP: 12  |  UDP: 5  |  ICMP: 0  |  Other: 0

Why This Project Is Cool

Helps you understand how packets travel across a network.

Lets you practice filtering and analyzing traffic like a cybersecurity pro.

Shows how attackers sniff traffic — so you can learn to defend networks.

License

This project is open source. Feel free to use, modify, and learn from it!
