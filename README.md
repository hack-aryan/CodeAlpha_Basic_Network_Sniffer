# CodeAlpha_Basic_Network_Sniffer
This project is a lightweight network packet sniffer built with Python and Scapy. It allows users to monitor, capture, and analyze network traffic in real time from any available network interface.

Features:

Lists all network interfaces and helps users select the correct one, with friendly names on Windows.
Captures live network packets on the chosen interface.
Displays key details for each packet, including source/destination IP, protocol (TCP, UDP, ICMP), and a hex preview of the payload.
Logs every packet’s summary and full details to sniffed_packets.txt for later review.
Simple, interactive command-line interface—just run the script, pick an interface, and start sniffing.
Usage:

Run the script with Python (requires Scapy).
Select the network interface to monitor.
View live packet information in the terminal.
Press Ctrl+C to stop sniffing; all captured packets are saved for offline analysis.
Requirements:

Python 3.x
Scapy (pip install scapy)
Windows users: Run as administrator for full interface access.
