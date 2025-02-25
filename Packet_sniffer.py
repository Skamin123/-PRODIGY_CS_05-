#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        # Print basic packet information
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst} | Protocol: {protocol}")

        # If the packet has a TCP or UDP layer, print the payload
        if TCP in packet:
            payload = bytes(packet[TCP].payload)
            print(f"TCP Payload: {payload}")
        elif UDP in packet:
            payload = bytes(packet[UDP].payload)
            print(f"UDP Payload: {payload}")

        # Print a separator for readability
        print("-" * 50)

def main():
    # Start sniffing packets
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
