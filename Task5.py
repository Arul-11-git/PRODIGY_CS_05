
import time
from scapy.all import IP, conf
from scapy.arch import get_windows_if_list  # For Windows only
from scapy.all import sniff, IP
# Data storage for packets
packet_data = []

# Initialize counters for different protocols
packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

def packet_handler(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        if proto == 6:
            protocol = "TCP"
            packet_counts['TCP'] += 1
        elif proto == 17:
            protocol = "UDP"
            packet_counts['UDP'] += 1
        elif proto == 1:
            protocol = "ICMP"
            packet_counts['ICMP'] += 1
        else:
            protocol = "Other"
            packet_counts['Other'] += 1
        
        payload = bytes(packet[IP].payload)[:20]  # Limiting payload for display purposes
        
        packet_info = {
            'Source': src_ip,
            'Destination': dst_ip,
            'Protocol': protocol,
            'Payload': payload
        }
        packet_data.append(packet_info)
        
        # Update the console with packet details
        print(f"Source: {packet_info['Source']} | Destination: {packet_info['Destination']} | Protocol: {packet_info['Protocol']}")
        print(f"Payload: {packet_info['Payload']}\n")

def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=packet_handler, filter="ip",timeout = 10, store=False)
    sniffing = False

    
start_sniffing()


















