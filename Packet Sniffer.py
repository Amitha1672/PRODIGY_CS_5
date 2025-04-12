import scapy.all as scapy

def packet_callback(packet):
    # Displaying the basic packet information
    print("\nPacket captured:")
    
    # Source and destination IP addresses
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst
        print(f"Source IP: {source_ip} --> Destination IP: {dest_ip}")
    
    # Protocol
    if packet.haslayer(scapy.IP):
        protocol = packet[scapy.IP].proto
        print(f"Protocol: {protocol}")
    
    # Displaying payload data if available
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        print(f"Payload (Raw Data): {payload}")

def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    # Start sniffing on the given network interface (None for default)
    scapy.sniff(iface=interface, prn=packet_callback, store=False)

# If you want to sniff on a specific network interface, pass it as a string, like "eth0" or "wlan0"
# For example: start_sniffing("eth0")
start_sniffing()
