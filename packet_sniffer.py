from scapy.all import sniff

def packet_callback(packet):

    if packet.haslayer("IP"):
        src = packet["IP"].src
        dst = packet["IP"].dst

        print(f"Packet Detected: {src} -> {dst}")

# Capture only 7 packets
sniff(prn=packet_callback, store=False, count=10)