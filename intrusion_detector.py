from scapy.all import sniff
from collections import defaultdict

ip_counter = defaultdict(int)
alerted_ips = set()

THRESHOLD = 10

def detect_intrusion(packet):

    if packet.haslayer("IP"):

        src = packet["IP"].src
        dst = packet["IP"].dst

        ip_counter[src] += 1

        print(f"Packet: {src} -> {dst} | Count: {ip_counter[src]}")

        if ip_counter[src] > THRESHOLD and src not in alerted_ips:

            alert = f"ALERT: Possible Intrusion Detected from {src}"

            print(alert)

            with open("log.txt", "a") as log:
                log.write(alert + "\n")

            alerted_ips.add(src)

sniff(prn=detect_intrusion, store=False)