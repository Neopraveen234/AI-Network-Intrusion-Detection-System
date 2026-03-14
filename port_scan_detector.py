from scapy.all import sniff
from collections import defaultdict

port_access = defaultdict(set)
alerted_ips = set()

PORT_THRESHOLD = 10

def detect_port_scan(packet):

    if packet.haslayer("TCP"):

        src = packet["IP"].src
        port = packet["TCP"].dport

        port_access[src].add(port)

        print(f"{src} accessed port {port}")

        if len(port_access[src]) > PORT_THRESHOLD and src not in alerted_ips:

            alert = f"ALERT: Port scan detected from {src}"
            print(alert)

            with open("log.txt","a") as log:
                log.write(alert + "\n")

            alerted_ips.add(src)

sniff(prn=detect_port_scan, store=False, count=50)