from scapy.all import sniff
from collections import defaultdict

ip_counter = defaultdict(int)
port_access = defaultdict(set)
alerted_ips = set()

THRESHOLD = 10
PORT_THRESHOLD = 10


def detect_packet(packet):

    # First check if packet has IP layer
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

        # Check TCP ports only if TCP layer exists
        if packet.haslayer("TCP"):

            port = packet["TCP"].dport
            port_access[src].add(port)

            print(f"{src} accessed port {port}")

            if len(port_access[src]) > PORT_THRESHOLD and src not in alerted_ips:

                alert = f"ALERT: Port scan detected from {src}"
                print(alert)

                with open("log.txt", "a") as log:
                    log.write(alert + "\n")

                alerted_ips.add(src)


print("Starting Network Intrusion Detection System...")

sniff(prn=detect_packet, store=False)