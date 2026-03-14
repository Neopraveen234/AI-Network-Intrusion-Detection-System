# AI-Based Network Intrusion Detection System (NIDS)

This project is a basic Network Intrusion Detection System developed using Python and Scapy. 
It monitors network traffic in real time and detects suspicious activities.

## Features

- Real-time packet sniffing
- IP traffic monitoring
- Intrusion detection based on packet count
- Suspicious port monitoring
- Alert logging

## Technologies Used

- Python
- Scapy
- Networking concepts (TCP/IP)

## Project Structure

NIDS_Project
│
├── packet_sniffer.py
├── intrusion_detector.py
├── port_monitor.py
├── log.txt
└── README.md

## How to Run

1. Install required library:

pip install scapy

2. Run packet sniffer:

python packet_sniffer.py

3. Run intrusion detection:

python intrusion_detector.py

4. Run port monitoring:

python port_monitor.py

## Future Improvements

- Machine learning based attack detection
- DDoS attack detection
- Visualization dashboard