Network Security Monitoring Project

Network monitoring provides continuously visibility into network traffic and monitor real-time performance and provides details into the packets and alerts the user for any attacks or malicious activity.

Why Do We Need Network Monitoring?

We Need Network Monitoring to provide visibility about the traffic patterns and spot the unusual anomalies.

Network Monitoring can prevent firewalls fail and the monitoring helps find hidden attackers before they steal data.

This projects Proives:

Network Flooding: Detects unusually large number of packets originating from the same source within a defined time window.


SYN Flooding: Detects a high number of TCP SYN packets from the same source within a short period.

Provides a Security Alert Dashboard which includes:

Network Statistics

Captured Packets

Security alerts

Source IP Address

Detection Evidence.

Technology Used:
Python
Scapy
Nmap
SQLite
Flask
HTML
CSS

To Use the Project, you require:

Python version of 3.10

To check the Python version, you can use: python --version

Install Required Packages:

Install Flask: pip install flask

Install Scapy: pip install scapy

Install Nmap

To run the Network Packet Sniffer

Save all the files in a folder named NS and go to the command prompt and run the first command of packet sniffer ie,

python packet_sniffer.py

TO STOP THE PACKET CAPTURE DO CONTROL + C ON THE KEYBOARD

Launch a New Command Prompt and run Detection Engine by: python detection_engine.py

To View the Security Alerts run: python view_alerts.py

To Start the Dashboard run: python app.py where flask will create a live application hosted on local ip (http://127.0.0.1:5000)
