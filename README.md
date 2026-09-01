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


The Output: <img width="512" height="113" alt="image" src="https://github.com/user-attachments/assets/4dc967ad-3ec8-4bea-8e34-e14143e3f6da" />


TO STOP THE PACKET CAPTURE DO CONTROL + C ON THE KEYBOARD

Launch a New Command Prompt and run Detection Engine by: python detection_engine.py

The Output: <img width="709" height="440" alt="image" src="https://github.com/user-attachments/assets/3d442001-cea6-476d-93c4-2acf5756794b" />



To View the Security Alerts run: python view_alerts.py

The Output: <img width="592" height="60" alt="image" src="https://github.com/user-attachments/assets/d6fce5c1-2374-4e3a-8e21-07ea17b5a761" />

To Start the Dashboard run: python app.py where flask will create a live application hosted on local ip (http://127.0.0.1:5000)

<img width="1166" height="489" alt="image" src="https://github.com/user-attachments/assets/e6f90ad4-cb8d-4182-aa42-d7f22f258918" />
