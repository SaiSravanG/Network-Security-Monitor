import sqlite3
from collections import defaultdict
from datetime import datetime

from database import get_connection, save_alert


# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------

TIME_WINDOW = 10

PORT_SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 100
SYN_FLOOD_THRESHOLD = 50


# ---------------------------------------------------------
# PORT SCAN DETECTION
# ---------------------------------------------------------

def detect_port_scans(connection):

    print("\nChecking for port scans...")

    rows = connection.execute("""
        SELECT
            source_ip,
            destination_port,
            timestamp
        FROM packets
        WHERE protocol = 'TCP'
          AND destination_port != '-'
        ORDER BY timestamp
    """).fetchall()

    packets_by_ip = defaultdict(list)

    for row in rows:
        packets_by_ip[row["source_ip"]].append(row)

    detected = False

    for source_ip, packets in packets_by_ip.items():

        for i in range(len(packets)):

            start_time = datetime.strptime(
                packets[i]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            ports = set()

            for packet in packets[i:]:

                packet_time = datetime.strptime(
                    packet["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                difference = (
                    packet_time - start_time
                ).total_seconds()

                if difference > TIME_WINDOW:
                    break

                ports.add(packet["destination_port"])

            if len(ports) >= PORT_SCAN_THRESHOLD:

                evidence = (
                    f"{len(ports)} unique destination ports "
                    f"detected within {TIME_WINDOW} seconds. "
                    f"Ports: {sorted(ports)}"
                )

                save_alert(
                    source_ip,
                    "Possible Port Scan",
                    "HIGH",
                    evidence
                )

                print("\n⚠ POSSIBLE PORT SCAN DETECTED")
                print(f"Source IP:       {source_ip}")
                print(f"Unique Ports:    {len(ports)}")
                print(f"Ports:           {sorted(ports)}")
                print("Severity:        HIGH")
                print("Alert saved to database.")

                detected = True
                break

    if not detected:
        print("✓ No possible port scans detected.")

    return detected


# ---------------------------------------------------------
# NETWORK FLOOD DETECTION
# ---------------------------------------------------------

def detect_network_floods(connection):

    print("\nChecking for network flooding...")

    rows = connection.execute("""
        SELECT
            source_ip,
            timestamp
        FROM packets
        ORDER BY timestamp
    """).fetchall()

    packets_by_ip = defaultdict(list)

    for row in rows:
        packets_by_ip[row["source_ip"]].append(row)

    detected = False

    for source_ip, packets in packets_by_ip.items():

        for i in range(len(packets)):

            start_time = datetime.strptime(
                packets[i]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            count = 0

            for packet in packets[i:]:

                packet_time = datetime.strptime(
                    packet["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                difference = (
                    packet_time - start_time
                ).total_seconds()

                if difference > TIME_WINDOW:
                    break

                count += 1

            if count >= FLOOD_THRESHOLD:

                evidence = (
                    f"{count} packets detected within "
                    f"{TIME_WINDOW} seconds."
                )

                save_alert(
                    source_ip,
                    "Possible Network Flooding",
                    "HIGH",
                    evidence
                )

                print("\n⚠ POSSIBLE NETWORK FLOODING")
                print(f"Source IP:       {source_ip}")
                print(f"Packet Count:    {count}")
                print(f"Time Window:     {TIME_WINDOW} seconds")
                print("Severity:        HIGH")
                print("Alert saved to database.")

                detected = True
                break

    if not detected:
        print("✓ No possible network flooding detected.")

    return detected


# ---------------------------------------------------------
# SYN FLOOD DETECTION
# ---------------------------------------------------------

def detect_syn_floods(connection):

    print("\nChecking for SYN flooding...")

    rows = connection.execute("""
        SELECT
            source_ip,
            timestamp
        FROM packets
        WHERE protocol = 'TCP'
          AND tcp_flags = 'S'
        ORDER BY timestamp
    """).fetchall()

    packets_by_ip = defaultdict(list)

    for row in rows:
        packets_by_ip[row["source_ip"]].append(row)

    detected = False

    for source_ip, packets in packets_by_ip.items():

        for i in range(len(packets)):

            start_time = datetime.strptime(
                packets[i]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            count = 0

            for packet in packets[i:]:

                packet_time = datetime.strptime(
                    packet["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                difference = (
                    packet_time - start_time
                ).total_seconds()

                if difference > TIME_WINDOW:
                    break

                count += 1

            if count >= SYN_FLOOD_THRESHOLD:

                evidence = (
                    f"{count} TCP SYN packets detected "
                    f"within {TIME_WINDOW} seconds."
                )

                save_alert(
                    source_ip,
                    "Possible SYN Flood",
                    "HIGH",
                    evidence
                )

                print("\n⚠ POSSIBLE SYN FLOOD DETECTED")
                print(f"Source IP:       {source_ip}")
                print(f"SYN Packets:     {count}")
                print(f"Time Window:     {TIME_WINDOW} seconds")
                print("Severity:        HIGH")
                print("Alert saved to database.")

                detected = True
                break

    if not detected:
        print("✓ No possible SYN flooding detected.")

    return detected


# ---------------------------------------------------------
# MAIN DETECTION ENGINE
# ---------------------------------------------------------

def run_detection():

    print()
    print("=" * 60)
    print("          NETWORK DETECTION ENGINE")
    print("=" * 60)

    connection = get_connection()

    try:

        detect_port_scans(connection)

        detect_network_floods(connection)

        detect_syn_floods(connection)

    finally:

        connection.close()

    print()
    print("=" * 60)
    print("Detection scan completed.")
    print("=" * 60)


# ---------------------------------------------------------
# PROGRAM START
# ---------------------------------------------------------

if __name__ == "__main__":
    run_detection()