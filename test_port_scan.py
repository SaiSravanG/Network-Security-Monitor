import sqlite3
from datetime import datetime, timedelta


DATABASE_NAME = "network_monitor.db"


source_ip = "192.168.29.100"

ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    443
]


connection = sqlite3.connect(DATABASE_NAME)

base_time = datetime.now()


for index, port in enumerate(ports):

    timestamp = (
        base_time + timedelta(seconds=index)
    ).strftime("%Y-%m-%d %H:%M:%S")

    connection.execute("""
        INSERT INTO packets (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        "192.168.29.54",
        "TCP",
        "50000",
        str(port),
        60,
        "S"
    ))


connection.commit()
connection.close()


print("Test port-scan data inserted successfully.")
print(f"Source IP: {source_ip}")
print(f"Ports tested: {ports}")