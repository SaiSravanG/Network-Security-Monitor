import sqlite3
from datetime import datetime, timedelta


DATABASE_NAME = "network_monitor.db"

source_ip = "192.168.29.102"

connection = sqlite3.connect(DATABASE_NAME)

base_time = datetime.now()

for i in range(60):

    timestamp = (
        base_time + timedelta(seconds=i // 6)
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
        40000 + i,
        80,
        60,
        "S"
    ))

connection.commit()
connection.close()

print("Test SYN flood data inserted successfully.")
print(f"Source IP: {source_ip}")
print("SYN packets inserted: 60")