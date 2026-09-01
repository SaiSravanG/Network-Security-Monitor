import sqlite3
from datetime import datetime


DATABASE_NAME = "network_monitor.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_NAME,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


def create_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port TEXT,
            destination_port TEXT,
            packet_size INTEGER,
            tcp_flags TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            alert_type TEXT,
            severity TEXT,
            evidence TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_packet(
    timestamp,
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    packet_size,
    tcp_flags
):
    connection = get_connection()

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
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        tcp_flags
    ))

    connection.commit()
    connection.close()


def save_alert(
    source_ip,
    alert_type,
    severity,
    evidence
):
    connection = get_connection()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    connection.execute("""
        INSERT INTO alerts (
            timestamp,
            source_ip,
            alert_type,
            severity,
            evidence
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        alert_type,
        severity,
        evidence
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_database()
    print("Database created successfully.")