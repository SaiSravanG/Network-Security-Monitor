import sqlite3


DATABASE_NAME = "network_monitor.db"


def view_alerts():

    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row

    alerts = connection.execute("""
        SELECT
            timestamp,
            source_ip,
            alert_type,
            severity,
            evidence
        FROM alerts
        ORDER BY timestamp DESC
    """).fetchall()

    connection.close()

    print()
    print("=" * 70)
    print("                    SECURITY ALERTS")
    print("=" * 70)

    if not alerts:
        print()
        print("No security alerts recorded.")
        print("Total alerts: 0")
        return

    print()
    print(f"Total alerts: {len(alerts)}")
    print()

    for alert in alerts:

        print("-" * 70)

        print(f"Time:       {alert['timestamp']}")
        print(f"Source IP:  {alert['source_ip']}")
        print(f"Alert:      {alert['alert_type']}")
        print(f"Severity:   {alert['severity']}")
        print(f"Evidence:   {alert['evidence']}")

    print("-" * 70)


if __name__ == "__main__":
    view_alerts()