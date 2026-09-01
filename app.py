from flask import Flask, render_template, jsonify, request
import sqlite3
import os


app = Flask(__name__)


DATABASE_NAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "network_monitor.db"
)


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def dashboard():

    connection = get_connection()

    # Total packets
    packet_count = connection.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    # Total alerts
    alert_count = connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    # High severity alerts
    high_alert_count = connection.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
    ).fetchone()[0]

    # Protocol statistics
    protocols = connection.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchall()

    # Threat statistics
    port_scan_count = connection.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'Possible Port Scan'
    """).fetchone()[0]

    flooding_count = connection.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'Possible Network Flooding'
    """).fetchone()[0]

    syn_flood_count = connection.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'Possible SYN Flood'
    """).fetchone()[0]

    # Top source IPs
    top_sources = connection.execute("""
        SELECT source_ip, COUNT(*) AS count
        FROM packets
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Recent packets
    recent_packets = connection.execute("""
        SELECT
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        FROM packets
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    # Recent alerts
    alerts = connection.execute("""
        SELECT
            timestamp,
            source_ip,
            alert_type,
            severity,
            evidence
        FROM alerts
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        packet_count=packet_count,
        alert_count=alert_count,
        high_alert_count=high_alert_count,
        protocols=protocols,
        port_scan_count=port_scan_count,
        flooding_count=flooding_count,
        syn_flood_count=syn_flood_count,
        top_sources=top_sources,
        recent_packets=recent_packets,
        alerts=alerts
    )


@app.route("/api/packets")
def api_packets():

    connection = get_connection()

    packets = connection.execute("""
        SELECT
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        FROM packets
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    connection.close()

    return jsonify([dict(packet) for packet in packets])


@app.route("/api/alerts")
def api_alerts():

    connection = get_connection()

    alerts = connection.execute("""
        SELECT
            timestamp,
            source_ip,
            alert_type,
            severity,
            evidence
        FROM alerts
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    connection.close()

    return jsonify([dict(alert) for alert in alerts])


@app.route("/api/stats")
def api_stats():

    connection = get_connection()

    packet_count = connection.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    alert_count = connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    high_alert_count = connection.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
    ).fetchone()[0]

    connection.close()

    return jsonify({
        "packet_count": packet_count,
        "alert_count": alert_count,
        "high_alert_count": high_alert_count
    })


if __name__ == "__main__":
    print("=" * 60)
    print("             NETWORK SECURITY MONITOR")
    print("=" * 60)
    print()
    print("Database:", DATABASE_NAME)
    print()
    print("Dashboard:")
    print("http://127.0.0.1:5000")
    print()
    print("Press CTRL+C to stop the server.")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )