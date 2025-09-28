#!/usr/bin/env python3
"""
Flask Webinterface für GeoIP-Filter
- Listet alle bekannten IPs
- Ermöglicht Allow / Block / Unblock
"""

from flask import Flask, render_template_string, redirect, url_for
import mysql.connector
import subprocess
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "geoipuser",
    "password": "geopass",
    "database": "geoipdb"
}

IPSET_ALLOW = "de_allow"
IPSET_BLOCK = "non_de_block"

FORWARD_HOST = "192.168.11.203"
FORWARD_PORT = 443
LISTEN_PORT = 30000

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>GeoIP Filter</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #f2f2f2; }
        a { padding: 4px 8px; background: #ddd; margin: 2px; text-decoration: none; }
        a.allow { background: #8f8; }
        a.block { background: #f88; }
        a.unblock { background: #88f; color: #fff; }
    </style>
</head>
<body>
    <h1>GeoIP Filter - Webinterface</h1>
    <table>
        <tr>
            <th>IP</th><th>Country</th><th>Last Seen</th><th>Aktionen</th>
        </tr>
        {% for ip,country,last_seen in ips %}
        <tr>
            <td>{{ ip }}</td>
            <td>{{ country }}</td>
            <td>{{ last_seen }}</td>
            <td>
                <a href="{{ url_for('allow_ip', ip=ip) }}" class="allow">Allow</a>
                <a href="{{ url_for('block_ip', ip=ip) }}" class="block">Block</a>
                <a href="{{ url_for('unblock_ip', ip=ip) }}" class="unblock">Unblock</a>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def get_all_ips():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, country, last_seen FROM ip_cache ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def save_ip_info(ip, country):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ip_cache (ip, country, last_seen)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE country=%s, last_seen=%s
    """, (ip, country, datetime.now(), country, datetime.now()))
    conn.commit()
    cursor.close()
    conn.close()

def add_forward_rule(ip):
    run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{FORWARD_HOST}:{FORWARD_PORT}"
    ])
    run([
        "iptables", "-A", "FORWARD",
        "-s", ip, "-d", FORWARD_HOST,
        "-p", "tcp", "--dport", str(FORWARD_PORT),
        "-j", "ACCEPT"
    ])
    print(f"[WEB] Forward-Regel für {ip} gesetzt")

@app.route("/")
def index():
    ips = get_all_ips()
    return render_template_string(HTML_TEMPLATE, ips=ips)

@app.route("/allow/<ip>")
def allow_ip(ip):
    run(["ipset", "add", IPSET_ALLOW, ip, "-exist"])
    save_ip_info(ip, "DE")
    add_forward_rule(ip)
    return redirect(url_for("index"))

@app.route("/block/<ip>")
def block_ip(ip):
    run(["ipset", "add", IPSET_BLOCK, ip, "-exist"])
    save_ip_info(ip, "XX")
    return redirect(url_for("index"))

@app.route("/unblock/<ip>")
def unblock_ip(ip):
    run(["ipset", "del", IPSET_ALLOW, ip], check=False)
    run(["ipset", "del", IPSET_BLOCK, ip], check=False)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
