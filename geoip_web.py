#!/usr/bin/env python3
"""
geoip_web.py – Webinterface für GeoIP-Filter
- Anzeige aller IPs (aus MySQL)
- Manuelles Allow/Block/Unblock
"""

from flask import Flask, render_template_string, redirect, url_for
import mysql.connector
import subprocess

# --- Config ---
DB_CONFIG = {
    "host": "localhost",
    "user": "geoipuser",
    "password": "geopass",
    "database": "geoipdb"
}
IPSET_ALLOW = "de_allow"
IPSET_BLOCK = "non_de_block"

# --- Helper ---
def run(cmd: list[str]):
    subprocess.run(cmd, check=False)

def get_all_ips():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT ip, country, last_seen FROM ip_cache ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def allow_ip(ip):
    run(["sudo", "ipset", "add", IPSET_ALLOW, ip, "-exist"])

def block_ip(ip):
    run(["sudo", "ipset", "add", IPSET_BLOCK, ip, "-exist"])

def unblock_ip(ip):
    run(["sudo", "ipset", "del", IPSET_ALLOW, ip])
    run(["sudo", "ipset", "del", IPSET_BLOCK, ip])

# --- Flask App ---
app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>GeoIP Filter</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background: #eee; }
    a { margin: 0 5px; }
  </style>
</head>
<body>
  <h1>GeoIP Filter Verwaltung</h1>
  <table>
    <tr><th>IP</th><th>Land</th><th>Letzte Verbindung</th><th>Aktion</th></tr>
    {% for row in rows %}
    <tr>
      <td>{{ row.ip }}</td>
      <td>{{ row.country or "-" }}</td>
      <td>{{ row.last_seen }}</td>
      <td>
        <a href="{{ url_for('allow', ip=row.ip) }}">✅ Allow</a>
        <a href="{{ url_for('block', ip=row.ip) }}">⛔ Block</a>
        <a href="{{ url_for('unblock', ip=row.ip) }}">🗑 Unblock</a>
      </td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

@app.route("/")
def index():
    rows = get_all_ips()
    return render_template_string(TEMPLATE, rows=rows)

@app.route("/allow/<ip>")
def allow(ip):
    allow_ip(ip)
    return redirect(url_for("index"))

@app.route("/block/<ip>")
def block(ip):
    block_ip(ip)
    return redirect(url_for("index"))

@app.route("/unblock/<ip>")
def unblock(ip):
    unblock_ip(ip)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
