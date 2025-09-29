#!/usr/bin/env python3
from flask import Flask, render_template_string, redirect, url_for, request
import subprocess
import mysql.connector
from datetime import datetime

# --- Konfiguration (ggf. anpassen) ---
DB_CONFIG = {
    "host": "localhost",
    "user": "geoipuser",
    "password": "geopass",
    "database": "geoipdb"
}
IPSET_ALLOW = "de_allow"
IPSET_BLOCK = "non_de_block"
LISTEN_PORT = 30000
TARGET_IP = "192.168.11.203"
TARGET_PORT = 443

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>GeoIP Filter</title></head>
<body>
<h1>GeoIP Filter</h1>
<form method="post" action="/add">
  IP: <input name="ip" required> <button type="submit">Add (check+allow)</button>
</form>
<table border="1" cellpadding="4">
<tr><th>IP</th><th>Country</th><th>Last seen</th><th>Actions</th></tr>
{% for ip,country,last in rows %}
<tr>
<td>{{ip}}</td><td>{{country}}</td><td>{{last}}</td>
<td>
  <a href="{{ url_for('allow', ip=ip) }}">Allow</a> |
  <a href="{{ url_for('block', ip=ip) }}">Block</a> |
  <a href="{{ url_for('unblock', ip=ip) }}">Unblock</a>
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
    cur = conn.cursor()
    cur.execute("SELECT ip,country,last_seen FROM ip_cache ORDER BY last_seen DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def save_ip(ip, country):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ip_cache (ip,country,last_seen) VALUES (%s,%s,%s)
        ON DUPLICATE KEY UPDATE country=VALUES(country), last_seen=VALUES(last_seen)
    """, (ip, country, datetime.utcnow()))
    conn.commit()
    cur.close()
    conn.close()

# ipset add/del helpers
def ipset_add(setname, ip):
    run(["ipset", "add", setname, ip, "-exist"])

def ipset_del(setname, ip):
    run(["ipset", "del", setname, ip])

# iptables rule removal helper
def remove_forward_rule(ip):
    # remove both nat PREROUTING and forward
    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
         "-j", "DNAT", "--to-destination", f"{TARGET_IP}:{TARGET_PORT}"])
    run(["iptables", "-D", "FORWARD", "-s", ip, "-d", TARGET_IP, "-p", "tcp", "--dport", str(TARGET_PORT), "-j", "ACCEPT"])

@app.route("/")
def index():
    rows = get_all_ips()
    return render_template_string(TEMPLATE, rows=rows)

@app.route("/allow/<ip>")
def allow(ip):
    ipset_add(IPSET_ALLOW, ip)
    save_ip(ip, "DE")
    # Optionally add rules immediately (auto-daemon also adds them)
    run(["/usr/bin/python3", "/opt/geoipfilter/geoip_auto_forward.py"])  # quick trigger (will check ipset)
    return redirect(url_for("index"))

@app.route("/block/<ip>")
def block(ip):
    ipset_add(IPSET_BLOCK, ip)
    save_ip(ip, "XX")
    return redirect(url_for("index"))

@app.route("/unblock/<ip>")
def unblock(ip):
    ipset_del(IPSET_ALLOW, request.view_args['ip'])
    ipset_del(IPSET_BLOCK, request.view_args['ip'])
    remove_forward_rule(request.view_args['ip'])
    return redirect(url_for("index"))

@app.route("/add", methods=["POST"])
def add():
    ip = request.form.get("ip")
    # optional: GeoIP lookup here, but we just save placeholder
    save_ip(ip, "??")
    ipset_add(IPSET_ALLOW, ip)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
