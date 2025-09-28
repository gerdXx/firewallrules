#!/usr/bin/env python3
"""
GeoIP Auto Forward (iptables-Version)
- Prüft IPs in MySQL / via ipapi.co
- Wenn DE → erstellt iptables-Forward-Regel von <IP>:30000 → 192.168.11.203:443
- Wenn nicht DE → IP in non_de_block ipset
"""

import mysql.connector
import requests
import subprocess
from datetime import datetime
import time

FORWARD_HOST = "192.168.11.203"
FORWARD_PORT = 443
LISTEN_PORT = 30000

DB_CONFIG = {
    "host": "localhost",
    "user": "geoipuser",
    "password": "geopass",
    "database": "geoipdb"
}

IPSET_ALLOW = "de_allow"
IPSET_BLOCK = "non_de_block"


def run(cmd):
    """Hilfsfunktion für ipset/iptables-Kommandos"""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def ensure_ipsets():
    run(["ipset", "create", IPSET_ALLOW, "hash:ip", "-exist"])
    run(["ipset", "create", IPSET_BLOCK, "hash:ip", "-exist"])


def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip VARCHAR(45) PRIMARY KEY,
            country VARCHAR(5),
            last_seen TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def get_all_ips():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, country FROM ip_cache")
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


def fetch_country(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None


def forward_rule_exists(ip):
    """Prüfen ob Regel für diese IP schon existiert"""
    check = run([
        "iptables", "-t", "nat", "-C", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{FORWARD_HOST}:{FORWARD_PORT}"
    ])
    return check.returncode == 0


def add_forward_rule(ip):
    if forward_rule_exists(ip):
        return

    # DNAT-Regel
    run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{FORWARD_HOST}:{FORWARD_PORT}"
    ])

    # Forward erlauben
    run([
        "iptables", "-A", "FORWARD",
        "-s", ip, "-d", FORWARD_HOST,
        "-p", "tcp", "--dport", str(FORWARD_PORT),
        "-j", "ACCEPT"
    ])
    print(f"[+] iptables-Forward für {ip} → {FORWARD_HOST}:{FORWARD_PORT} gesetzt")


def process_ip(ip, country=None):
    if not country:
        country = fetch_country(ip)
        if not country:
            print(f"[!] {ip} → Land unbekannt → block")
            run(["ipset", "add", IPSET_BLOCK, ip, "-exist"])
            return

        save_ip_info(ip, country)

    if country == "DE":
        run(["ipset", "add", IPSET_ALLOW, ip, "-exist"])
        add_forward_rule(ip)
        print(f"[ALLOW] {ip} (DE)")
    else:
        run(["ipset", "add", IPSET_BLOCK, ip, "-exist"])
        print(f"[BLOCK] {ip} ({country})")


if __name__ == "__main__":
    print("[*] GeoIP Auto Forward (iptables-Version) startet...")
    init_db()
    ensure_ipsets()

    while True:
        try:
            ips = get_all_ips()
            for ip, country in ips:
                process_ip(ip, country)
        except Exception as e:
            print(f"[!] Fehler: {e}")

        time.sleep(60)  # alle 60 Sekunden prüfen
