#!/usr/bin/env python3
"""
geoip_auto_forward.py (iptables/ipset Version)
- Prüft eingehende IPs in MySQL
- Holt Land via ipapi.co falls nicht vorhanden
- Schreibt IP in ipset (de_allow oder non_de_block)
"""

import mysql.connector
import requests
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

def run(cmd):
    subprocess.run(cmd, check=False)

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

def get_ip_info(ip):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ip_cache WHERE ip=%s", (ip,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row

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

def process_ip(ip):
    row = get_ip_info(ip)
    if row:
        country = row["country"]
    else:
        country = fetch_country(ip)
        if not country:
            print(f"[!] Konnte Land für {ip} nicht bestimmen → block")
            run(["ipset", "add", IPSET_BLOCK, ip, "-exist"])
            return
        save_ip_info(ip, country)

    if country == "DE":
        print(f"[+] {ip} erlaubt (DE)")
        run(["ipset", "add", IPSET_ALLOW, ip, "-exist"])
    else:
        print(f"[-] {ip} blockiert ({country})")
        run(["ipset", "add", IPSET_BLOCK, ip, "-exist"])

if __name__ == "__main__":
    init_db()
    # Beispiel: IPs manuell verarbeiten (später durch Logs oder Webinterface triggern)
    test_ips = ["8.8.8.8", "91.12.45.33"]
    for ip in test_ips:
        process_ip(ip)
