#!/usr/bin/env python3
"""
geoip_auto_forward.py
- Lauscht auf Port 30000
- Prüft eingehende IPs in MySQL
- Erlaubt nur DE-IPs (oder manuell freigegebene)
- Leitet erlaubte Verbindungen weiter zu 192.168.11.205:433
"""

import socket
import threading
import requests
import mysql.connector
from datetime import datetime

# --- Config ---
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 30000
FORWARD_HOST = "192.168.11.203"
FORWARD_PORT = 443

DB_CONFIG = {
    "host": "localhost",
    "user": "geoipuser",
    "password": "geopass",
    "database": "geoipdb"
}

# --- DB Setup ---
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

# --- DB Funktionen ---
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

# --- GeoIP Abfrage ---
def fetch_country(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None

# --- Proxy-Handler ---
def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    print(f"[+] Verbindung von {ip}")

    row = get_ip_info(ip)
    if row:
        country = row["country"]
    else:
        country = fetch_country(ip)
        if not country:
            print(f"[!] Konnte Land für {ip} nicht bestimmen -> blockiert")
            client_sock.close()
            return
        save_ip_info(ip, country)

    print(f"[i] {ip} -> {country}")

    if country != "DE":
        print(f"[x] Nicht-DE IP blockiert: {ip}")
        client_sock.close()
        return

    try:
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_sock.connect((FORWARD_HOST, FORWARD_PORT))

        def forward(src, dst):
            while True:
                try:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
                except Exception:
                    break
            src.close()
            dst.close()

        threading.Thread(target=forward, args=(client_sock, forward_sock), daemon=True).start()
        threading.Thread(target=forward, args=(forward_sock, client_sock), daemon=True).start()

    except Exception as e:
        print(f"[!] Fehler beim Weiterleiten: {e}")
        client_sock.close()

def start_server():
    init_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(100)
    print(f"[*] Lausche auf {LISTEN_HOST}:{LISTEN_PORT} -> Weiterleitung {FORWARD_HOST}:{FORWARD_PORT}")

    while True:
        client_sock, client_addr = srv.accept()
        threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

