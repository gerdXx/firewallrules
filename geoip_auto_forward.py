#!/usr/bin/env python3
import subprocess
import time
import mysql.connector
import requests
from datetime import datetime

# --- Konfiguration (ggf. anpassen) ---
DB_HOST = "localhost"
DB_USER = "geoipuser"
DB_PASS = "geopass"
DB_NAME = "geoipdb"

TARGET_IP = "192.168.11.203"
TARGET_PORT = 443
LISTEN_PORT = 30000

IPSET_ALLOW = "de_allow"
IPSET_BLOCK = "non_de_block"

# ---- Hilfsfunktionen ----
def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}", flush=True)

# DB: sicherstellen, dass Tabelle existiert
def init_db():
    conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip VARCHAR(45) PRIMARY KEY,
            country VARCHAR(5),
            last_seen DATETIME
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

# IPs aus ipset auslesen (sichere Methode)
def get_ipset_members(setname):
    p = run(["ipset", "list", setname, "-o", "save"])
    if p.returncode != 0:
        return []
    ips = []
    for line in p.stdout.splitlines():
        # Zeilen mit: "add de_allow 1.2.3.4"
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "add":
            ips.append(parts[2])
    return ips

# prüfen ob iptables DNAT-Regel existiert
def forward_rule_exists(ip):
    check = run([
        "iptables", "-t", "nat", "-C", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{TARGET_IP}:{TARGET_PORT}"
    ])
    return check.returncode == 0

# fügt DNAT + FORWARD für ip hinzu (idempotent)
def add_forward_rule(ip):
    if forward_rule_exists(ip):
        return
    run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{TARGET_IP}:{TARGET_PORT}"
    ])
    run([
        "iptables", "-C", "FORWARD",
        "-s", ip, "-d", TARGET_IP, "-p", "tcp", "--dport", str(TARGET_PORT),
        "-j", "ACCEPT"
    ])
    # Falls die -C oben nicht existiert, füge dann hinzu:
    if run(["iptables", "-C", "FORWARD", "-s", ip, "-d", TARGET_IP, "-p", "tcp", "--dport", str(TARGET_PORT), "-j", "ACCEPT"]).returncode != 0:
        run([
            "iptables", "-A", "FORWARD",
            "-s", ip, "-d", TARGET_IP, "-p", "tcp", "--dport", str(TARGET_PORT),
            "-j", "ACCEPT"
        ])
    log(f"Added iptables forward rule for {ip} -> {TARGET_IP}:{TARGET_PORT}")

# löscht DNAT + FORWARD für ip (wenn es entblockt wird)
def remove_forward_rule(ip):
    # versuche zu löschen, ignorier Fehler
    run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(LISTEN_PORT),
        "-j", "DNAT", "--to-destination", f"{TARGET_IP}:{TARGET_PORT}"
    ])
    run([
        "iptables", "-D", "FORWARD",
        "-s", ip, "-d", TARGET_IP, "-p", "tcp", "--dport", str(TARGET_PORT),
        "-j", "ACCEPT"
    ])
    log(f"Removed iptables forward rule for {ip} (if existed)")

# Basisregeln prüfen/setzen (drop non_de_block; accept port)
def ensure_base_rules():
    # drop non_de_block (insert top)
    if run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", IPSET_BLOCK, "src", "-j", "DROP"]).returncode != 0:
        run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", IPSET_BLOCK, "src", "-j", "DROP"])
    # ensure accept on LISTEN_PORT exists
    if run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT), "-j", "ACCEPT"]).returncode != 0:
        run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT), "-j", "ACCEPT"])

# Masquerade sicherstellen (einmalig)
def ensure_masquerade():
    # ermitteln externes Interface
    p = run(["sh", "-c", "ip route | awk '/default/ {print $5; exit}'"])
    if p.returncode != 0:
        return
    ext_if = p.stdout.strip()
    if not ext_if:
        return
    # prüfen und setzen
    if run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", ext_if, "-j", "MASQUERADE"]).returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ext_if, "-j", "MASQUERADE"])
        log(f"MASQUERADE added on {ext_if}")

# IP-Forwarding sicherstellen
def ensure_ip_forward():
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

# Hauptloop: ipset lesen und Regeln sicher anlegen/entfernen
def main_loop():
    init_db()
    ensure_ip_forward()
    ensure_masquerade()
    # ensure ipsets exist
    run(["ipset", "create", IPSET_ALLOW, "hash:ip", "-exist"])
    run(["ipset", "create", IPSET_BLOCK, "hash:ip", "-exist"])
    log("Started main loop")
    seen_rules = set()
    while True:
        try:
            ensure_base_rules()
            allowed = get_ipset_members(IPSET_ALLOW)

            # add rules for allowed IPs
            for ip in allowed:
                if ip not in seen_rules:
                    add_forward_rule(ip)
                    seen_rules.add(ip)

            # remove rules for IPs that are no longer allowed
            for ip in list(seen_rules):
                if ip not in allowed:
                    remove_forward_rule(ip)
                    seen_rules.remove(ip)

        except Exception as e:
            log(f"Error in main loop: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main_loop()
