#!/usr/bin/env python3
"""
Tiny Threat Intelligence Platform (Terminal Demo)
- Downloads malicious domains from URLhaus
- Stores them in SQLite database
- Lets you check multiple domains for malicious status
"""

import requests
import sqlite3
import json
import uuid
from datetime import datetime

URLHOSTS = "https://urlhaus.abuse.ch/downloads/hostfile/"
DB_FILE = "iocs.db"

# --- ASCII Banner ---
print("""
████████╗██╗███╗   ██╗██╗   ██╗
╚══██╔══╝██║████╗  ██║██║   ██║
   ██║   ██║██╔██╗ ██║██║   ██║
   ██║   ██║██║╚██╗██║██║   ██║
   ██║   ██║██║ ╚████║╚██████╔╝
   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝
Tiny Threat Intelligence Platform
""")

def fetch_hostfile():
    print("📥 Downloading hostfile from URLhaus...")
    r = requests.get(URLHOSTS, timeout=30)
    r.raise_for_status()
    return r.text.splitlines()

def parse_domains(lines):
    domains = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        domain = parts[-1]
        if '/' in domain or ':' in domain or domain.count('.') == 0:
            continue
        domains.add(domain.lower())
    return sorted(domains)

def save_sqlite(domains):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id TEXT PRIMARY KEY,
            domain TEXT UNIQUE,
            status TEXT,
            collected_at TEXT,
            stix_json TEXT
        )
    ''')
    collected_at = datetime.utcnow().isoformat() + "Z"
    for d in domains:
        obj = {
            "id": f"indicator--{uuid.uuid4()}",
            "domain": d,
            "status": "malicious",
            "collected_at": collected_at
        }
        c.execute('INSERT OR IGNORE INTO indicators VALUES (?, ?, ?, ?, ?)',
                  (obj["id"], obj["domain"], obj["status"], obj["collected_at"], json.dumps(obj)))
    conn.commit()
    conn.close()

def show_sample():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT domain, status, collected_at FROM indicators LIMIT 10")
    rows = cur.fetchall()
    conn.close()
    print("\n🔎 Sample of collected indicators:")
    print("====================================")
    for r in rows:
        print(f"🌐 Domain: {r[0]} | Status: {r[1]} | Collected at: {r[2]}")

def check_domain(domain):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT status FROM indicators WHERE domain=?", (domain.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "unknown"

def interactive_check():
    print("\n💡 Check domains for malicious status. Type 'exit' to quit.")
    while True:
        user_input = input("Enter domain: ").strip()
        if user_input.lower() in ['exit', 'quit']:
            print("👋 Exiting. Demo finished!")
            break
        status = check_domain(user_input)
        print(f"👉 Domain '{user_input}' is: {status.upper()}")

def main():
    lines = fetch_hostfile()
    domains = parse_domains(lines)
    print(f"✅ Found {len(domains)} malicious domains.")
    save_sqlite(domains)
    show_sample()
    interactive_check()

if __name__ == "__main__":
    main()

import requests
from datetime import datetime

API_KEY = "769382b02d7639ba5624bf484d3471d1d09d34d09de154aff9321c5a00b35d0"
BASE_URL = "https://www.virustotal.com/api/v3/domains/"

# Known malicious domains (hardcoded)
malicious_domains = {
    "acc.jiangsujiaxue.com",
    "acc.o365drive-support.com",
    "acc.wtshelp.top",
    "agapi.cqjjb.cn"
}

def check_domain(domain):
    if domain in malicious_domains:
        status = "MALICIOUS"
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        print(f"🌐 Domain: {domain} | Status: {status} | Collected at: {timestamp}")
        return

    # Optional: check VirusTotal API
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(BASE_URL + domain, headers=headers)
        data = response.json()
        last_analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if last_analysis.get("malicious", 0) > 0:
            status = "MALICIOUS"
        elif last_analysis.get("harmless", 0) > 0:
            status = "SAFE"
        else:
            status = "UNKNOWN"

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        print(f"🌐 Domain: {domain} | Status: {status} | Collected at: {timestamp}")

    except Exception as e:
        print(f"Error checking domain '{domain}': {e}")

def main():
    print("💡 Check domains for malicious status. Type 'exit' to quit.")
    while True:
        domain = input("Enter domain: ").strip()
        if domain.lower() == 'exit':
            print("👋 Exiting. Demo finished!")
            break
        check_domain(domain)

if __name__ == "__main__":
    main()


