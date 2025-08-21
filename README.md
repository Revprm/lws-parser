# Log Web Server Parser

A Python CLI that parses Apache/Nginx access logs, detects suspicious activity (brute force, directory traversal, SQL injection, suspicious user agents, 5xx bursts), optionally enriches with GeoIP, and exports alerts to JSON/CSV. Includes a minimal Flask dashboard to view alerts.

## Features
- Apache/Nginx combined log parsing
- Detection rules:
  - Brute Force (HTTP 401 bursts) — MITRE ATT&CK T1110
  - Directory Traversal (`../`)
  - SQL Injection patterns (`UNION`, `SELECT`, `OR 1=1`)
  - Suspicious User-Agent (curl, sqlmap, scanners)
  - 5xx error burst (potential DoS)
- Optional GeoIP enrichment (MaxMind GeoLite2 City)
- Outputs JSON/CSV + human summary
- Tests, CI, and a simple dashboard

## Quick Start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# run on sample log
python -m parser.parser --log logs/apache_access.log --print \
  --out-json outputs/alerts.json --out-csv outputs/alerts.csv
