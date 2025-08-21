#!/usr/bin/env python3
"""
Log Generator for Apache and Nginx
----------------------------------
Generates fake access logs containing:
- Normal traffic
- Brute force attempts
- Directory traversal
- SQL Injection
- Suspicious User-Agent
"""

import random
import time
from datetime import datetime, timedelta

# -------------------------
# Configuration
# -------------------------
APACHE_LOG = "./apache_access.log"
NGINX_LOG = "./nginx_access.log"

NUM_LOGS = 200

ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]
users = ["-", "admin", "guest"]
methods = ["GET", "POST"]
uas_normal = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/8.0",
]
uas_bad = [
    "sqlmap/1.7",
    "nikto/2.1.6",
    "hydra/9.1",
    "nmap/7.94",
]

# Malicious payloads
paths_normal = ["/", "/index.html", "/about", "/contact", "/login", "/products"]
paths_traversal = ["/../../etc/passwd", "/..%2F..%2F..%2Fwindows/win.ini"]
paths_sqli = [
    "/p.php?id=1' OR 1=1 --",
    "/search?q=test' UNION SELECT * FROM users --",
]
paths_bruteforce = ["/login", "/admin"]


def rand_timestamp():
    now = datetime.now()
    delta = timedelta(seconds=random.randint(0, 3600))
    ts = now - delta
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z") or ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def make_apache_log(ip, user, method, path, status, size, ua):
    ts = rand_timestamp()
    return f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def make_nginx_log(ip, user, method, path, status, size, ua, req_time=0.123):
    ts = rand_timestamp()
    return f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}" {req_time:.3f}'


def generate_logs():
    apache_logs = []
    nginx_logs = []

    for _ in range(NUM_LOGS):
        ip = random.choice(ips)
        user = random.choice(users)
        method = random.choice(methods)
        ua = random.choice(uas_normal + uas_bad)

        # Randomly select attack type or normal
        attack_type = random.choices(
            ["normal", "bruteforce", "traversal", "sqli", "badua"],
            weights=[70, 10, 5, 10, 5],
        )[0]

        if attack_type == "normal":
            path = random.choice(paths_normal)
            status = random.choice([200, 302, 404])
        elif attack_type == "bruteforce":
            path = random.choice(paths_bruteforce)
            status = 401
        elif attack_type == "traversal":
            path = random.choice(paths_traversal)
            status = 404
        elif attack_type == "sqli":
            path = random.choice(paths_sqli)
            status = random.choice([200, 500])
        elif attack_type == "badua":
            path = random.choice(paths_normal)
            ua = random.choice(uas_bad)
            status = 200

        size = random.randint(100, 5000)

        apache_logs.append(make_apache_log(ip, user, method, path, status, size, ua))
        nginx_logs.append(make_nginx_log(ip, user, method, path, status, size, ua))

    return apache_logs, nginx_logs


def main():
    apache_logs, nginx_logs = generate_logs()

    with open(APACHE_LOG, "w") as f:
        for line in apache_logs:
            f.write(line + "\n")

    with open(NGINX_LOG, "w") as f:
        for line in nginx_logs:
            f.write(line + "\n")

    print(f"✅ Generated {len(apache_logs)} Apache logs -> {APACHE_LOG}")
    print(f"✅ Generated {len(nginx_logs)} Nginx logs -> {NGINX_LOG}")


if __name__ == "__main__":
    main()
