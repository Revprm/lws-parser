from pathlib import Path
from parser.utils import parse_line
from parser.rules import RuleEngine


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
        '1.1.1.1 - - [10/Oct/2000:13:55:00 -0700] "GET /login HTTP/1.1" 401 0 "-" "curl/8.0"',
        '1.1.1.1 - - [10/Oct/2000:13:55:10 -0700] "GET /login HTTP/1.1" 401 0 "-" "curl/8.0"',
        '2.2.2.2 - - [10/Oct/2000:13:55:20 -0700] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
        '3.3.3.3 - - [10/Oct/2000:13:55:30 -0700] "GET /p.php?id=1\' OR 1=1 -- HTTP/1.1" 200 0 "-" "sqlmap/1.7"',
    ]
    evs = [parse_line(l, "apache") for l in logs]
    engine = RuleEngine(
        brute_force_threshold=2, brute_force_window_sec=60, burst_5xx_threshold=999
    )
    alerts = engine.run([e for e in evs if e])
    types = sorted(set(a.type for a in alerts))
    assert "Brute Force" in types
    assert "Directory Traversal" in types
    assert "SQL Injection" in types
