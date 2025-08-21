from datetime import datetime, timezone
from parser.utils import LogEvent, parse_apache_time, parse_line

import pytest


def test_parse_apache_time_with_timezone():
    """Test parsing Apache timestamp with timezone"""
    timestamp = "10/Oct/2000:13:55:36 -0700"
    result = parse_apache_time(timestamp)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_parse_apache_time_without_timezone():
    """Test parsing Apache timestamp without timezone"""
    timestamp = "10/Oct/2000:13:55:36"
    result = parse_apache_time(timestamp)
    assert isinstance(result, datetime)
    assert result.tzinfo == timezone.utc


def test_parse_apache_time_invalid():
    """Test parsing invalid timestamp"""
    timestamp = "invalid-timestamp"
    result = parse_apache_time(timestamp)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_parse_line_nginx():
    """Test parsing Nginx log line"""
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0" 0.123'
    ev = parse_line(line, "nginx")
    assert ev is not None
    assert ev.ip == "127.0.0.1"
    assert ev.method == "GET"
    assert ev.url == "/index.html"
    assert ev.status == 200
    assert ev.size == 2326
    assert "response_time" in ev.extra


def test_parse_line_malformed():
    """Test parsing malformed log line"""
    line = "malformed log line"
    ev = parse_line(line, "apache")
    assert ev is None


def test_parse_line_empty():
    """Test parsing empty line"""
    line = ""
    ev = parse_line(line, "apache")
    assert ev is None


def test_parse_line_with_dash_fields():
    """Test parsing line with dash fields"""
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 - "-" "-"'
    ev = parse_line(line, "apache")
    assert ev is not None
    assert ev.size == 0
    assert ev.referrer == ""
    assert ev.user_agent == ""


def test_parse_line_invalid_status():
    """Test parsing line with invalid status code"""
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 999 2326 "-" "Mozilla/5.0"'
    ev = parse_line(line, "apache")
    assert ev is not None
    assert ev.status == 0  # Should be reset to 0 for invalid status


def test_parse_line_invalid_size():
    """Test parsing line with invalid size"""
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 invalid "-" "Mozilla/5.0"'
    ev = parse_line(line, "apache")
    assert ev is not None
    assert ev.size == 0  # Should be reset to 0 for invalid size
