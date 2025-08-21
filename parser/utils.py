import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

APACHE_COMBINED_REGEX = re.compile(
    r"(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+)\s(?P<url>[^"]+?)(?:\sHTTP/(?P<httpver>[0-9.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

NGINX_COMBINED_REGEX = re.compile(
    r"(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+)\s(?P<url>[^"]+?)(?:\sHTTP/(?P<httpver>[0-9.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<response_time>\S+)'
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class LogEvent:
    ip: str
    ts: datetime
    method: str
    url: str
    status: int
    size: int
    referrer: str
    user_agent: str
    raw: str
    extra: Dict[str, str]


def parse_apache_time(s: str) -> datetime:
    """Parse Apache/Nginx timestamp with enhanced error handling"""
    # Strip any trailing whitespace
    s = s.strip()
    
    try:
        # Check if we have timezone information
        if len(s) >= 26 and (s[21] == '+' or s[21] == '-'):
            # Format: dd/MMM/yyyy:HH:mm:ss +zzzz
            day = int(s[0:2])
            mon = MONTHS[s[3:6]]
            year = int(s[7:11])
            hh = int(s[12:14])
            mm = int(s[15:17])
            ss = int(s[18:20])
            sign = 1 if s[21] == "+" else -1
            tzh = int(s[22:24])
            tzm = int(s[24:26])
            offset = sign * (tzh * 60 + tzm)
            return datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc).astimezone(
                timezone.utc
            )
        else:
            # Format: dd/MMM/yyyy:HH:mm:ss (no timezone)
            day = int(s[0:2])
            mon = MONTHS[s[3:6]]
            year = int(s[7:11])
            hh = int(s[12:14])
            mm = int(s[15:17])
            ss = int(s[18:20])
            # Assume UTC if no timezone provided
            return datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except (ValueError, KeyError, IndexError) as e:
        # If parsing fails, return current time as fallback
        return datetime.now(timezone.utc)


def parse_line(line: str, fmt: str = "auto") -> Optional[LogEvent]:
    """Parse a single log line with enhanced error handling"""
    if not line.strip():
        return None
        
    regex = APACHE_COMBINED_REGEX if fmt in ("auto", "apache") else NGINX_COMBINED_REGEX
    m = regex.match(line)
    if not m:
        return None
        
    g = m.groupdict()
    
    try:
        ts = parse_apache_time(g["time"])
    except Exception:
        return None
        
    # Handle size field with better error handling
    size = 0
    try:
        size_str = g.get("size", "0")
        if size_str == "-" or not size_str:
            size = 0
        else:
            size = int(size_str)
    except (ValueError, TypeError):
        size = 0
    
    # Handle status code with validation
    try:
        status = int(g.get("status", 0))
        if status < 100 or status > 599:
            status = 0
    except (ValueError, TypeError):
        status = 0
    
    # Handle extra fields for nginx
    extra = {"httpver": g.get("httpver") or ""}
    if fmt == "nginx" and "response_time" in g:
        extra["response_time"] = g["response_time"]
    
    # Clean and validate IP address
    ip = g.get("ip", "").strip()
    if not ip or ip == "-":
        ip = "0.0.0.0"
    
    # Clean and validate URL
    url = g.get("url", "").strip()
    if not url or url == "-":
        url = "/"
    
    # Clean user agent
    user_agent = g.get("user_agent", "").strip()
    if not user_agent or user_agent == "-":
        user_agent = ""
    
    # Clean referrer
    referrer = g.get("referrer", "").strip()
    if not referrer or referrer == "-":
        referrer = ""
    
    return LogEvent(
        ip=ip,
        ts=ts,
        method=g.get("method", "GET"),
        url=url,
        status=status,
        size=size,
        referrer=referrer,
        user_agent=user_agent,
        raw=line.rstrip("\n"),
        extra=extra,
    )
