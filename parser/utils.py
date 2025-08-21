import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

APACHE_COMBINED_REGEX = re.compile(
    r"(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+)\s(?P<url>\S+)(?:\sHTTP/(?P<httpver>[0-9.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

NGINX_COMBINED_REGEX = APACHE_COMBINED_REGEX

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


def parse_line(line: str, fmt: str = "auto") -> Optional[LogEvent]:
    regex = APACHE_COMBINED_REGEX if fmt in ("auto", "apache") else NGINX_COMBINED_REGEX
    m = regex.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = parse_apache_time(g["time"])
    except Exception:
        return None
    size = 0
    try:
        size = 0 if g["size"] == "-" else int(g["size"])
    except Exception:
        size = 0
    return LogEvent(
        ip=g["ip"],
        ts=ts,
        method=g.get("method", "-"),
        url=g.get("url", "-"),
        status=int(g.get("status", 0)),
        size=size,
        referrer=g.get("referrer", ""),
        user_agent=g.get("user_agent", ""),
        raw=line.rstrip("\n"),
        extra={"httpver": g.get("httpver") or ""},
    )
