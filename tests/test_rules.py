from parser.rules import RuleEngine
from parser.utils import LogEvent
from datetime import datetime, timezone


def ev(ip="1.1.1.1", url="/", status=200, ua="Mozilla/5.0"):
    return LogEvent(
        ip=ip,
        ts=datetime.now(timezone.utc),
        method="GET",
        url=url,
        status=status,
        size=0,
        referrer="-",
        user_agent=ua,
        raw="",
        extra={},
    )


def test_suspicious_ua():
    e = ev(ua="curl/8.0")
    eng = RuleEngine()
    eng.feed(e)
    out = eng.pop_alerts()
    assert any(a.type == "Suspicious User-Agent" for a in out)
