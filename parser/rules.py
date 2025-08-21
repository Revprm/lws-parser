import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

from .utils import LogEvent


@dataclass
class Alert:
    type: str
    severity: str
    ts: str
    ip: str
    details: Dict[str, str]


class RuleEngine:
    """
    Stateless + stateful rules. Call feed(event) per log event.
    Retrieve alerts via pop_alerts() or iterate.
    """

    def __init__(
        self,
        brute_force_threshold: int = 10,
        brute_force_window_sec: int = 60,
        sqli_regex: Optional[re.Pattern] = None,
        traversal_regex: Optional[re.Pattern] = None,
        suspicious_ua_regex: Optional[re.Pattern] = None,
        burst_5xx_threshold: int = 30,
        burst_5xx_window_sec: int = 60,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = timedelta(seconds=brute_force_window_sec)
        self.sqli_regex = sqli_regex or re.compile(
            r"(\\'|\\\"|\\'|\"|%27|%22|union|select|insert|update|delete|drop|create|alter|exec|execute|\bor\s+\d+\s*=\s*\d+|\band\s+\d+\s*=\s*\d+|\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1|--|#|\/\*|\*\/)",
            re.I,
        )
        self.traversal_regex = traversal_regex or re.compile(
            r"(\.\./|%2e%2e/|%2e%2e%5c)", re.I
        )
        # Updated command injection regex to catch more patterns
        self.cmd_injection_regex = re.compile(
            r"(&&|\|\||;|%3b|`|%60|\$\(|\$\{|(\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|chmod|chown|rm|mv|cp|mkdir|rmdir|touch|find|grep|awk|sed|sort|uniq|head|tail|wc|which|locate|crontab|su|sudo|passwd|mount|umount|df|du|free|top|kill|killall|nohup|jobs|bg|fg|history|alias|unalias|export|env|set|unset|echo|printf|read|test|true|false|exit|return|break|continue|while|for|if|then|else|elif|fi|do|done|case|esac|function|local|declare|readonly|shift|eval|exec|trap|wait|sleep|basename|dirname|realpath|readlink)\b))",
            re.I,
        )
        self.suspicious_ua_regex = suspicious_ua_regex or re.compile(
            r"(curl|python-requests|sqlmap|nmap|masscan|hydra|gobuster|dirb|feroxbuster|nikto|wfuzz)",
            re.I,
        )
        self.xss_regex = re.compile(
            r"(<script>|%3cscript%3e|<\/script>|%3c\/script%3e|onerror|onload|onmouseover|javascript:)",
            re.I,
        )
        self.log4shell_regex = re.compile(r"\$\{jndi:", re.I)
        self._alerts: List[Alert] = []
        self._fail_window: Dict[str, deque] = defaultdict(deque)
        self._server_error_window: deque = deque()
        self.burst_5xx_threshold = burst_5xx_threshold
        self.burst_5xx_window = timedelta(seconds=burst_5xx_window_sec)

    def _emit(self, event: LogEvent, typ: str, severity: str, **details):
        self._alerts.append(
            Alert(
                type=typ,
                severity=severity,
                ts=event.ts.isoformat(),
                ip=event.ip,
                details={k: str(v) for k, v in details.items()},
            )
        )

    def feed(self, event: LogEvent):
        # Rule 1: Brute force via HTTP 401 in window
        if event.status == 401:
            dq = self._fail_window[event.ip]
            dq.append(event.ts)
            # purge window
            while dq and (event.ts - dq[0]) > self.brute_force_window:
                dq.popleft()
            if len(dq) >= self.brute_force_threshold:
                self._emit(
                    event,
                    "Brute Force",
                    "high",
                    count=len(dq),
                    window_sec=int(self.brute_force_window.total_seconds()),
                    url=event.url,
                )

        # Rule 2: Directory traversal
        if self.traversal_regex.search(event.url):
            self._emit(event, "Directory Traversal", "medium", url=event.url)

        # Rule 3: SQL injection
        if self.sqli_regex.search(event.url):
            self._emit(event, "SQL Injection", "high", url=event.url)

        # Rule 3a: XSS
        if self.xss_regex.search(event.url):
            self._emit(event, "Cross-Site Scripting (XSS)", "medium", url=event.url)

        # Rule 3b: Command injection
        if self.cmd_injection_regex.search(event.url):
            self._emit(event, "Command Injection", "high", url=event.url)

        # Rule 3c: Log4Shell
        if self.log4shell_regex.search(event.url) or self.log4shell_regex.search(
            event.user_agent
        ):
            self._emit(event, "Log4Shell Attempt", "high", url=event.url)

        # Rule 4: Suspicious user agent
        if self.suspicious_ua_regex.search(event.user_agent):
            self._emit(
                event,
                "Suspicious User-Agent",
                "low",
                user_agent=event.user_agent,
                url=event.url,
            )

        # Rule 5: 5xx burst (potential DoS / outage)
        if 500 <= event.status <= 599:
            self._server_error_window.append(event.ts)
            while (
                self._server_error_window
                and (event.ts - self._server_error_window[0]) > self.burst_5xx_window
            ):
                self._server_error_window.popleft()
            if len(self._server_error_window) >= self.burst_5xx_threshold:
                self._emit(
                    event,
                    "5xx Burst",
                    "medium",
                    count=len(self._server_error_window),
                    window_sec=int(self.burst_5xx_window.total_seconds()),
                )

    def pop_alerts(self) -> List[Alert]:
        out = self._alerts[:]
        self._alerts.clear()
        return out

    def run(self, events: Iterable[LogEvent]) -> List[Alert]:
        for ev in events:
            if ev:
                self.feed(ev)
        return self.pop_alerts()
