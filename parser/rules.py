import re
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
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
    Enhanced RuleEngine with comprehensive attack detection
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
        port_scan_threshold: int = 15,
        port_scan_window_sec: int = 300,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = timedelta(seconds=brute_force_window_sec)
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = timedelta(seconds=port_scan_window_sec)
        
        # Enhanced SQL Injection detection
        self.sqli_regex = sqli_regex or re.compile(
            r"('|\"|%27|%22|union|select|insert|update|delete|drop|create|alter|exec|execute"
            r"|\bor\s+\d+\s*=\s*\d+\b|\band\s+\d+\s*=\s*\d+\b|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b"
            r"|--|#|/\*|\*/|;.*(select|union|drop|insert|delete)"
            r"|information_schema|sys\.tables|sys\.columns|@@version|@@hostname|@@datadir"
            r"|substring|concat|char|ascii|hex|unhex|load_file|into\s+outfile|into\s+dumpfile"
            r"|benchmark|sleep|waitfor|delay|pg_sleep|dbms_pipe\.receive_message)",
            re.I,
        )
        
        # Enhanced Directory Traversal detection
        self.traversal_regex = traversal_regex or re.compile(
            r"(\.\./|%2e%2e/|%2e%2e%5c|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c"
            r"|\.\.%252f|\.\.%255c|%252e%252e%252f|%255c%255c%255c"
            r"|\.\.%c0%af|\.\.%c1%9c|\.\.%c0%9v|\.\.%c0%qf)",
            re.I,
        )
        
        # Enhanced Command Injection detection
        self.cmd_injection_regex = re.compile(
            r"(&&|\|\||;|%3b|`|%60|\$\(|\$\{|"
            r"(cmd=|exec=|system=|eval=).*(\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|"
            r"telnet|ssh|ftp|chmod|chown|rm|mv|cp|mkdir|rmdir|touch|find|grep|awk|sed|sort|uniq|head|tail|wc|"
            r"which|locate|crontab|su|sudo|mount|umount|df|du|free|top|kill|killall|nohup|jobs|bg|fg|history|"
            r"alias|unalias|export|env|set|unset|echo|printf|read|test|true|false|exit|return|break|continue|"
            r"while|for|if|then|else|elif|fi|do|done|case|esac|function|local|declare|readonly|shift|trap|wait|"
            r"sleep|basename|dirname|realpath|readlink|nslookup|dig|host|traceroute|route|iptables|firewall|"
            r"systemctl|service|init\.d|rc\.d|chroot|jail|docker|kubectl|helm|oc|openshift)\b))",
            re.I,
        )
        
        # Enhanced XSS detection
        self.xss_regex = re.compile(
            r"(<script>|%3cscript%3e|<\/script>|%3c\/script%3e|onerror|onload|onmouseover|onclick|onfocus|onblur|"
            r"javascript:|vbscript:|data:text/html|data:application/x-javascript|"
            r"<iframe|<\/iframe|%3ciframe|%3c\/iframe|"
            r"<img|<\/img|%3cimg|%3c\/img|"
            r"<svg|<\/svg|%3csvg|%3c\/svg|"
            r"<object|<\/object|%3cobject|%3c\/object|"
            r"<embed|<\/embed|%3cembed|%3c\/embed|"
            r"eval\(|setTimeout\(|setInterval\(|Function\(|"
            r"document\.|window\.|location\.|history\.|navigator\.|screen\.|"
            r"alert\(|confirm\(|prompt\(|console\.|"
            r"fetch\(|XMLHttpRequest|axios|jquery|"
            r"String\.fromCharCode|unescape|decodeURI|decodeURIComponent)",
            re.I,
        )
        
        # File Inclusion detection (LFI/RFI)
        self.file_inclusion_regex = re.compile(
            r"(include|require|include_once|require_once|file_get_contents|file_put_contents|fopen|fread|fwrite|"
            r"readfile|file|load|view|page|template|template_path|include_path|"
            r"\.\./|\.\.\\|%2e%2e|%2e%2e%5c|%2e%2e%2f|"
            r"etc/passwd|etc/shadow|etc/hosts|proc/version|proc/cpuinfo|proc/meminfo|"
            r"var/log|var/www|var/lib|var/spool|var/mail|"
            r"windows/win\.ini|windows/system32|windows/system|"
            r"c:\\windows|c:\\system32|c:\\temp|c:\\tmp|"
            r"http://|https://|ftp://|file://|php://|data://|expect://|input://|"
            r"php://filter|php://input|data:text/plain|data:application/x-php)",
            re.I,
        )
        
        # Enhanced Suspicious User-Agent detection
        self.suspicious_ua_regex = suspicious_ua_regex or re.compile(
            r"(curl|python-requests|sqlmap|nmap|masscan|hydra|gobuster|dirb|feroxbuster|nikto|wfuzz|"
            r"burpsuite|w3af|zap|acunetix|nessus|openvas|qualys|rapid7|"
            r"scanner|spider|crawler|bot|scraper|harvester|"
            r"sqlmap|sqlninja|havij|pangolin|bsqlbf|"
            r"nmap|zenmap|masscan|unicornscan|angryip|"
            r"hydra|medusa|patator|ncrack|thc-hydra|"
            r"gobuster|dirb|dirbuster|feroxbuster|wfuzz|"
            r"nikto|skipfish|w3af|zap|burp|"
            r"metasploit|msfconsole|msfvenom|"
            r"john|hashcat|ophcrack|rainbowcrack|"
            r"aircrack|kismet|wireshark|tcpdump|"
            r"nslookup|dig|whois|traceroute|ping|telnet|nc|netcat)",
            re.I,
        )
        
        # Bot detection
        self.bot_regex = re.compile(
            r"(googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|"
            r"facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|"
            r"discord|slack|microsoftbot|applebot|ahrefsbot|semrushbot|"
            r"mj12bot|dotbot|rogerbot|exabot|ia_archiver|archive\.org|"
            r"wget|curl|python|perl|ruby|java|php|node|"
            r"bot|crawler|spider|scraper|harvester)",
            re.I,
        )
        
        # Log4Shell detection
        self.log4shell_regex = re.compile(r"\$\{jndi:", re.I)
        
        # Port scanning detection patterns
        self.port_scan_paths = {
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico",
            "/humans.txt", "/crossdomain.xml", "/clientaccesspolicy.xml", "/.env",
            "/config.php", "/wp-config.php", "/config.json", "/.git/config",
            "/.svn/entries", "/.htaccess", "/web.config", "/phpinfo.php",
            "/test.php", "/info.php", "/admin", "/administrator", "/login",
            "/wp-admin", "/wp-login.php", "/admin.php", "/admin.html"
        }
        
        # DDoS/Flood detection
        self.ddos_threshold = 100
        self.ddos_window = timedelta(seconds=60)
        
        # State tracking
        self._alerts: List[Alert] = []
        self._fail_window: Dict[str, deque] = defaultdict(deque)
        self._server_error_window: deque = deque()
        self._request_window: Dict[str, deque] = defaultdict(deque)
        self._port_scan_window: Dict[str, deque] = defaultdict(deque)
        self._ddos_window: deque = deque()
        
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

    def _normalize(self, text: str) -> str:
        """Decode URL-encoded chars and unescape quotes for reliable matching."""
        if not text:
            return ""
        decoded = urllib.parse.unquote(text)
        # unescape common encodings
        return decoded.replace("\\'", "'").replace('\\"', '"').lower()

    def _is_port_scan_path(self, path: str) -> bool:
        """Check if path is commonly scanned during reconnaissance"""
        normalized_path = path.lower().split('?')[0]  # Remove query params
        return normalized_path in self.port_scan_paths

    def feed(self, event: LogEvent):
        # Rule 1: Brute force via HTTP 401 in window
        if event.status == 401:
            dq = self._fail_window[event.ip]
            dq.append(event.ts)
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

        # Rule 3: SQL injection (check raw + normalized URL)
        url_norm = self._normalize(event.url)
        if self.sqli_regex.search(event.url) or self.sqli_regex.search(url_norm):
            self._emit(event, "SQL Injection", "high", url=event.url)

        # Rule 4: XSS
        if self.xss_regex.search(event.url) or self.xss_regex.search(url_norm):
            self._emit(event, "Cross-Site Scripting (XSS)", "medium", url=event.url)

        # Rule 5: Command injection
        if self.cmd_injection_regex.search(event.url) or self.cmd_injection_regex.search(url_norm):
            self._emit(event, "Command Injection", "high", url=event.url)

        # Rule 6: File Inclusion (LFI/RFI)
        if self.file_inclusion_regex.search(event.url) or self.file_inclusion_regex.search(url_norm):
            self._emit(event, "File Inclusion", "high", url=event.url)

        # Rule 7: Log4Shell
        if (self.log4shell_regex.search(event.url) or 
            self.log4shell_regex.search(url_norm) or 
            self.log4shell_regex.search(event.user_agent)):
            self._emit(event, "Log4Shell Attempt", "high", url=event.url)

        # Rule 8: Suspicious user agent
        if self.suspicious_ua_regex.search(event.user_agent):
            self._emit(
                event,
                "Suspicious User-Agent",
                "low",
                user_agent=event.user_agent,
                url=event.url,
            )

        # Rule 9: Bot detection
        if self.bot_regex.search(event.user_agent):
            self._emit(
                event,
                "Bot Traffic",
                "low",
                user_agent=event.user_agent,
                url=event.url,
            )

        # Rule 10: Port scanning detection
        if self._is_port_scan_path(event.url):
            dq = self._port_scan_window[event.ip]
            dq.append(event)  # Store the full event object
            while dq and (event.ts - dq[0].ts) > self.port_scan_window:
                dq.popleft()
            if len(dq) >= self.port_scan_threshold:
                self._emit(
                    event,
                    "Port Scanning",
                    "medium",
                    count=len(dq),
                    window_sec=int(self.port_scan_window.total_seconds()),
                    scanned_paths=list(set([e.url.split('?')[0] for e in dq])),
                )

        # Rule 11: DDoS/Flood detection
        self._ddos_window.append(event.ts)
        while self._ddos_window and (event.ts - self._ddos_window[0]) > self.ddos_window:
            self._ddos_window.popleft()
        if len(self._ddos_window) >= self.ddos_threshold:
            self._emit(
                event,
                "DDoS/Flood Attack",
                "high",
                count=len(self._ddos_window),
                window_sec=int(self.ddos_window.total_seconds()),
            )

        # Rule 12: 5xx burst
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

        # Rule 13: Unusual HTTP methods
        unusual_methods = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"}
        if event.method in unusual_methods:
            self._emit(
                event,
                "Unusual HTTP Method",
                "low",
                method=event.method,
                url=event.url,
            )

        # Rule 14: Large request size (potential file upload attack)
        if event.size > 10000000:  # 10MB
            self._emit(
                event,
                "Large Request",
                "medium",
                size_bytes=event.size,
                url=event.url,
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
