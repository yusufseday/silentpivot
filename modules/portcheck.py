"""Native TCP port check — a fast open/closed test that works even without nmap.
Pure Python socket + thread pool; only attempts a TCP connect to the target."""
import socket
import concurrent.futures

# Common service ports (default for a quick scan)
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


class PortChecker:
    def __init__(self, timeout=1.0, max_workers=100):
        self.timeout = timeout
        self.max_workers = max_workers

    def _check(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                is_open = s.connect_ex((host, port)) == 0
        except OSError:
            is_open = False
        return port, is_open

    def scan(self, host, ports=None, only_open=True):
        """Check ports on host in parallel. Returns a structured list."""
        try:
            host = socket.gethostbyname(host)
        except socket.gaierror:
            return None  # target could not be resolved

        ports = list(ports) if ports else list(COMMON_PORTS.keys())
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = [ex.submit(self._check, host, p) for p in ports]
            for f in concurrent.futures.as_completed(futures):
                port, is_open = f.result()
                if is_open or not only_open:
                    results.append({
                        "port": port,
                        "state": "open" if is_open else "closed",
                        "service": COMMON_PORTS.get(port, "unknown"),
                    })
        return sorted(results, key=lambda r: r["port"])

    @staticmethod
    def parse_ports(spec):
        """'22,80,443' or '1-1024' or 'top' -> list of ports."""
        spec = (spec or "").strip().lower()
        if not spec or spec == "top":
            return None  # None -> COMMON_PORTS is used
        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            elif part.isdigit():
                ports.add(int(part))
        return sorted(p for p in ports if 0 < p <= 65535)
