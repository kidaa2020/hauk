"""
Port scanner using sockets (no nmap dependency)
"""
import socket
import concurrent.futures
from modules.utils import color, Colors

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5672: "RabbitMQ", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB", 5000: "Flask/Dev",
    4848: "GlassFish", 7001: "WebLogic", 8161: "ActiveMQ",
}

class PortScanner:
    def __init__(self, targets, ports="21,22,80,443,3306,3389,8080", threads=100, timeout=3):
        self.targets = targets
        self.timeout = timeout
        self.threads = threads
        self.ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]

    def run(self):
        results = {}
        tasks = [(host, port) for host in self.targets for port in self.ports]

        def check(task):
            host, port = task
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                res = sock.connect_ex((host, port))
                if res == 0:
                    banner = self._grab_banner(sock, port)
                    sock.close()
                    return host, port, banner
                sock.close()
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for result in ex.map(check, tasks):
                if result:
                    host, port, banner = result
                    if host not in results:
                        results[host] = []
                    service = SERVICE_BANNERS.get(port, "Unknown")
                    entry = {"port": port, "service": service, "banner": banner}
                    results[host].append(entry)
                    print(color(f"  [OPEN] {host}:{port} ({service}) {banner[:60] if banner else ''}", Colors.GREEN))

        return results

    def _grab_banner(self, sock, port):
        try:
            if port in (80, 8080, 8443, 443):
                return ""
            sock.settimeout(2)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            return banner
        except Exception:
            return ""
