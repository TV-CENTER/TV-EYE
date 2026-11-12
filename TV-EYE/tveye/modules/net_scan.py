"""Network scanning modules for TV-EYE: TCP ports, service banners, host discovery."""

import socket
import struct
import threading
import time

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class PortScannerModule(BaseModule):
    NAME = "port_scan"
    DESCRIPTION = ("Fast async TCP port scan with service banner grabbing "
                   "(top ports or custom range)")
    CATEGORY = "network"
    REQUIRED = ["target"]

    TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000,
                 3306, 3389, 4444, 5000, 5432, 5555, 5601, 5900, 6379, 6443,
                 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
                 10000, 27017, 28017, 50050]

    def options(self):
        return {
            "target": "host or IP to scan",
            "ports": "comma separated ports or range like 1-1024 (default top 50)",
            "banner": "1 to grab service banners (default 1)",
        }

    def run(self):
        host = self._host()
        ports = self._ports()
        self.info("TCP scanning %s -> %d ports, %d threads" % (
            C.c(host, C.BOLD), len(ports), self.ctx.threads))
        open_ports = []
        lock = threading.Lock()

        def probe(port):
            try:
                with socket.create_connection((host, port), timeout=self.ctx.timeout):
                    with lock:
                        open_ports.append(port)
                return port
            except Exception:
                return None

        t0 = time.time()
        U.worker_pool(ports, probe, threads=self.ctx.threads)
        self.success("scan done in %.1fs - %d open ports" % (time.time() - t0, len(open_ports)))
        rows = []
        grab = str(self.ctx.get_option("banner", "1")) == "1"
        for port in sorted(open_ports):
            svc = self._svc_name(port)
            banner_txt = ""
            if grab:
                banner_txt = self._grab(host, port)
            rows.append((port, svc, banner_txt[:60]))
            print("   %-6s %-14s %s" % (
                C.c(str(port), C.BRIGHT_GREEN, C.BOLD), svc, banner_txt[:48]))
            if port in (6379, 27017, 9200, 3306, 5432, 2375, 5601) :
                self.add_finding(
                    "Database/admin service exposed to the network: %s:%d" % (host, port),
                    "medium", "%s:%d" % (host, port),
                    "Port %d (%s) reachable%s" % (port, svc,
                                                  (" - banner: " + banner_txt[:80]) if banner_txt else ""),
                    tip="Confirm exposure from outside your perimeter; unauth databases are critical.",
                    cwe="CWE-200")
            if banner_txt and re_search_version(banner_txt):
                self.add_finding(
                    "Version banner disclosed on %s:%d" % (host, port), "info",
                    "%s:%d" % (host, port), banner_txt[:120],
                    tip="Limit banner disclosure.", cwe="CWE-200")
        self.output({"host": host, "open": rows})
        return "port scan finished (%d open)" % len(open_ports)

    def _host(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        _s, h, _p, _b = U.normalize_target(t)
        return h

    def _ports(self):
        raw = self.ctx.get_option("ports", "") or ""
        if not raw:
            return list(self.TOP_PORTS)
        out = []
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    out.extend(range(int(a), int(b) + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                out.append(int(part))
        return sorted(set(p for p in out if 1 <= p <= 65535))

    def _svc_name(self, port):
        names = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                 80: "http", 110: "pop3", 139: "netbios", 143: "imap",
                 443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
                 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
                 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
                 9200: "elasticsearch", 5601: "kibana", 2375: "docker",
                 6443: "k8s-api", 5900: "vnc", 4444: "metasploit?"}
        return names.get(port, "unknown")

    def _grab(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=self.ctx.timeout) as s:
                s.settimeout(2.5)
                if port in (80, 8080, 8000, 5000, 8888, 3000, 9090, 8008, 8081):
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode())
                try:
                    data = s.recv(256)
                    return data.decode("utf-8", "replace").replace("\r\n", " | ").strip()
                except socket.timeout:
                    return ""
        except Exception:
            return ""


def re_search_version(text):
    import re as _re
    return _re.search(r"\d+\.\d+", text)


class HostDiscoveryModule(BaseModule):
    NAME = "host_discovery"
    DESCRIPTION = ("Live host discovery in a small CIDR via TCP ping "
                   "(80/443/22/445) - firewall friendly")
    CATEGORY = "network"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "CIDR like 192.168.1.0/28 (max 256 hosts)",
                "ports": "TCP ping ports (default 80,443,22,445)"}

    def run(self):
        import ipaddress as ipmod
        raw = self.ctx.get_option("target")
        if "/" not in raw:
            raise ModuleError("provide a CIDR range, e.g. 10.0.0.0/28")
        try:
            net = ipmod.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ModuleError("bad CIDR: %s" % exc)
        if net.num_addresses > 256:
            raise ModuleError("range too large (max 256 addresses)")
        ports = [int(p) for p in (self.ctx.get_option("ports", "80,443,22,445")
                                  or "80,443,22,445").split(",")]
        hosts = [str(h) for h in net.hosts()]
        self.info("TCP-pinging %d hosts on ports %s" % (len(hosts), ports))
        live = []

        def job(h):
            for p in ports:
                try:
                    with socket.create_connection((h, p), timeout=min(2.0, self.ctx.timeout)):
                        return (h, p)
                except Exception:
                    continue
            return None

        results = U.worker_pool(hosts, job, threads=self.ctx.threads)
        for h, p in [r for r in results if r]:
            live.append((h, p))
            self.success("%s alive (TCP %d open)" % (h, p))
        self.output({"cidr": raw, "live": live})
        self.success("host_discovery: %d live hosts" % len(live))
        return "host discovery finished (%d live)" % len(live)
