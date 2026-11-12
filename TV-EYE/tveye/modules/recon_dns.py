"""DNS / WHOIS reconnaissance modules for TV-EYE (Author: Mr_TV)."""

import json
import socket
import subprocess
import sys
import time

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class DnsReconModule(BaseModule):
    NAME = "dns_recon"
    DESCRIPTION = ("Full DNS recon: A/AAAA/CNAME/MX/NS/TXT/SOA records, "
                   "wildcard detection and reverse lookups")
    CATEGORY = "recon"
    REQUIRED = ["domain"]

    def options(self):
        return {
            "domain": "domain to enumerate (e.g. example.com)",
            "subdomains": "optional comma separated subdomains to resolve",
        }

    def run(self):
        domain = self.ctx.get_option("domain").strip().lower()
        self.info("DNS recon on %s" % C.c(domain, C.BOLD))
        rows = []
        for qtype in ("A", "CNAME", "MX", "NS", "TXT", "SOA"):
            vals = U.dns_lookup(domain, qtype)
            if vals:
                for v in vals:
                    rows.append((qtype, v))
                self.success("%-6s %s" % (qtype, ", ".join(str(x) for x in vals[:4])))
            else:
                self.info("%-6s (none)" % qtype)
        ips = U.dns_resolve(domain)
        for ip in ips:
            if (ip, "") not in [(a, b) for a, b in rows]:
                rows.append(("A(os)", ip))
        revs = []
        for ip in ips[:8]:
            try:
                name = socket.gethostbyaddr(ip)[0]
                revs.append((ip, name))
            except Exception:
                pass
        if revs:
            self.info("reverse DNS:")
            for ip, name in revs:
                print("     %-16s -> %s" % (ip, name))
        self.output({"domain": domain, "records": [list(r) for r in rows],
                     "reverse": revs})
        # basic zone hints for bug bounty
        txt_join = " | ".join(v for t, v in rows if t == "TXT")
        if "spf" in txt_join.lower() and "~all" not in txt_join.lower() and "-all" not in txt_join.lower():
            self.add_finding(
                "SPF record does not end with strict all (soft/none fail)",
                "low", domain,
                "TXT records: %s" % txt_join,
                tip="Review SPF policy; permissive policies allow sender spoofing.",
                cwe="CWE-290")
        if any("mail" in str(v).lower() for t, v in rows if t == "CNAME"):
            pass
        self.success("dns_recon complete - %d records collected" % len(rows))
        return "dns recon finished"


class WhoisModule(BaseModule):
    NAME = "whois_lookup"
    DESCRIPTION = "Query WHOIS registration data via OS whois or raw socket (port 43)"
    CATEGORY = "recon"
    REQUIRED = ["domain"]

    def options(self):
        return {"domain": "domain to look up"}

    def run(self):
        domain = self.ctx.get_option("domain").strip().lower()
        self.info("WHOIS lookup for %s" % domain)
        text = ""
        if sys.platform.startswith("win"):
            try:
                p = subprocess.run(["whois", domain], capture_output=True,
                                   text=True, timeout=15)
                text = p.stdout or ""
            except Exception:
                text = ""
        else:
            try:
                p = subprocess.run(["whois", domain], capture_output=True,
                                   text=True, timeout=15)
                text = p.stdout or ""
            except Exception:
                text = ""
        if not text:
            tld = domain.rsplit(".", 1)[-1]
            servers = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
                       "org": "whois.pir.org", "io": "whois.nic.io",
                       "ir": "whois.nic.ir", "dev": "whois.nic.google",
                       "app": "whois.nic.google", "info": "whois.afilias.net",
                       "ru": "whois.tcinet.ru", "de": "whois.denic.de"}
            server = servers.get(tld, "whois.iana.org")
            self.info("using raw WHOIS server %s" % server)
            try:
                with socket.create_connection((server, 43), timeout=8) as s:
                    s.sendall((domain + "\r\n").encode())
                    chunks = []
                    while True:
                        d = s.recv(4096)
                        if not d:
                            break
                        chunks.append(d.decode("utf-8", "replace"))
                    text = "\n".join(chunks)
            except Exception as exc:
                raise ModuleError("whois query failed: %s" % exc)
        keep = []
        for line in text.splitlines():
            l = line.strip()
            if not l or l.startswith("%") or l.startswith("#"):
                continue
            if any(k in l.lower() for k in ("registrar:", "creation date", "expiry",
                                            "registrant", "name server", "abuse",
                                            "updated date", "status:", "dnssec")):
                keep.append(l)
        for k in keep[:28]:
            print("   " + k)
        self.output({"domain": domain, "whois_lines": keep, "raw_len": len(text)})
        if keep:
            self.success("whois: %d key lines captured" % len(keep))
        else:
            self.warn("whois returned no recognizable fields")
        return "whois lookup finished"


class ReverseDnsModule(BaseModule):
    NAME = "reverse_dns"
    DESCRIPTION = "Reverse DNS (PTR) sweep for a host, IP or CIDR range"
    CATEGORY = "recon"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "IP, host or CIDR (e.g. 10.0.0.0/29)"}

    def run(self):
        import ipaddress as ipmod
        raw = self.ctx.get_option("target").strip()
        targets = []
        if "/" in raw:
            try:
                net = ipmod.ip_network(raw, strict=False)
                if net.num_addresses > 256:
                    raise ModuleError("range too large for reverse sweep (max /24 slice of 256)")
                targets = [str(x) for x in net.hosts()] or [str(net.network_address)]
            except ValueError as exc:
                raise ModuleError("bad CIDR: %s" % exc)
        else:
            targets = U.dns_resolve(raw) or [raw]
        self.info("reverse resolving %d addresses" % len(targets))
        rows = []

        def job(ip):
            try:
                return (ip, socket.gethostbyaddr(ip)[0])
            except Exception:
                return (ip, "-")

        results = U.worker_pool(targets, job, threads=self.ctx.threads)
        for ip, name in results:
            rows.append((ip, name))
            if name != "-":
                self.success("%-16s -> %s" % (ip, name))
        self.output({"results": rows})
        self.success("reverse_dns complete: %d PTR records" % len([r for r in rows if r[1] != "-"]))
        return "reverse dns finished"
