"""Utility helpers shared across TV-EYE modules (network, dns, parsing)."""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import colors as C


# ------------------------------------------------------------------ networking
def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def normalize_target(target):
    """Return (scheme, host, port, base_url) from user input."""
    target = str(target).strip().rstrip("/")
    if target.startswith("http://") or target.startswith("https://"):
        scheme = "https" if target.startswith("https") else "http"
        rest = target[len(scheme) + 3:]
    else:
        scheme = "https"
        rest = target
    host, port = rest, None
    if ":" in rest and not rest.count(":") > 1:
        host, _, p = rest.rpartition(":")
        try:
            port = int(p)
        except ValueError:
            host = rest
    base = "%s://%s" % (scheme, host)
    if port:
        base += ":%d" % port
    return scheme, host, port, base


def root_domain(host):
    """Cracks a host down to its registrable root (best effort, no PSL)."""
    host = host.strip().lower().rstrip(".")
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.ir", "ac.ir", "org.ir",
        "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "com.br",
        "com.tr", "co.nz", "co.za", "com.mx", "co.in", "com.cn", "com.ua",
        "com.sg", "com.my", "com.ar", "com.pk", "gov.in", "edu.au",
    }
    tail = ".".join(parts[-2:])
    if tail in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail


def dns_resolve(host):
    """Resolve A records using the OS resolver."""
    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for fam, _typ, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception:
        return []


def dns_lookup(host, qtype, timeout=4.0, server=None):
    """Manual DNS query (A/CNAME/MX/NS/TXT/SOA) without external libraries."""
    if qtype not in ("A", "CNAME", "MX", "NS", "TXT", "SOA"):
        raise ValueError("unsupported qtype")
    server = server or _first_resolver()
    if not server:
        return []
    tid = os.urandom(2)
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in host.split("."):
        if label:
            q += bytes([len(label)]) + label.encode("idna" if any(
                ord(cch) > 127 for cch in label) else "ascii", "ignore")
    q += b"\x00" + struct.pack(">HH", {"A": 1, "CNAME": 5, "MX": 15,
                                       "NS": 2, "TXT": 16, "SOA": 6}[qtype], 1)
    packet = header + tid + q
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _addr = sock.recvfrom(4096)
    except Exception:
        return []
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if len(data) < 12 or data[2:4] != tid:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    out = []
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        off += rdlen
        val = _decode_rr(qtype, rtype, rd, data)
        if val:
            out.append(val)
    return out


def _first_resolver():
    """Find the system DNS server (best effort on Windows/Linux/macOS)."""
    if sys.platform.startswith("win"):
        try:
            out = subprocess.run(
                ["nslookup", "localhost"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Address:") and "127.0.0.1" not in line:
                    ip = line.split(":", 1)[1].strip()
                    if ip.count(".") == 3:
                        return ip
        except Exception:
            pass
        return "8.8.8.8"
    try:
        with open("/etc/resolv.conf", "r") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except Exception:
        pass
    return "8.8.8.8"


def _skip_name(data, off):
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln
    return off


def _read_name(data, off):
    labels = []
    jumps = 0
    while off < len(data) and jumps < 8:
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            sub, _ = _read_name(data, ptr)
            labels.append(sub)
            off += 2
            break
        labels.append(data[off + 1:off + 1 + ln].decode("latin1", "replace"))
        off += 1 + ln
        jumps += 1
    return ".".join(l for l in labels if l), off


def _decode_rr(qtype, rtype, rd, msg):
    try:
        if qtype == "A" and rtype == 1 and len(rd) >= 4:
            return socket.inet_ntoa(rd[:4])
        if qtype in ("CNAME", "NS") and rtype in (5, 2):
            name, _ = _read_name(msg, msg.find(rd[:1]) if False else 0)
            # safer: parse rd directly
            labels = []
            off = 0
            while off < len(rd):
                ln = rd[off]
                if ln == 0:
                    break
                if ln & 0xC0 == 0xC0:
                    ptr = struct.unpack(">H", rd[off:off + 2])[0] & 0x3FFF
                    nm, _ = _read_name(msg, ptr)
                    labels.append(nm)
                    break
                labels.append(rd[off + 1:off + 1 + ln].decode("latin1", "replace"))
                off += 1 + ln
            name = ".".join(labels)
            return name if name else None
        if qtype == "MX" and rtype == 15 and len(rd) >= 3:
            pref = struct.unpack(">H", rd[:2])[0]
            labels = []
            off = 2
            while off < len(rd):
                ln = rd[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 == 0xC0:
                    ptr = struct.unpack(">H", rd[off:off + 2])[0] & 0x3FFF
                    nm, _ = _read_name(msg, ptr)
                    labels.append(nm)
                    off += 2
                    break
                labels.append(rd[off + 1:off + 1 + ln].decode("latin1", "replace"))
                off += 1 + ln
            ex = ".".join(labels)
            return "%d %s" % (pref, ex) if ex else None
        if qtype == "TXT" and rtype == 16:
            texts = []
            off = 0
            while off < len(rd):
                ln = rd[off]
                off += 1
                texts.append(rd[off:off + ln].decode("utf-8", "replace"))
                off += ln
            return "".join(texts)
        if qtype == "SOA" and rtype == 6:
            return "SOA record present"
    except Exception:
        return None
    return None


class HTTPResult(object):
    __slots__ = ("status", "headers", "body", "url", "elapsed", "ok", "error")

    def __init__(self):
        self.status = 0
        self.headers = {}
        self.body = ""
        self.url = ""
        self.elapsed = 0.0
        self.ok = False
        self.error = None

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


def http_request(url, method="GET", data=None, headers=None, timeout=10.0,
                 proxy=None, user_agent="TV-EYE/1.0 (Mr_TV)", cookie=None,
                 verify=True, retries=1, delay=0.0):
    """stdlib-only HTTP client (urllib) with proxy + TLS-verify control."""
    result = HTTPResult()
    result.url = url
    attempts = max(1, retries + 1)
    hdrs = {"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"}
    if cookie:
        hdrs["Cookie"] = cookie
    if headers:
        hdrs.update(headers)
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8", "replace")
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({
            "http": proxy if "://" in proxy else "http://" + proxy,
            "https": proxy if "://" in proxy else "http://" + proxy,
        }))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(*handlers, **({"context": ctx} if False else {}))
    # attach SSL context properly
    if ctx is not None:
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener.add_handler(https_handler)
    last_err = None
    for attempt in range(attempts):
        if delay:
            time.sleep(delay)
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            started = time.time()
            with opener.open(req, timeout=timeout) as resp:
                result.status = resp.getcode()
                raw = resp.read(2 * 1024 * 1024)
                result.body = raw.decode("utf-8", "replace")
                result.headers = dict(resp.headers.items())
                result.elapsed = time.time() - started
                result.ok = True
                return result
        except urllib.error.HTTPError as exc:
            result.status = exc.code
            try:
                raw = exc.read(2 * 1024 * 1024)
                result.body = raw.decode("utf-8", "replace")
            except Exception:
                result.body = ""
            result.headers = dict(exc.headers.items()) if exc.headers else {}
            result.ok = True  # got an HTTP response
            result.error = str(exc)
            return result
        except Exception as exc:
            last_err = exc
            if attempt + 1 < attempts:
                time.sleep(0.4 * (attempt + 1))
    result.error = str(last_err)
    return result


def worker_pool(items, fn, threads=10):
    """Tiny thread pool preserving result order. Returns list of results."""
    results = [None] * len(items)
    lock = threading.Lock()
    idx = {"n": 0}

    def runner():
        while True:
            with lock:
                if idx["n"] >= len(items):
                    return
                i = idx["n"]
                idx["n"] += 1
            try:
                results[i] = fn(items[i])
            except Exception as exc:
                results[i] = {"error": str(exc)}

    ths = []
    real = max(1, min(threads, len(items) or 1))
    for _ in range(real):
        t = threading.Thread(target=runner)
        t.daemon = True
        t.start()
        ths.append(t)
    for t in ths:
        t.join()
    return results


def random_string(n=8, chars=string.ascii_lowercase):
    return "".join(random.choice(chars) for _ in range(n))


# ------------------------------------------------------------------- payloads
def b64e(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "replace")
    return base64.b64encode(s).decode("ascii", "replace")


def b64d(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def md5(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "replace")
    return hashlib.md5(s).hexdigest()


def sha1(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "replace")
    return hashlib.sha1(s).hexdigest()


def sha256(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "replace")
    return hashlib.sha256(s).hexdigest()


def hmac_sha256(key, msg):
    if isinstance(key, str):
        key = key.encode("utf-8", "replace")
    if isinstance(msg, str):
        msg = msg.encode("utf-8", "replace")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def url_encode(s):
    return urllib.parse.quote(str(s), safe="")


def url_decode(s):
    return urllib.parse.unquote(str(s))


def parse_url_params(url):
    q = urllib.parse.urlsplit(url).query
    return urllib.parse.parse_qsl(q, keep_blank_values=True)


def build_url(base, path):
    if not path:
        return base
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def extract_links(html, base=""):
    hrefs = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)["\']', html, re.I)
    out = []
    for h in hrefs:
        if h.startswith("javascript:") or h.startswith("data:") or h.startswith("mailto:"):
            continue
        if base and h.startswith("/"):
            h = base.rstrip("/") + h
        out.append(h)
    return out


def extract_emails(text):
    return sorted(set(re.findall(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]{2,}", text)))


def extract_ips(text):
    found = []
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        ip = m.group(0)
        try:
            ipaddress.ip_address(ip)
            found.append(ip)
        except ValueError:
            pass
    return sorted(set(found))


def extract_forms(html):
    """Very small form parser: returns list of dicts with action+inputs."""
    forms = []
    for fm in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
        tag = fm.group(0)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        inputs = []
        for im in re.finditer(r"<input\b[^>]*>", tag, re.I):
            itag = im.group(0)
            name = re.search(r'name\s*=\s*["\']([^"\']*)["\']', itag, re.I)
            typ = re.search(r'type\s*=\s*["\']([^"\']*)["\']', itag, re.I)
            inputs.append({"name": name.group(1) if name else "",
                           "type": (typ.group(1) if typ else "text").lower()})
        for im in re.finditer(r"<textarea\b[^>]*>", tag, re.I):
            itag = im.group(0)
            name = re.search(r'name\s*=\s*["\']([^"\']*)["\']', itag, re.I)
            inputs.append({"name": name.group(1) if name else "",
                           "type": "textarea"})
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "get").lower(),
            "inputs": inputs,
        })
    return forms


def strip_html(html):
    return re.sub(r"<[^>]+>", " ", html)


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PB" % n


def now_stamp():
    return datetime_now().strftime("%Y%m%d_%H%M%S")


def datetime_now():
    from datetime import datetime as _dt
    return _dt.now()


def read_wordlist(path, max_lines=200000):
    """Load a wordlist file, tolerating missing files by returning []."""
    if not path or not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                w = line.strip()
                if w and not w.startswith("#"):
                    out.append(w)
    except Exception:
        return []
    return out


def builtin_wordlist(name="small"):
    """Tiny built-in wordlists so the tool works with zero downloads."""
    dirs = ["admin", "backup", "backups", "bak", "bin", "cgi-bin", "config",
            "console", "dashboard", "db", "debug", "dev", "docs", "downloads",
            "env", ".env", "files", "ftp", "git", ".git", "home", "images",
            "img", "includes", "install", "installer", "js", "json", "log",
            "logs", "mail", "manager", "media", "new", "old", "panel", "php",
            "phpinfo", "phpmyadmin", "private", "robots.txt", "server-status",
            "settings", "shell", "sitemap.xml", "source", "sql", "src", "static",
            "stats", "status", "system", "temp", "test", "tmp", "tools",
            "uploads", "users", "web.config", "webmail", "wp-admin", "wp-content",
            "wp-login.php", "www", "xml", "api", "api/v1", "actuator", "actuator/health",
            "actuator/env", "swagger", "swagger-ui.html", "graphql", ".htaccess",
            ".htpasswd", "administrator", "login", "signin", "signup", "register",
            "wp-config.php.bak", "composer.json", "package.json", "yarn.lock",
            "id_rsa", ".DS_Store", "crossdomain.xml", "security.txt", ".well-known/security.txt"]
    users = ["admin", "administrator", "root", "test", "guest", "user", "demo",
             "backup", "info", "support", "sales", "dev", "deploy", "git", "oracle"]
    if name == "users":
        return users
    return dirs


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80]


def print_kv(items):
    for k, v in items:
        print("   %-22s %s" % (C.c(str(k) + ":", C.BRIGHT_CYAN), v))
