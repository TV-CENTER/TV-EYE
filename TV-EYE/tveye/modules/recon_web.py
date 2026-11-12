"""Web fingerprinting: tech stack, WAF, CMS, security headers, TLS, CORS."""

import re
import ssl
import socket

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class TechFingerprintModule(BaseModule):
    NAME = "tech_fingerprint"
    DESCRIPTION = ("Identify server tech, frameworks, languages and version "
                   "disclosure from headers, HTML and cookie names")
    CATEGORY = "web"

    SIGS = [
        ("Apache", [("header", "server", re.compile(r"apache"))]),
        ("nginx", [("header", "server", re.compile(r"nginx"))]),
        ("IIS", [("header", "server", re.compile(r"iis|microsoft-iis"))]),
        ("LiteSpeed", [("header", "server", re.compile(r"litespeed"))]),
        ("PHP", [("header", "x-powered-by", re.compile(r"php")),
                 ("body", None, re.compile(r"\.php[\"'?]"))]),
        ("ASP.NET", [("header", "x-powered-by", re.compile(r"asp\.net")),
                     ("header", "x-aspnet-version", re.compile(r".")),
                     ("body", None, re.compile(r"__viewstate|\.aspx"))]),
        ("Express", [("header", "x-powered-by", re.compile(r"express"))]),
        ("Next.js", [("body", None, re.compile(r"__NEXT_DATA__|/_next/"))]),
        ("Nuxt", [("body", None, re.compile(r"__NUXT__"))]),
        ("React", [("body", None, re.compile(r"react(-dom)?[.@]|data-reactroot"))]),
        ("Angular", [("body", None, re.compile(r"ng-version|angular\.min\.js|ng-app"))]),
        ("Vue", [("body", None, re.compile(r"vue(\.min)?\.js|data-v-[0-9a-f]{8}"))]),
        ("jQuery", [("body", None, re.compile(r"jquery(-|\.)[0-9.]*(min)?\.js"))]),
        ("Bootstrap", [("body", None, re.compile(r"bootstrap(\.min)?\.(css|js)"))]),
        ("WordPress", [("body", None, re.compile(r"wp-content|wp-includes")),
                       ("header", "x-generator", re.compile(r"wordpress"))]),
        ("Drupal", [("body", None, re.compile(r"drupal|sites/default/files"))]),
        ("Joomla", [("body", None, re.compile(r"joomla|com_content"))]),
        ("Django", [("header", "x-csrftoken", re.compile(r".")),
                    ("header", "server", re.compile(r"django|gunicorn|uvicorn")),
                    ("body", None, re.compile(r"csrfmiddlewaretoken"))]),
        ("Rails", [("header", "x-request-id", re.compile(r".")),
                   ("header", "x-runtime", re.compile(r".")),
                   ("body", None, re.compile(r"csrf-token.*rails|actionview"))]),
        ("Laravel", [("header", "set-cookie", re.compile(r"laravel_session|xsrf-token"))]),
        ("Cloudflare", [("header", "server", re.compile(r"cloudflare")),
                        ("header", "cf-ray", re.compile(r"."))]),
        ("Google Cloud", [("header", "via", re.compile(r"1\.1 google")),
                          ("header", "x-served-by", re.compile(r"cache-"))]),
        ("Vercel", [("header", "x-vercel-id", re.compile(r".")),
                    ("header", "server", re.compile(r"vercel"))]),
        ("Netlify", [("header", "x-nf-request-id", re.compile(r"."))]),
        ("Akamai", [("header", "server", re.compile(r"akamai")),
                    ("header", "x-akamai", re.compile(r"."))]),
        ("Shopify", [("header", "x-shopid", re.compile(r".")),
                     ("header", "x-sorting-hat-poufops", re.compile(r"."))]),
        ("CloudFront", [("header", "x-amz-cf-id", re.compile(r"."))]),
        ("Stripe", [("body", None, re.compile(r"js\.stripe\.com"))]),
        ("Google Analytics", [("body", None, re.compile(r"google-analytics\.com|googletagmanager"))]),
        ("reCAPTCHA", [("body", None, re.compile(r"recaptcha|grecaptcha"))]),
        ("hCaptcha", [("body", None, re.compile(r"hcaptcha"))]),
    ]

    VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                       "x-drupal-cache", "x-generator", "x-version"]

    def options(self):
        return {"target": "URL or host to fingerprint"}

    def run(self):
        base = self._base()
        r = U.http_request(base, timeout=self.ctx.timeout,
                           user_agent=self.ctx.user_agent,
                           cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
        if not r.ok:
            raise ModuleError("request failed: %s" % (r.error or "no response"))
        found = []
        hl = {k.lower(): v for k, v in r.headers.items()}
        body = r.body
        for tech, sigs in self.SIGS:
            for kind, hname, rx in sigs:
                if kind == "header":
                    if hname in hl and rx.search(hl[hname]):
                        found.append(tech)
                        break
                elif rx.search(body):
                    found.append(tech)
                    break
        versions = []
        for h in self.VERSION_HEADERS:
            if h in hl:
                versions.append((h, hl[h][:120]))
        print("   %-18s %s" % (C.c("status:", C.BRIGHT_CYAN), r.status))
        for tech in sorted(set(found)):
            print("   %-18s %s" % (C.c("tech:", C.BRIGHT_CYAN),
                                   C.c(tech, C.BRIGHT_GREEN, C.BOLD)))
        for h, v in versions:
            print("   %-18s %s: %s" % (C.c("disclosure", C.BRIGHT_YELLOW), h, v))
        server = hl.get("server", "")
        m = re.search(r"(\d+\.\d+[\w./]*)", server)
        if m:
            self.add_finding("Server version disclosed in Server header (%s)" % m.group(1),
                             "info", base, "Server: %s" % server,
                             tip="Banner disclosure assists attackers; suppress versions.",
                             cwe="CWE-200")
        self.output({"url": base, "status": r.status, "tech": sorted(set(found)),
                     "versions": versions})
        self.success("tech_fingerprint: %d technologies identified" % len(set(found)))
        return "fingerprint finished"

    def _base(self):
        target = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not target:
            raise ModuleError("set 'target' option or add a target first")
        _s, _h, _p, base = U.normalize_target(target)
        return base


class WafDetectModule(BaseModule):
    NAME = "waf_detect"
    DESCRIPTION = "Detect WAF/CDN/proxy (Cloudflare, AWS WAF, Akamai, Imperva...) "
    CATEGORY = "web"

    WAFS = [
        ("Cloudflare", ["cf-ray", "server: cloudflare", "__cfduid", "cf-cache-status"]),
        ("AWS WAF", ["x-amzn-waf", "awswaf"]),
        ("Akamai", ["akamai", "x-akamai", "reference #18"]),
        ("Imperva/Incapsula", ["incap", "imperva", "x-iinfo"]),
        ("Sucuri", ["sucuri", "cloudproxy"]),
        ("F5 BIG-IP", ["bigipserver", "ts="]),
        ("Barracuda", ["barracuda", "bar_sync"]),
        ("Citrix NetScaler", ["ns cookie", "ns_af", "citrix"]),
        ("ModSecurity", ["mod_security", "modsecurity"]),
        ("Radware", ["x-sl-event", "radware"]),
        ("Edgecast", ["ec-"]),
        ("Fastly", ["fastly", "x-served-by: cache-"]),
        ("StackPath/MaxCDN", ["stackpath", "maxcdn"]),
        ("Deno Deploy", ["x-deno"]),
        ("Vercel WAF", ["x-vercel-id", "x-vercel-error"]),
        ("CloudFront", ["x-amz-cf-id", "x-amz-cf-pop"]),
        ("Google Cloud Armor", ["gcip", "x-cloud-trace-context"]),
        ("Wordfence", ["wordfence"]),
        ("Palo Alto", ["pan-web-session-id"]),
        ("Reblaze", ["reblaze"]),
    ]

    def options(self):
        return {"target": "URL or host"}

    def run(self):
        target = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not target:
            raise ModuleError("set 'target' option")
        _s, _h, _p, base = U.normalize_target(target)
        marker = "tveye" + U.random_string(10)
        probes = [
            ("normal GET", base, None),
            ("nosql-ish path", base + "/?id=1%27%20OR%201%3D1--", None),
            ("sqli path", base + "/?q=<script>alert(1)</script>", None),
            ("path traversal", base + "/?f=../../etc/passwd", None),
            ("sensitive path", base + "/.env", None),
        ]
        waf_hits = {}
        for label, url, _d in probes:
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, verify=self.ctx.verify_tls)
            if not r.ok:
                self.debug("probe %s failed: %s" % (label, r.error))
                continue
            text = r.body.lower() + " " + " ".join(
                "%s: %s" % (k.lower(), v.lower()) for k, v in r.headers.items())
            for name, sigs in self.WAFS:
                for sig in sigs:
                    if sig in text:
                        waf_hits.setdefault(name, 0)
                        waf_hits[name] += 1
                        break
            if r.status in (403, 406, 429, 501) and label != "normal GET":
                self.info("%s -> HTTP %s (possible WAF block)" % (label, r.status))
        detected = sorted(waf_hits.items(), key=lambda x: -x[1])
        if detected:
            for name, score in detected:
                print("   %-24s %s" % (C.c(name, C.BRIGHT_GREEN, C.BOLD),
                                       "confidence %d/5" % min(score, 5)))
            self.add_finding("WAF/CDN detected: %s" % detected[0][0], "info",
                             base, "fingerprints: %s" % dict(detected[:3]),
                             tip="Tune payloads for this WAF; document for the report.")
        else:
            self.success("no known WAF signature detected (target may be unfiltered)")
        self.output({"url": base, "waf": dict(detected)})
        return "waf detection finished"


class SecurityHeadersModule(BaseModule):
    NAME = "security_headers"
    DESCRIPTION = ("Audit security headers (CSP, HSTS, cookies, CORS, "
                   "clickjacking, cache) and rate each control")
    CATEGORY = "web"

    CHECKS = [
        ("strict-transport-security", "high", "HSTS missing - TLS downgrade/MITM risk",
         "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
        ("content-security-policy", "medium", "CSP missing - XSS impact not limited",
         "Add a Content-Security-Policy with script-src nonces or allow-lists"),
        ("x-frame-options", "low", "X-Frame-Options missing - clickjacking risk",
         "Set X-Frame-Options: DENY or frame-ancestors in CSP"),
        ("x-content-type-options", "low", "nosniff missing - MIME confusion risk",
         "Set X-Content-Type-Options: nosniff"),
        ("referrer-policy", "info", "Referrer-Policy missing - URL leakage",
         "Set Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "info", "Permissions-Policy missing",
         "Restrict camera/microphone/geolocation via Permissions-Policy"),
        ("x-xss-protection", "info", "Legacy X-XSS-Protection set (obsolete header)",
         "Remove X-XSS-Protection; rely on CSP"),
    ]

    def options(self):
        return {"target": "URL or host"}

    def run(self):
        target = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not target:
            raise ModuleError("set 'target' option")
        _s, _h, _p, base = U.normalize_target(target)
        r = U.http_request(base, timeout=self.ctx.timeout,
                           user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                           verify=self.ctx.verify_tls)
        if not r.ok:
            raise ModuleError("request failed: %s" % (r.error or r.status))
        hl = {k.lower(): v for k, v in r.headers.items()}
        present, missing = [], []
        for header, sev, why, fix in self.CHECKS:
            if header in hl:
                present.append((header, hl[header][:150]))
                self.success("%-28s present: %s" % (header, hl[header][:90]))
            else:
                missing.append((header, sev, why, fix))
                self.warn("%-28s MISSING (%s)" % (header, sev))
        # CORS
        cors = hl.get("access-control-allow-origin")
        if cors:
            if cors == "*":
                self.add_finding("Permissive CORS: Access-Control-Allow-Origin: *",
                                 "low", base, "ACA-O: %s" % cors,
                                 tip="Wildcard CORS on credentialed APIs leaks data.",
                                 cwe="CWE-942")
            else:
                self.info("CORS ACA-O: %s" % cors)
            aca = hl.get("access-control-allow-credentials")
            if aca and aca.lower() == "true" and cors not in ("*", "null"):
                self.add_finding(
                    "CORS with credentials allowed to origin %s" % cors,
                    "medium", base,
                    "ACA-O: %s | ACA-Credentials: %s" % (cors, aca),
                    tip="If origin is attacker-controlled this is critical; verify reflection.",
                    cwe="CWE-942")
        # cookies
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                low = v.lower()
                flags = []
                if "httponly" not in low:
                    flags.append("HttpOnly missing")
                if "secure" not in low:
                    flags.append("Secure missing")
                if "samesite" not in low:
                    flags.append("SameSite missing")
                if flags:
                    self.add_finding("Insecure cookie flags (%s)" % ", ".join(flags),
                                     "low", base, "Set-Cookie: %s" % v[:200],
                                     tip="Set HttpOnly; Secure; SameSite=Lax on session cookies.",
                                     cwe="CWE-1004")
        # clickjacking test via CSP too
        if "x-frame-options" not in hl and "frame-ancestors" not in hl.get("content-security-policy", ""):
            self.add_finding("Clickjacking possible (no frame protection)",
                             "low", base, "no X-Frame-Options and no CSP frame-ancestors",
                             tip="Add frame-ancestors 'none' or X-Frame-Options: DENY.",
                             cwe="CWE-1021")
        score = 100 - 15 * len([m for m in missing if m[1] in ("high", "medium")]) \
                - 6 * len([m for m in missing if m[1] == "low"]) \
                - 2 * len([m for m in missing if m[1] == "info"])
        score = max(0, score)
        print("")
        print("   " + C.c("HEADER SCORE: %d/100" % score, C.BOLD,
                          C.BRIGHT_GREEN if score >= 70 else C.BRIGHT_YELLOW))
        self.output({"url": base, "score": score, "present": present,
                     "missing": [m[0] for m in missing]})
        self.success("security_headers complete (score %d/100)" % score)
        return "header audit finished (score %d/100)" % score


class TlsAuditModule(BaseModule):
    NAME = "tls_audit"
    DESCRIPTION = ("TLS audit: cert chain/host mismatch/expiry, legacy protocol "
                   "support, weak cipher check")
    CATEGORY = "web"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "host or URL (TLS audit runs on 443)",
                "port": "TLS port (default 443)"}

    def run(self):
        _s, host, _p, _b = U.normalize_target(self.ctx.get_option("target"))
        port = int(self.ctx.get_option("port", 443))
        self.info("TLS audit %s:%d" % (host, port))
        problems = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.ctx.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ts:
                    cert = ts.getpeercert(binary_form=False) or {}
                    der = ts.getpeercert(binary_form=True)
                    proto = ts.version() or "?"
                    cipher = ts.cipher() or ("?", "?", 0)
                    print("   %-24s %s" % (C.c("protocol:", C.BRIGHT_CYAN), proto))
                    print("   %-24s %s (%s bits)" % (C.c("cipher:", C.BRIGHT_CYAN),
                                                     cipher[0], cipher[2]))
            if der:
                import ssl as _ssl
                # use _ssl enum_certificates alternative: parse via ssl._ssl? use openssl via os
                try:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    self.output({"host": host, "protocol": proto, "cipher": cipher[0],
                                 "cert_pem": pem[:4000]})
                except Exception:
                    pass
            if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                problems.append("Legacy protocol negotiated: %s" % proto)
                self.add_finding("Legacy TLS protocol supported: %s" % proto,
                                 "medium", "%s:%d" % (host, port), "negotiated %s" % proto,
                                 tip="Disable TLS < 1.2; enable TLS 1.3.",
                                 cwe="CWE-327")
            if cipher[0] and re.search(r"RC4|DES|3DES|NULL|EXP|aNULL", cipher[0]):
                problems.append("Weak cipher negotiated: %s" % cipher[0])
                self.add_finding("Weak TLS cipher suite: %s" % cipher[0],
                                 "medium", "%s:%d" % (host, port), "cipher %s" % cipher[0],
                                 tip="Restrict to AEAD suites (AES-GCM, ChaCha20).",
                                 cwe="CWE-327")
        except Exception as exc:
            raise ModuleError("TLS handshake failed: %s" % exc)
        # cert expiry / hostname check with verification on
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.ctx.timeout) as sock:
                with vctx.wrap_socket(sock, server_hostname=host):
                    self.success("certificate validates against system CA store")
        except ssl.SSLCertVerificationError as exc:
            problems.append("Certificate verification failed: %s" % exc.verify_message
                            if hasattr(exc, "verify_message") else str(exc))
            self.add_finding("TLS certificate verification fails (%s)" % host,
                             "medium", "%s:%d" % (host, port), str(exc)[:300],
                             tip="Fix chain/hostname/SAN; self-signed certs break clients.",
                             cwe="CWE-295")
            self.warn("cert verification failed: %s" % str(exc)[:160])
        except Exception as exc:
            self.debug("verification pass: %s" % exc)
        if not problems:
            self.success("no TLS protocol/cipher problems detected")
        return "tls audit finished (%d issues)" % len(problems)


class CorsModule(BaseModule):
    NAME = "cors_scan"
    DESCRIPTION = ("CORS misconfiguration scanner: origin reflection, null origin, "
                   "subdomain trust, credentials")
    CATEGORY = "web"
    REQUIRED = ["target"]

    EVIL_ORIGINS = [
        "https://evil.example.com",
        "null",
        "https://%s.evil.example.com",  # subdomain trust test placeholder
    ]

    def options(self):
        return {"target": "API endpoint or site URL to test",
                "origin": "custom Origin header value (optional)"}

    def run(self):
        target = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not target:
            raise ModuleError("set 'target' option")
        _s, host, _p, base = U.normalize_target(target)
        origins = [o if "%s" not in o else o % host for o in self.EVIL_ORIGINS]
        custom = self.ctx.get_option("origin")
        if custom:
            origins.insert(0, custom)
        results = []
        for origin in origins:
            r = U.http_request(base, timeout=self.ctx.timeout,
                               headers={"Origin": origin},
                               user_agent=self.ctx.user_agent,
                               cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
            acao = ""
            acac = ""
            for k, v in r.headers.items():
                if k.lower() == "access-control-allow-origin":
                    acao = v
                if k.lower() == "access-control-allow-credentials":
                    acac = v
            print("   Origin: %-38s ACAO: %-28s ACAC: %s" % (origin, acao or "-", acac or "-"))
            results.append({"origin": origin, "acao": acao, "acac": acac,
                            "status": r.status})
            if acao and (acao == origin or (origin == "null" and acao == "null")):
                if acac.lower() == "true":
                    self.add_finding(
                        "CORS reflects arbitrary origin with credentials: %s" % base,
                        "high", base,
                        "Origin: %s -> ACAO: %s, ACAC: %s" % (origin, acao, acac),
                        tip="Any site can read authenticated responses; restrict origin allow-list.",
                        cwe="CWE-942")
                else:
                    self.add_finding(
                        "CORS reflects arbitrary origin (no credentials): %s" % base,
                        "low", base,
                        "Origin: %s -> ACAO: %s" % (origin, acao),
                        tip="Limit reflection to trusted origins.",
                        cwe="CWE-942")
        self.output({"target": base, "results": results})
        self.success("cors_scan finished")
        return "cors scan finished"
