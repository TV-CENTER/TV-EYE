"""OSINT modules for TV-EYE: metadata harvest, email hunting, GitHub dorks."""

import re

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class OsintHarvestModule(BaseModule):
    NAME = "osint_harvest"
    DESCRIPTION = ("Harvest emails, social links, analytics IDs, phone numbers "
                   "and technology comments from a site's pages")
    CATEGORY = "osint"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "site base URL", "depth": "pages to crawl (default 15)"}

    def run(self):
        _s, _h, _p, base = U.normalize_target(self._target())
        depth = int(self.ctx.get_option("depth", 15))
        seen = set()
        queue = [base + "/"]
        emails, phones, socials, ga_ids, comments = set(), set(), set(), set(), set()
        pages = 0
        while queue and pages < depth:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            r = U.http_request(url, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok or "html" not in r.header("content-type", "html").lower() and r.body[:200].find("<") == -1:
                continue
            pages += 1
            body = r.body
            emails.update(U.extract_emails(body))
            for ph in re.findall(r"(\+?\d[\d\s().-]{7,}\d)", body):
                if re.match(r"^[+]?[\d\s().-]{8,15}$", ph):
                    phones.add(ph.strip())
            for m in re.findall(r"https?://(?:www\.)?(facebook|twitter|x|linkedin|instagram|youtube|t\.me|github)\.com/([A-Za-z0-9_./-]{2,40})", body, re.I):
                socials.add("%s.com/%s" % (m[0], m[1].rstrip("/")))
            ga_ids.update(re.findall(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12})\b", body))
            for m in re.findall(r"<!--(.*?)-->", body, re.S):
                if len(m) > 8:
                    comments.add(" ".join(m.split())[:140])
            for link in U.extract_links(body):
                if link.startswith(base) and link not in seen:
                    queue.append(link)
        print("   %-16s %d emails, %d phones, %d socials, %d analytics ids" % (
            C.c("harvested:", C.BRIGHT_CYAN), len(emails), len(phones),
            len(socials), len(ga_ids)))
        for e in sorted(emails)[:20]:
            print("     email : %s" % e)
        for s in sorted(socials)[:15]:
            print("     social: %s" % s)
        for g in sorted(ga_ids)[:8]:
            print("     anal  : %s" % g)
        for cch in sorted(comments)[:10]:
            print("     comment: %s" % cch[:120])
        self.output({"url": base, "emails": sorted(emails), "phones": sorted(phones),
                     "socials": sorted(socials), "analytics": sorted(ga_ids),
                     "comments": sorted(comments), "pages": pages})
        if emails:
            self.add_finding("Email addresses publicly harvested (%d)" % len(emails),
                             "info", base, ", ".join(sorted(emails)[:30]),
                             tip="Use for phishing-awareness programs; verify in-scope policy.")
        self.success("osint_harvest done: %d pages crawled" % pages)
        return "osint harvest finished (%d emails)" % len(emails)

    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        return t


class EmailHuntModule(BaseModule):
    NAME = "email_hunt"
    DESCRIPTION = ("Email hunter: generate candidate addresses from a name/domain "
                   "and verify MX existence + optional breach-check hints")
    CATEGORY = "osint"
    REQUIRED = ["domain"]

    def options(self):
        return {"domain": "target domain",
                "first": "first name (optional)", "last": "last name (optional)"}

    def run(self):
        domain = self.ctx.get_option("domain").strip().lower()
        first = (self.ctx.get_option("first", "") or "").lower().strip()
        last = (self.ctx.get_option("last", "") or "").lower().strip()
        mx = U.dns_lookup(domain, "MX")
        if mx:
            self.success("MX found: %s" % ", ".join(mx[:4]))
        else:
            self.warn("no MX record - domain may not receive mail")
        cands = []
        patterns = []
        if first and last:
            patterns = [f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}",
                        f"{first[0]}.{last}", f"{first}-{last}", f"{first}",
                        f"{last}", f"{first}_{last}"]
        else:
            patterns = ["info", "contact", "support", "admin", "hello", "sales",
                        "security", "abuse", "hr", "jobs", "noreply", "no-reply",
                        "billing", "dev", "press"]
        for pat in patterns:
            cands.append("%s@%s" % (pat, domain))
        self.info("%d candidate addresses generated" % len(cands))
        for c0 in cands:
            print("     %s" % c0)
        self.output({"domain": domain, "mx": mx, "candidates": cands})
        if not mx:
            self.add_finding("Domain has no MX record (no mail service)", "info",
                             domain, "MX lookup empty", tip="Informational.")
        self.success("email_hunt done")
        return "email hunt finished"


class GithubDorkModule(BaseModule):
    NAME = "github_dorks"
    DESCRIPTION = ("Generate GitHub dork search links for a target domain/company "
                   "(opens ready-to-run search URLs)")
    CATEGORY = "osint"
    REQUIRED = ["domain"]

    DORKS = [
        '"{D}" password', '"{D}" secret', '"{D}" api_key', '"{D}" apikey',
        '"{D}" token', '"{D}" AWS_SECRET', '"{D}" smtp', '"{D}" jdbc',
        '"{D}" "authorization: Bearer"', '"{D}" ssh-rsa', '"{D}" .env',
        '"{D}" config', '"{D}" dbname', '"{D}" sendgrid', '"{D}" firebase',
        'filename:.env "{D}"', 'filename:config "{D}"',
        'filename:settings.py "{D}"', 'extension:json "{D}"',
    ]

    def options(self):
        return {"domain": "domain or company name",
                "github_token": "optional personal access token for the API"}

    def run(self):
        d = self.ctx.get_option("domain").strip()
        self.info("GitHub dork URLs for '%s' (open in browser):" % d)
        links = []
        for dork in self.DORKS:
            q = dork.replace("{D}", d)
            import urllib.parse
            link = "https://github.com/search?q=" + urllib.parse.quote(q) + "&type=code"
            links.append(link)
            print("   %s" % link)
        tok = self.ctx.get_option("github_token", "")
        if tok:
            import json as _json
            import urllib.request as _ur
            hdr = {"Authorization": "token " + tok, "User-Agent": self.ctx.user_agent}
            for dork in self.DORKS[:6]:
                q = dork.replace("{D}", d)
                try:
                    req = _ur.Request("https://api.github.com/search/code?q=" +
                                      urllib.parse.quote(q), headers=hdr)
                    with _ur.urlopen(req, timeout=10) as resp:
                        data = _json.loads(resp.read(200000).decode("utf-8", "replace"))
                    total = data.get("total_count", 0)
                    print("   %-40s -> %s hits" % (q, total))
                    if total:
                        for item in data.get("items", [])[:3]:
                            print("       %s" % item.get("html_url", ""))
                except Exception as exc:
                    self.debug("github api: %s" % exc)
                    break
        self.output({"domain": d, "links": links})
        self.success("github_dorks: %d search links generated" % len(links))
        return "github dorks generated"


class JsSecretsModule(BaseModule):
    NAME = "js_secrets"
    DESCRIPTION = ("Fetch site JavaScript files and grep for API keys, secrets, "
                   "tokens, internal endpoints")
    CATEGORY = "osint"
    REQUIRED = ["target"]

    PATTERNS = [
        ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
        ("Firebase", re.compile(r"[a-z0-9.-]+\.firebaseio\.com")),
        ("JWT", re.compile(r"ey[A-Za-z0-9_-]{10,}\.[eyA-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")),
        ("Slack token", re.compile(r"xox[bp]-[0-9A-Za-z-]{10,}")),
        ("Stripe key", re.compile(r"(sk|pk)_(live|test)_[0-9a-zA-Z]{10,}")),
        ("Generic secret", re.compile(r"(?:secret|password|passwd|pwd|token|api[-_]?key)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{8,64})['\"]", re.I)),
        ("Internal URL", re.compile(r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?[^\s\"']*")),
        ("S3 bucket", re.compile(r"[a-z0-9.-]+\.s3[.-]?[a-z0-9-]*\.?amazonaws\.com")),
        ("Private key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
        ("Heroku", re.compile(r"heroku[a-z0-9]{28,40}")),
        ("Mailgun", re.compile(r"key-[0-9a-zA-Z]{32}")),
        ("Twilio", re.compile(r"AC[a-z0-9]{32}")),
        ("SendGrid", re.compile(r"SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,32}")),
    ]

    def options(self):
        return {"target": "site base URL", "max_js": "max js files to fetch (default 25)"}

    def run(self):
        _s, _h, _p, base = U.normalize_target(self._target())
        r = U.http_request(base, timeout=self.ctx.timeout, user_agent=self.ctx.user_agent,
                           cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
        if not r.ok:
            raise ModuleError("cannot fetch base page")
        scripts = set()
        for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.body, re.I):
            if m.endswith(".js") or ".js?" in m:
                scripts.add(U.build_url(base, m) if not m.startswith("http") else m)
        # also inline scripts
        inline = re.findall(r"<script(?![^>]*src)[^>]*>(.*?)</script>", r.body, re.I | re.S)
        max_js = int(self.ctx.get_option("max_js", 25))
        self.info("found %d external js + %d inline blocks" % (len(scripts), len(inline)))
        hits = {}

        def scan_text(text, src):
            out = []
            for name, rx in self.PATTERNS:
                for m in rx.finditer(text):
                    val = m.group(0)
                    if name == "Generic secret" and m.lastindex and m.lastindex >= 1:
                        val = m.group(1)
                    out.append((name, val[:80], src))
            return out

        all_hits = scan_text(" ".join(inline[:40]), "inline")
        js_list = sorted(scripts)[:max_js]

        def job(u):
            rr = U.http_request(u, timeout=self.ctx.timeout, user_agent=self.ctx.user_agent,
                                verify=self.ctx.verify_tls, retries=0)
            if rr.ok:
                return scan_text(rr.body, u)
            return []

        results = U.worker_pool(js_list, job, threads=max(2, self.ctx.threads))
        for lst in results:
            all_hits.extend(lst)
        for name, val, src in all_hits:
            key = (name, val)
            if key in hits:
                continue
            hits[key] = src
            color = C.BRIGHT_RED if name in ("AWS Key", "Private key", "Stripe key",
                                             "SendGrid", "Slack token") else C.BRIGHT_YELLOW
            print("   %s %-16s %s" % (C.c("SECRET?", color, C.BOLD), name, val[:60]))
        for (name, val), src in list(hits.items())[:40]:
            sev = "high" if name in ("AWS Key", "Private key", "SendGrid", "Stripe key") else "low"
            if name in ("Internal URL", "S3 bucket", "Firebase", "Heroku"):
                sev = "info"
            if name == "Generic secret":
                sev = "medium"
            self.add_finding("Possible secret in JavaScript: %s" % name, sev, src,
                             "Match: %s" % val,
                             tip="Verify key is live and report with minimal redaction.",
                             cwe="CWE-798" if "key" in name.lower() or "secret" in name.lower() else "CWE-200")
        self.output({"base": base, "hits": ["%s: %s" % (n, v) for (n, v) in hits]})
        self.success("js_secrets: %d unique match(es)" % len(hits))
        return "js secrets scan finished (%d hits)" % len(hits)

    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        return t
