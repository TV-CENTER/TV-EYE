"""Subdomain enumeration, takeover checks and wayback discovery for TV-EYE."""

import json
import re
import time
import urllib.parse

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class SubdomainEnumModule(BaseModule):
    NAME = "subdomain_enum"
    DESCRIPTION = ("Discover subdomains via certificate transparency (crt.sh), "
                   "DNS bruteforce with built-in wordlist and active resolution")
    CATEGORY = "recon"
    REQUIRED = ["domain"]

    WORDS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
             "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
             "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
             "mx", "email", "cloud", "1", "mail1", "forum", "owa", "www2",
             "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app",
             "gov", "2yty", "vps", "intranet", "staging", "beta", "demo",
             "dashboard", "jenkins", "git", "jira", "confluence", "sso",
             "vpn2", "static", "assets", "media", "files", "backup", "old",
             "new", "internal", "corp", "intra", "prod", "qa", "uat", "sales",
             "crm", "erp", "hr", "portal2", "client", "partners", "docs",
             "help", "status", "metrics", "grafana", "kibana", "elastic",
             "db", "sql", "mysql", "pg", "mongo", "redis", "cache", "s3",
             "bucket", "storage", "upload", "download", "node", "proxy",
             "gateway", "edge", "lb", "firewall", "auth", "login", "id",
             "oauth", "accounts", "payment", "pay", "billing", "invoice",
             "shop2", "cart", "checkout", "catalog", "search", "solr",
             "es", "k8s", "docker", "registry", "nexus", "artifactory",
             "ci", "cd", "build", "stage", "preprod", "rc", "rel", "hotfix"]

    def options(self):
        return {
            "domain": "root domain to enumerate",
            "mode": "ct|brute|all (default all)",
        }

    def run(self):
        domain = self.ctx.get_option("domain").strip().lower().strip(".")
        mode = (self.ctx.get_option("mode", "all") or "all").lower()
        found = set()
        wildcard_ips = self._wildcard_check(domain)

        if mode in ("ct", "all"):
            self.info("querying crt.sh certificate transparency logs ...")
            got = self._crtsh(domain)
            found.update(got)
            self.success("crt.sh: %d unique names" % len(got))

        if mode in ("brute", "all"):
            self.info("DNS bruteforce with %d built-in candidates ..." % len(self.WORDS))

            def job(w):
                sub = "%s.%s" % (w, domain)
                if U.dns_resolve(sub):
                    return sub
                return None

            t0 = time.time()
            hits = U.worker_pool(self.WORDS, job, threads=self.ctx.threads)
            hits = [h for h in hits if h]
            found.update(hits)
            self.success("brute force: %d hits in %.1fs" % (len(hits), time.time() - t0))

        if wildcard_ips:
            self.warn("wildcard DNS detected (%s) - verifying each host resolves "
                      "to a unique IP" % ",".join(wildcard_ips[:3]))

        resolved = {}

        def rjob(sub):
            return sub, U.dns_resolve(sub)

        subs = sorted(found)[:400]
        rres = U.worker_pool(subs, rjob, threads=self.ctx.threads)
        table = []
        for sub, ips in rres:
            if not ips:
                continue
            if wildcard_ips and set(ips) == set(wildcard_ips):
                continue
            resolved[sub] = ips
            table.append((sub, ", ".join(ips[:2])))
        self.output({"domain": domain, "count": len(resolved),
                     "resolved": resolved, "wildcard": wildcard_ips})
        for sub, ips in table[:60]:
            print("   " + C.c("%-38s" % sub, C.BRIGHT_WHITE) + " " + ips)
        if len(table) > 60:
            self.info("... and %d more (see session output)" % (len(table) - 60))
        self.success("subdomain_enum finished: %d live subdomains" % len(resolved))
        return "subdomain enum finished (%d live)" % len(resolved)

    def _wildcard_check(self, domain):
        probe = U.random_string(14) + "." + domain
        return U.dns_resolve(probe)

    def _crtsh(self, domain):
        url = ("https://crt.sh/?q=%25." + urllib.parse.quote(domain) +
               "&output=json")
        r = U.http_request(url, timeout=self.ctx.timeout + 10,
                           user_agent=self.ctx.user_agent, verify=self.ctx.verify_tls)
        names = set()
        if r.ok and r.body:
            try:
                data = json.loads(r.body)
                for entry in data[:3000]:
                    nv = entry.get("name_value", "")
                    for n in nv.split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(domain) and n != domain and "*" not in n:
                            names.add(n)
            except (ValueError, KeyError):
                self.warn("crt.sh returned non-JSON (rate limited?)")
        return names


class TakeoverModule(BaseModule):
    NAME = "takeover_check"
    DESCRIPTION = ("Detect dangling DNS records (CNAME/TXT) pointing to "
                   "unclaimed services - classic subdomain takeover")
    CATEGORY = "recon"
    REQUIRED = ["domain"]

    FINGERPRINTS = [
        ("GitHub Pages", ["there isn't a github pages site here", "404 there isn't"], "github.io"),
        ("Heroku", ["no such app", "herokucdn.com/error-pages"], "herokuapp.com"),
        ("AWS S3", ["the specified bucket does not exist", "nosuchbucket"], "s3.amazonaws.com"),
        ("Azure", ["404 web site not found", "the resource you are looking for"], "azurewebsites.net"),
        ("CloudFront", ["bad request", "error: the request could not be satisfied"], "cloudfront.net"),
        ("Shopify", ["sorry, this shop is currently unavailable"], "myshopify.com"),
        ("Fastly", ["fastly error: unknown domain"], "fastly.net"),
        ("Pantheon", ["the gods are wise", "404 error unknown domain"], "pantheonsite.io"),
        ("Tumblr", ["whatever you were looking for doesn't currently exist"], "tumblr.com"),
        ("Wordpress.com", ["do you want to register", "domain mapping setup"], "wordpress.com"),
        ("Zendesk", ["help center closed"], "zendesk.com"),
        ("Unbounce", ["the requested url was not found on this server"], "unbouncepages.com"),
        ("Surge.sh", ["project not found"], "surge.sh"),
        ("Bitbucket", ["repository not found"], "bitbucket.io"),
        ("Intercom", ["this page is reserved for artistic dogs"], "custom.intercom.help"),
        ("Webflow", ["the page you are looking for doesn't exist or has been moved"], "proxy-ssl.webflow.com"),
        ("Readme.io", ["project doesnt exist... yet!"], "readme.io"),
        ("Freshdesk", ["may be moved or deleted"], "freshdesk.com"),
        ("HatenaBlog", ["hatena blog \u003e 404"], "hatenablog.com"),
        ("Cargo", ["if you're moving your domain away"], "cargocollective.com"),
    ]

    def options(self):
        return {
            "domain": "root domain; enumerates then probes every subdomain",
            "subdomains": "optional comma separated list to probe directly",
        }

    def run(self):
        subs = self.ctx.get_option_list("subdomains")
        domain = self.ctx.get_option("domain")
        if not subs and domain:
            self.info("collecting subdomains for %s (ct.sh quick pass)" % domain)
            url = "https://crt.sh/?q=%25." + domain + "&output=json"
            r = U.http_request(url, timeout=self.ctx.timeout + 10,
                               user_agent=self.ctx.user_agent)
            if r.ok and r.body.strip().startswith("["):
                try:
                    for e in json.loads(r.body)[:2000]:
                        for n in e.get("name_value", "").split("\n"):
                            n = n.strip().lower().lstrip("*.")
                            if n.endswith(domain) and n != domain:
                                if n not in subs:
                                    subs.append(n)
                except ValueError:
                    pass
        if not subs:
            raise ModuleError("no subdomains to check (set domain or subdomains option)")
        self.info("checking %d subdomains for dangling records" % len(subs))

        def job(sub):
            return self._check(sub)

        results = U.worker_pool(subs, job, threads=max(2, min(self.ctx.threads, 15)))
        hits, dangles = [], []
        for res in results:
            if not res:
                continue
            sub, cname, status, snippet, service = res
            if cname:
                if status == 0:
                    dangles.append((sub, cname))
                    self.warn("DANGLING CNAME %s -> %s (no HTTP response)" % (sub, cname))
                elif status in (404, 400, 409, 502) or service:
                    dangles.append((sub, cname))
                    msg = "POSSIBLE TAKEOVER %s -> %s (HTTP %s%s)" % (
                        sub, cname, status,
                        " - matched: %s" % service if service else "")
                    sev = "high" if service else "medium"
                    self.add_finding(
                        ("Subdomain takeover: %s" % sub) if service
                        else ("Possible subdomain takeover: %s" % sub),
                        sev, sub, "%s\nCNAME: %s\nHTTP status: %s\nBody: %s" % (
                            msg, cname, status, snippet[:200]),
                        tip="Verify the target service allows claiming this hostname, "
                            "then register/claim the endpoint and report with evidence.",
                        cwe="CWE-350")
                    hits.append(res)
                else:
                    self.info("ok %s -> %s (HTTP %s)" % (sub, cname, status))
        self.output({"checked": len(subs), "dangling": dangles, "hits": hits})
        if not dangles:
            self.success("no dangling records found")
        return "takeover check finished (%d dangling)" % len(dangles)

    def _check(self, sub):
        cnames = U.dns_lookup(sub, "CNAME")
        target = cnames[0] if cnames else None
        status, snippet, service = 0, "", None
        scheme = "https"
        url = "%s://%s" % (scheme, sub)
        r = U.http_request(url, timeout=self.ctx.timeout + 5,
                           user_agent=self.ctx.user_agent, verify=False)
        if r.status:
            status = r.status
            snippet = r.body[:400]
            low = r.body.lower()
            for svc, sigs, dom in self.FINGERPRINTS:
                if target and target.endswith(dom):
                    service = svc
                    break
                if any(s.lower() in low for s in sigs):
                    service = svc
                    break
        return (sub, target or "", status, snippet, service)


class WaybackModule(BaseModule):
    NAME = "wayback_urls"
    DESCRIPTION = "Pull historical URLs from the Wayback Machine CDX API"
    CATEGORY = "recon"
    REQUIRED = ["domain"]

    def options(self):
        return {"domain": "domain or URL to fetch history for",
                "filter": "optional URL substring filter (e.g. .json, api)"}

    def run(self):
        dom = self.ctx.get_option("domain").strip()
        flt = self.ctx.get_option("filter", "")
        url = ("https://web.archive.org/cdx/search/cdx?url=%s*&output=text&"
               "fl=original,statuscode,mimetype&collapse=urlkey&limit=1500"
               % urllib.parse.quote(dom))
        self.info("querying Wayback CDX for %s ..." % dom)
        r = U.http_request(url, timeout=self.ctx.timeout + 15,
                           user_agent=self.ctx.user_agent)
        if not r.ok:
            raise ModuleError("wayback request failed: %s" % (r.error or r.status))
        lines = [l for l in r.body.splitlines() if l.strip()]
        rows = []
        for l in lines:
            parts = l.split(" ", 2)
            if len(parts) == 3:
                u, code, mime = parts
                if flt and flt not in u:
                    continue
                rows.append((u[:110], code, mime[:30]))
        for u, code, mime in rows[:60]:
            print("   [%s] %-30s %s" % (code, mime, u))
        if len(rows) > 60:
            self.info("... and %d more" % (len(rows) - 60))
        self.output({"count": len(rows), "urls": [r0[0] for r0 in rows[:1500]]})
        interesting = [u for u, _c, _m in rows if re.search(
            r"\.(sql|zip|bak|json|xml|log|conf|env|yaml|yml|7z|tar|gz)(\?|$)", u)]
        if interesting:
            self.warn("%d interesting file extensions in history" % len(interesting))
            for u in interesting[:15]:
                print("     * " + u)
        self.success("wayback_urls complete: %d URLs" % len(rows))
        return "wayback finished (%d urls)" % len(rows)
