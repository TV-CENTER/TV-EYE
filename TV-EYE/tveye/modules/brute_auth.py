"""Authorized credential-testing modules: login brute force + password spray."""

import time

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class LoginBruteModule(BaseModule):
    NAME = "login_brute"
    DESCRIPTION = ("Login brute force helper for AUTHORIZED pentests "
                   "(use only accounts you own or are permitted to test)")
    CATEGORY = "auth"
    REQUIRED = ["target"]

    def options(self):
        return {
            "target": "login endpoint URL",
            "body": "POST body template with {USER} and {PASS}",
            "users": "comma separated usernames or 'users' for builtin list",
            "passwords": "comma separated passwords (keep it small!) or path to wordlist",
            "success": "text in response that marks success (optional)",
            "fail": "text in response that marks failure (optional)",
            "delay": "seconds between attempts (default 0.3)",
        }

    def run(self):
        url = self.ctx.get_option("target")
        body = self.ctx.get_option("body", "username={USER}&password={PASS}")
        users = self._list(self.ctx.get_option("users", ""), U.builtin_wordlist("users"))
        passwords = self._list(self.ctx.get_option("passwords", ""), ["password", "123456", "admin"])
        ok_sig = self.ctx.get_option("success", "")
        fail_sig = self.ctx.get_option("fail", "")
        delay = float(self.ctx.get_option("delay", 0.3) or 0.3)
        if not users or not passwords:
            raise ModuleError("provide users and passwords options")
        total = len(users) * len(passwords)
        if total > 500:
            raise ModuleError("attempt set too large (%d > 500). Keep authorized tests bounded." % total)
        self.warn("authorized credential testing: %d user x %d pass = %d attempts"
                  % (len(users), len(passwords), total))
        hits = []
        n = 0
        for u in users:
            for p in passwords:
                n += 1
                data = body.replace("{USER}", u).replace("{PASS}", p)
                r = U.http_request(url, method="POST", data=data,
                                   timeout=self.ctx.timeout,
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                                   verify=self.ctx.verify_tls, retries=0)
                body_low = (r.body or "").lower()
                good = False
                if ok_sig and ok_sig.lower() in body_low:
                    good = True
                elif fail_sig and fail_sig.lower() not in body_low and r.status == 200:
                    good = True
                elif not ok_sig and not fail_sig and r.status in (200, 302):
                    self.debug("[%d/%d] %s:%s -> HTTP %s (no signature set)"
                               % (n, total, u, p, r.status))
                if good:
                    hits.append((u, p, r.status))
                    self.add_finding("Valid credentials found: %s / %s" % (u, p),
                                     "critical", url,
                                     "Login succeeded (HTTP %s) with %s:%s" % (r.status, u, p),
                                     tip="Report per program policy; suggest MFA + lockout.",
                                     cwe="CWE-521")
                    self.success("HIT: %s : %s (HTTP %s)" % (u, p, r.status))
                if delay:
                    time.sleep(delay)
        self.output({"url": url, "attempts": n, "hits": hits})
        self.success("login_brute done: %d hits" % len(hits))
        return "brute finished (%d attempts, %d hits)" % (n, len(hits))

    def _list(self, raw, fallback):
        if not raw:
            return []
        if raw.lower() == "users":
            return fallback
        if "/" in raw or "\\" in raw:
            wl = U.read_wordlist(raw, 200)
            if wl:
                return wl[:200]
        return [x.strip() for x in raw.split(",") if x.strip()]


class HeaderReconModule(BaseModule):
    NAME = "header_recon"
    DESCRIPTION = "Dump all response headers, server behavior and interesting values"
    CATEGORY = "web"
    REQUIRED = ["target"]

    def options(self):
        return {"target": "URL"}

    def run(self):
        _s, _h, _p, base = U.normalize_target(self.ctx.get_option("target"))
        r = U.http_request(base, timeout=self.ctx.timeout, user_agent=self.ctx.user_agent,
                           cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
        if not r.ok:
            raise ModuleError("request failed: %s" % (r.error or r.status))
        print("   %s %s" % (C.c("status:", C.BRIGHT_CYAN), r.status))
        for k, v in sorted(r.headers.items()):
            print("   %-32s %s" % (C.c(k + ":", C.BRIGHT_CYAN), v[:120]))
        interesting = ["server", "x-powered-by", "x-AspNet-Version".lower(),
                       "x-request-id", "via", "x-forwarded-host"]
        for k, v in r.headers.items():
            if k.lower() in interesting and re.search(r"\d+\.\d+", v):
                self.add_finding("Header disclosure: %s: %s" % (k, v[:80]), "info", base,
                                 "%s: %s" % (k, v), tip="Suppress detailed server headers.",
                                 cwe="CWE-200")
        self.output({"url": base, "headers": dict(r.headers)})
        return "header recon finished"
