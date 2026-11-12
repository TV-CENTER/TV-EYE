"""Directory/parameter discovery modules for TV-EYE."""

import re
import urllib.parse

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class DirBusterModule(BaseModule):
    NAME = "dir_buster"
    DESCRIPTION = ("Content discovery: brute force directories/files with built-in "
                   "or custom wordlist, response code + length + heuristic soft-404")
    CATEGORY = "web"
    REQUIRED = ["target"]

    INTEREST = [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500]

    def options(self):
        return {
            "target": "base URL to scan",
            "wordlist": "path to custom wordlist file (optional)",
            "extensions": "comma separated extensions (default .php,.bak,.txt,.json)",
        }

    def run(self):
        _s, _h, _p, base = U.normalize_target(self._target())
        words = U.read_wordlist(self.ctx.get_option("wordlist", ""))
        if not words:
            words = U.builtin_wordlist("small")
        exts = [e.strip() if e.strip().startswith(".") else "." + e.strip()
                for e in (self.ctx.get_option("extensions", "") or "").split(",") if e.strip()]
        paths = []
        for w in words:
            w = w.strip("/")
            paths.append("/" + w)
            for e in exts:
                paths.append("/" + w + e)
        # baseline / random 404
        base_rand = "/%s" % U.random_string(12)
        r404 = U.http_request(U.build_url(base, base_rand), timeout=self.ctx.timeout,
                              user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                              verify=self.ctx.verify_tls)
        soft404 = {r404.status, r404.body.__len__()}
        self.info("baseline 404 -> status %s, len %s" % (r404.status, len(r404.body)))
        self.info("probing %d paths with %d threads ..." % (len(paths), self.ctx.threads))
        hits = []

        def job(p):
            r = U.http_request(U.build_url(base, p), timeout=self.ctx.timeout,
                               method="GET", user_agent=self.ctx.user_agent,
                               cookie=self.ctx.cookie, verify=self.ctx.verify_tls,
                               retries=0)
            if not r.ok:
                return None
            if r.status in (404, 410):
                return None
            # soft 404 heuristic: same length as random 404
            if r.status == r404.status and len(r.body) == len(r404.body):
                return None
            return p, r.status, len(r.body), r.header("location")[:60]

        results = U.worker_pool(paths, job, threads=self.ctx.threads)
        for res in results:
            if res:
                hits.append(res)
                code, plen = res[1], res[2]
                color = C.BRIGHT_GREEN if code in (200,) else (
                    C.BRIGHT_YELLOW if code in (301, 302, 307, 308) else C.BRIGHT_RED)
                print("   %s %-8s %-52s len=%-7d %s" % (
                    C.c("HIT", C.BOLD), C.c(str(code), color), res[0], plen, res[3]))
        self.output({"base": base, "hits": hits, "baseline": list(soft404)})
        if hits:
            self.success("dir_buster found %d entries" % len(hits))
        else:
            self.warn("no directory hits found (try a bigger wordlist)")
        return "dir buster finished (%d hits)" % len(hits)

    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        return t


class SensitiveFilesModule(BaseModule):
    NAME = "sensitive_files"
    DESCRIPTION = ("Probe high-value exposure: .env, .git, backups, config dumps, "
                   "ID files, actuator, cloud metadata artifacts")
    CATEGORY = "web"
    REQUIRED = ["target"]

    PATHS = [
        ("/.env", "env file", "high"),
        ("/.env.local", "env file", "high"),
        ("/.git/HEAD", "git repo exposed", "high"),
        ("/.git/config", "git config", "high"),
        ("/.svn/entries", "svn repo exposed", "high"),
        ("/.DS_Store", "directory listing artifact", "low"),
        ("/backup.zip", "backup archive", "medium"),
        ("/backup.tar.gz", "backup archive", "medium"),
        ("/site.zip", "backup archive", "medium"),
        ("/db.sql", "database dump", "high"),
        ("/dump.sql", "database dump", "high"),
        ("/robots.txt", "robots file", "info"),
        ("/sitemap.xml", "sitemap", "info"),
        ("/server-status", "apache status", "medium"),
        ("/web.config", "IIS config", "medium"),
        ("/crossdomain.xml", "flash policy (legacy)", "low"),
        ("/security.txt", "security contact", "info"),
        ("/.well-known/security.txt", "security contact", "info"),
        ("/actuator/health", "spring actuator", "info"),
        ("/actuator/env", "spring actuator env (secrets!)", "high"),
        ("/actuator/heapdump", "heap dump download", "critical"),
        ("/swagger.json", "API docs", "low"),
        ("/swagger-ui.html", "API docs", "info"),
        ("/api-docs", "API docs", "info"),
        ("/graphql", "GraphQL endpoint", "info"),
        ("/wp-config.php.bak", "wp config backup", "high"),
        ("/config.php.bak", "config backup", "high"),
        ("/composer.lock", "dependency list", "info"),
        ("/package.json", "dependency list", "info"),
        ("/id_rsa", "private key", "critical"),
        ("/.htaccess", "apache config", "low"),
        ("/debug/vars", "expvar debug endpoint", "medium"),
        ("/trace", "django debug", "medium"),
        ("/admin/config", "admin config", "info"),
        ("/phpinfo.php", "phpinfo", "medium"),
        ("/info.php", "phpinfo", "medium"),
        ("/cgi-bin/test-cgi", "cgi test", "low"),
        ("/elmah.axd", "error log viewer", "medium"),
        ("/.svn/wc.db", "svn metadata", "medium"),
    ]

    def options(self):
        return {"target": "base URL"}

    def run(self):
        _s, _h, _p, base = U.normalize_target(self._target())
        self.info("probing %d sensitive paths ..." % len(self.PATHS))

        def job(item):
            path, label, sev = item
            r = U.http_request(U.build_url(base, path), timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok or r.status >= 500:
                return None
            return (path, label, sev, r.status, len(r.body), r.body[:600])

        results = U.worker_pool(self.PATHS, job, threads=max(2, self.ctx.threads))
        for path, label, sev, code, length, body in results:
            if code in (404, 410):
                continue
            color = {"critical": C.BRIGHT_MAGENTA, "high": C.BRIGHT_RED,
                     "medium": C.BRIGHT_YELLOW, "low": C.CYAN,
                     "info": C.BRIGHT_BLACK}[sev]
            print("   %s %-3s %-24s %-26s len=%d" % (
                C.c("[*]", C.BOLD), C.c(str(code), color), path, label, length))
            if sev == "info":
                continue
            # quick content heuristics to cut false positives
            low = body.lower()
            if path.endswith(".env") and ("=" in body and len(body) > 8):
                self.add_finding("Environment file exposed: %s" % path, sev, base + path,
                                 body[:400], tip="Secrets in .env can leak API keys and DB passwords.",
                                 cwe="CWE-200")
            elif path.startswith("/.git/") and ("ref" in low or "gitdir" in low or "[core]" in low):
                self.add_finding("Git repository exposed: %s" % path, sev, base + path,
                                 body[:400], tip="Recover source and secrets via git objects.",
                                 cwe="CWE-538")
            elif "heapdump" in path:
                self.add_finding("Spring heapdump exposed", "critical", base + path,
                                 "HTTP %s, %d bytes - heap dumps contain session/credentials" % (code, length),
                                 tip="Download and analyze for secrets.", cwe="CWE-532")
            elif code == 200 and length > 20 and label not in ("robots file", "sitemap",
                                                               "security contact", "API docs",
                                                               "dependency list"):
                self.add_finding("Sensitive path exposed: %s (%s)" % (path, label),
                                 sev, base + path, "HTTP %s, len %d, snippet: %s" % (
                                     code, length, U.strip_html(body)[:250]),
                                 tip="Verify manually and report if real data is exposed.",
                                 cwe="CWE-538")
        self.output({"base": base, "hits": [r[:5] for r in results if r]})
        return "sensitive file probe finished"

    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        return t


class ParamMinerModule(BaseModule):
    NAME = "param_miner"
    DESCRIPTION = ("Mine hidden GET/POST parameters via common names + response "
                   "diff (len/status/reflect) against baseline")
    CATEGORY = "web"

    PARAMS = ["debug", "test", "admin", "id", "user", "page", "file", "path",
              "url", "redirect", "next", "goto", "return", "returnurl", "rurl",
              "callback", "continue", "dest", "ref", "referer", "lang", "theme",
              "template", "preview", "view", "edit", "delete", "token", "auth",
              "apikey", "api_key", "key", "secret", "access_token", "session",
              "sid", "email", "username", "role", "level", "status", "type",
              "action", "cmd", "exec", "command", "query", "q", "search",
              "sort", "order", "limit", "offset", "start", "debug2", "logged_in",
              "is_admin", "admin_panel", "su", "root", "sudo", "export",
              "download", "read", "show", "include", "inc", "load", "cat",
              "src", "doc", "config", "setting", "settings", "options", "opt"]

    def options(self):
        return {"target": "full URL to fuzz (with or without existing params)",
                "method": "GET (default) or POST"}

    def run(self):
        raw = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not raw:
            raise ModuleError("set 'target' option")
        method = (self.ctx.get_option("method", "GET") or "GET").upper()
        base = raw.split("?")[0]
        sep = "&" if "?" in raw else "?"
        r_base = U.http_request(raw, timeout=self.ctx.timeout, method=method,
                                data="x=1" if method == "POST" else None,
                                user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                                verify=self.ctx.verify_tls)
        bl_status, bl_len = r_base.status, len(r_base.body)
        self.info("baseline: HTTP %s, len %d" % (bl_status, bl_len))
        found = []

        def job(p):
            url = "%s%s%s=%s" % (base, sep, p, "tveyeprobe1")
            r = U.http_request(url, timeout=self.ctx.timeout, method=method,
                               data=("%s=tveyeprobe1" % p) if method == "POST" else None,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            if not r.ok:
                return None
            diff_len = abs(len(r.body) - bl_len)
            interesting = []
            if r.status != bl_status:
                interesting.append("status %s->%s" % (bl_status, r.status))
            if diff_len > 40:
                interesting.append("len delta %d" % diff_len)
            if "tveyeprobe1" in r.body:
                interesting.append("reflected")
            if interesting:
                return p, r.status, "; ".join(interesting)
            return None

        results = U.worker_pool(self.PARAMS, job, threads=max(2, self.ctx.threads))
        for res in results:
            if res:
                found.append(res)
                print("   %s %-16s %s" % (C.c("PARAM", C.BOLD),
                                          C.c(res[0], C.BRIGHT_GREEN, C.BOLD), res[2]))
        self.output({"url": raw, "interesting_params": found})
        self.success("param_miner: %d interesting parameters" % len(found))
        return "param mining finished (%d hits)" % len(found)
