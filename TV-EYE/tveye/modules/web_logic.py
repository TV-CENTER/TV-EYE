"""Application logic modules: JWT, GraphQL, rate limiting, IDOR helpers."""

import base64
import json
import re
import time
import urllib.parse

from ..core import BaseModule, ModuleError
from .. import util as U
from .. import colors as C


class JwtAuditModule(BaseModule):
    NAME = "jwt_audit"
    DESCRIPTION = ("Decode + audit JWTs: algorithm confusion (none), weak HMAC "
                   "secret brute, kid injection hint, expired tokens")
    CATEGORY = "logic"

    WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt_secret",
                    "secretkey", "your-256-bit-secret", "supersecret", "key",
                    "test", "dev", "admin", "qwerty", "letmein", "abcdefghijklmnopqrstuvwxyz",
                    "tveye", "shhh", "s3cr3t", "topsecret", "hunter2", "iloveyou",
                    "default", "null", "undefined", "falsy", "example"]

    def options(self):
        return {"token": "JWT string to analyze",
                "target": "optional URL to fetch a JWT from (Authorization header)"}

    def run(self):
        token = self.ctx.get_option("token", "")
        if not token and self.ctx.get_option("target"):
            base = self.ctx.get_option("target")
            r = U.http_request(base, timeout=self.ctx.timeout,
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls)
            if r.ok:
                m = re.search(r"ey[A-Za-z0-9_-]{6,}\.[eyA-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
                              r.body)
                if m:
                    token = m.group(0)
                    self.info("extracted candidate JWT from response body")
        if not token:
            raise ModuleError("no token: set 'token' option or 'target' to auto-extract")
        token = token.strip().replace("Bearer ", "")
        parts = token.split(".")
        if len(parts) < 2:
            raise ModuleError("not a JWT (expected 3 dot-separated segments)")
        header, payload = {}, {}
        try:
            header = json.loads(U.b64d(parts[0]))
            payload = json.loads(U.b64d(parts[1]))
        except Exception as exc:
            raise ModuleError("base64/JSON decode failed: %s" % exc)
        print("   " + C.c("HEADER:", C.BRIGHT_CYAN) + " %s" % json.dumps(header, indent=2)[:400].replace("\n", "\n    "))
        print("   " + C.c("PAYLOAD:", C.BRIGHT_CYAN) + " %s" % json.dumps(payload, indent=2)[:600].replace("\n", "\n    "))
        alg = str(header.get("alg", "?"))
        issues = []
        if alg.lower() == "none":
            issues.append(("JWT uses alg:none - signature not verified", "critical", "CWE-347"))
        if "jku" in header or "x5u" in header:
            issues.append(("Header contains jku/x5u - possible key-injection vector",
                           "medium", "CWE-347"))
        if "kid" in header:
            if "../" in str(header["kid"]) or "://" in str(header["kid"]):
                issues.append(("kid looks injectable/path-controlled", "high", "CWE-347"))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp * 1.0 < time.time():
            issues.append(("Token is expired", "info", None))
        if isinstance(payload.get("iat"), (int, float)) and isinstance(payload.get("exp"), (int, float)):
            if payload["exp"] - payload["iat"] > 31536000:
                issues.append(("Token lifetime > 1 year", "low", "CWE-613"))
        if alg.startswith("HS") and parts[2]:
            self.info("weak-secret brute force (%d candidates, HMAC)..." % len(self.WEAK_SECRETS))
            import hashlib
            import hmac as hmaclib
            sig = U.b64e(parts[0] + "." + parts[1])  # not the actual sig; compute properly
            sig_b64 = parts[2].rstrip("=")
            for cand in self.WEAK_SECRETS:
                key = cand.encode()
                mac = hmaclib.new(key, ("%s.%s" % (parts[0], parts[1])).encode(),
                                  hashlib.sha256).digest()
                if U.b64e(mac).rstrip("=") == sig_b64:
                    issues.append(("JWT signing secret is weak: '%s'" % cand, "critical",
                                   "CWE-321"))
                    break
        for msg, sev, cwe in issues:
            self.add_finding(msg, sev, "jwt", "token header: %s" % json.dumps(header),
                             tip="Review JWT handling; sign with strong keys, verify alg.",
                             cwe=cwe)
            self.warn("JWT issue: %s (%s)" % (msg, sev))
        if not issues:
            self.success("no obvious JWT issues detected")
        self.output({"header": header, "payload": payload, "issues": [i[0] for i in issues]})
        return "jwt audit finished (%d issues)" % len(issues)


class GraphqlScanModule(BaseModule):
    NAME = "graphql_scan"
    DESCRIPTION = ("GraphQL recon: endpoint discovery, introspection check, "
                   "field suggestion probes")
    CATEGORY = "logic"
    REQUIRED = ["target"]

    PATHS = ["/graphql", "/graphql/console", "/graphiql", "/api/graphql",
             "/gql", "/query", "/graphql/schema.json", "/api/graphiql",
             "/v1/graphql", "/v2/graphql", "/graphql/dev"]

    def options(self):
        return {"target": "site base URL or direct graphql endpoint"}

    def run(self):
        _s, _h, _p, base = U.normalize_target(self._target())
        endpoints = []
        base_ep = self.ctx.get_option("target")
        if base_ep and "/graphql" in base_ep.lower():
            endpoints.append(base_ep)
        for p in self.PATHS:
            endpoints.append(U.build_url(base, p))
        live = []
        introspection_open = False
        for ep in endpoints:
            r = U.http_request(ep, method="POST", data='{"query":"{ __typename }"}',
                               headers={"Content-Type": "application/json"},
                               timeout=self.ctx.timeout, user_agent=self.ctx.user_agent,
                               cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
            if r.ok and r.status < 500:
                live.append((ep, r.status, r.body[:120]))
                self.info("endpoint responds: %s (HTTP %s)" % (ep, r.status))
                if '"__typename"' in r.body or "__typename" in r.body:
                    # introspection check
                    q = '{"query":"{ __schema { queryType { name } } }"}'
                    r2 = U.http_request(ep, method="POST", data=q,
                                        headers={"Content-Type": "application/json"},
                                        timeout=self.ctx.timeout,
                                        user_agent=self.ctx.user_agent,
                                        cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
                    if r2.ok and "__schema" in r2.body and "queryType" in r2.body:
                        introspection_open = True
                        self.add_finding(
                            "GraphQL introspection enabled: %s" % ep, "medium", ep,
                            "Introspection query returned schema metadata:\n%s" % r2.body[:400],
                            tip="Introspection discloses the full API surface; disable in prod.",
                            cwe="CWE-200")
                    # field suggestion check
                    r3 = U.http_request(ep, method="POST",
                                        data='{"query":"{ __typenamexyz }"}',
                                        headers={"Content-Type": "application/json"},
                                        timeout=self.ctx.timeout,
                                        user_agent=self.ctx.user_agent,
                                        cookie=self.ctx.cookie, verify=self.ctx.verify_tls)
                    if r3.ok and "Did you mean" in r3.body:
                        self.add_finding(
                            "GraphQL field suggestions leak schema: %s" % ep, "low", ep,
                            "Error contains 'Did you mean' suggestions:\n%s" % r3.body[:300],
                            tip="Disable suggestion leak in production builds.",
                            cwe="CWE-209")
        if not live:
            self.warn("no GraphQL endpoint found at common paths")
        self.output({"base": base, "live": live, "introspection": introspection_open})
        self.success("graphql_scan done: %d live endpoint(s)" % len(live))
        return "graphql scan finished"

    def _target(self):
        t = self.ctx.get_option("target") or (self.ctx.targets[0] if self.ctx.targets else None)
        if not t:
            raise ModuleError("set 'target' option")
        return t


class RateLimitModule(BaseModule):
    NAME = "rate_limit_check"
    DESCRIPTION = ("Test rate limiting/lockout on login or OTP endpoints "
                   "(only against accounts you own)")
    CATEGORY = "logic"
    REQUIRED = ["target"]

    def options(self):
        return {
            "target": "login/OTP endpoint URL",
            "body": "POST body template, use {USER} and {PASS} placeholders",
            "count": "number of attempts (default 20)",
            "username": "test username you own",
            "password": "wrong password to use",
        }

    def run(self):
        url = self.ctx.get_option("target")
        body = self.ctx.get_option("body", "username={USER}&password={PASS}")
        count = int(self.ctx.get_option("count", 20))
        user = self.ctx.get_option("username", "tveye_test_user")
        pwd = self.ctx.get_option("password", "wrongpass123")
        user = self.ctx.get_option("username", "tveye_test_user") or user
        self.info("rate-limit test: %d attempts to %s" % (count, url))
        codes = {}
        lens = {}
        for i in range(count):
            data = body.replace("{USER}", user).replace("{PASS}", pwd)
            r = U.http_request(url, method="POST", data=data, timeout=self.ctx.timeout,
                               headers={"Content-Type": "application/x-www-form-urlencoded",
                                        "X-Forwarded-For": "10.%d.%d.%d" % (
                                            i // 256 % 256, i % 256, 7)},
                               user_agent=self.ctx.user_agent, cookie=self.ctx.cookie,
                               verify=self.ctx.verify_tls, retries=0)
            codes[r.status] = codes.get(r.status, 0) + 1
            lens[r.status] = len(r.body)
            if r.status == 429:
                self.success("HTTP 429 received at attempt %d (rate limit enforced)" % (i + 1))
                break
            time.sleep(0.15)
        self.output({"url": url, "attempts": count, "status_counts": codes})
        if 429 in codes:
            self.success("rate limiting appears enforced (429 present)")
        elif len(codes) == 1 and list(codes)[0] in (200, 302, 401, 403):
            self.add_finding(
                "No rate limiting observed after %d attempts" % count, "medium", url,
                "All %d attempts returned: %s" % (count, codes),
                tip="Verify lockout/CAPTCHA; brute-forceable credentials are CWE-307.",
                cwe="CWE-307")
        else:
            self.info("mixed responses: %s (analyze manually)" % codes)
        return "rate limit test finished"


class IdorHunterModule(BaseModule):
    NAME = "idor_hunt"
    DESCRIPTION = ("IDOR helper: compare two sessions' access to object IDs "
                   "(requires 2 cookies) - classic BOLA/IDOR testing")
    CATEGORY = "logic"

    def options(self):
        return {
            "url": "object URL template with {ID} placeholder",
            "ids": "comma separated object IDs to test",
            "cookie_a": "cookie/header of account A (owner)",
            "cookie_b": "cookie/header of account B (attacker)",
        }

    def run(self):
        url = self.ctx.get_option("url")
        ids = [i.strip() for i in (self.ctx.get_option("ids", "") or "").split(",") if i.strip()]
        ca = self.ctx.get_option("cookie_a")
        cb = self.ctx.get_option("cookie_b")
        if not url or "{ID}" not in url or not ids:
            raise ModuleError("need url with {ID} and ids list")
        if not ca and not cb:
            raise ModuleError("provide cookie_a (owner) and optionally cookie_b (attacker)")
        self.info("IDOR comparison across %d ids" % len(ids))
        rows = []

        def fetch(u, cookie):
            return U.http_request(u, timeout=self.ctx.timeout,
                                  user_agent=self.ctx.user_agent, cookie=cookie,
                                  verify=self.ctx.verify_tls)

        for oid in ids:
            ra = fetch(url.replace("{ID}", oid), ca)
            rb = fetch(url.replace("{ID}", oid), cb) if cb else None
            a_ok = ra.ok and ra.status == 200
            b_ok = rb.ok and rb.status == 200 if rb else False
            same = (a_ok and b_ok and
                    self._sig(ra.body) == self._sig(rb.body))
            rows.append((oid, ra.status, rb.status if rb else "-",
                         "SAME" if same else ("B-OK" if b_ok else "diff")))
            print("   id=%-10s A:%s B:%s -> %s" % (
                oid, ra.status, rb.status if rb else "-", rows[-1][3]))
            if b_ok and not same and a_ok:
                self.add_finding(
                    "Possible IDOR: object %s readable by second account" % oid,
                    "high", url.replace("{ID}", oid),
                    "Account A status %s (len %d)\nAccount B status %s (len %d)\n"
                    "Bodies differ but B received 200." % (
                        ra.status, len(ra.body), rb.status, len(rb.body)),
                    tip="Confirm B lacks authorization; diff exact objects.",
                    cwe="CWE-639")
            elif same and cb and a_ok:
                self.add_finding(
                    "Possible IDOR: object %s served identically to both accounts" % oid,
                    "medium", url.replace("{ID}", oid),
                    "Both accounts received HTTP 200 with identical body signature.",
                    tip="Verify object ownership and sensitivity.",
                    cwe="CWE-639")
        self.output({"url": url, "rows": rows})
        return "idor hunt finished"

    def _sig(self, body):
        return U.md5(U.strip_html(body)[:8000].strip()[:2000])
