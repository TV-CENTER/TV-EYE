"""Shared runtime context passed to every TV-EYE module."""

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

from . import colors as C


class Context(object):
    """Global state: options, workspace, targets, findings, outputs, console."""

    def __init__(self):
        self.options = {}
        self.workspace = os.getcwd()
        self.targets = []
        self.findings = []
        self.outputs = {}
        self.commands = []  # (timestamp, command) history
        self.threads = 10
        self.timeout = 10.0
        self.proxy = None
        self.user_agent = "TV-EYE/1.0 (Author: Mr_TV; +https://github.com/TV-CENTER)"
        self.cookie = None
        self.headers_extra = {}
        self.delay = 0.0
        self.retries = 1
        self.verify_tls = True
        self.offline = False
        self.verbose = True
        self._lock = threading.Lock()
        self.started_at = time.time()

    # -------------------------------------------------------------- options
    def set_option(self, key, value):
        self.options[key] = value
        # live-sync special options
        if key == "threads":
            try:
                self.threads = max(1, int(value))
            except (TypeError, ValueError):
                pass
        elif key == "timeout":
            try:
                self.timeout = float(value)
            except (TypeError, ValueError):
                pass
        elif key == "proxy":
            self.proxy = value or None
        elif key == "user-agent":
            self.user_agent = value
        elif key == "cookie":
            self.cookie = value or None
        elif key == "delay":
            try:
                self.delay = max(0.0, float(value))
            except (TypeError, ValueError):
                pass
        elif key == "retries":
            try:
                self.retries = max(0, int(value))
            except (TypeError, ValueError):
                pass
        elif key == "verify-tls":
            self.verify_tls = str(value).lower() not in ("0", "false", "no", "off")
        elif key == "offline":
            self.offline = str(value).lower() in ("1", "true", "yes", "on")

    def get_option(self, key, default=None):
        v = self.options.get(key)
        if v in (None, ""):
            return default
        return v

    def get_option_list(self, key):
        """Options like target/domains can hold comma separated lists."""
        v = self.options.get(key)
        if not v:
            return []
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if str(x).strip()]
        return [p.strip() for p in str(v).split(",") if p.strip()]

    # ------------------------------------------------------------- printing
    def info(self, msg):
        print(C.c("[*] ", C.BRIGHT_CYAN, C.BOLD) + C.c(str(msg), C.WHITE))

    def success(self, msg):
        print(C.c("[+] ", C.BRIGHT_GREEN, C.BOLD) + C.c(str(msg), C.GREEN))

    def warn(self, msg):
        print(C.c("[!] ", C.BRIGHT_YELLOW, C.BOLD) + C.c(str(msg), C.YELLOW))

    def error(self, msg):
        print(C.c("[-] ", C.BRIGHT_RED, C.BOLD) + C.c(str(msg), C.RED))

    def debug(self, msg):
        if self.verbose:
            print(C.c("[dbg] ", C.BRIGHT_BLACK) + C.c(str(msg), C.BRIGHT_BLACK))

    def table(self, headers, rows):
        if not rows:
            self.info("no results")
            return
        widths = [len(str(h)) for h in headers]
        srows = [[str(c0) for c0 in r] for r in rows]
        for r in srows:
            for i, cell in enumerate(r):
                if i < len(widths):
                    widths[i] = min(max(widths[i], len(cell)), 60)
        def line(ch="-", j="|"):
            return " " + j + j.join([ch * (w + 2) for w in widths]) + j
        def row(cells, j="|"):
            return (" " + j + j.join(
                [" " + c0.ljust(widths[i]) + " " for i, c0 in enumerate(cells)]
            ) + j).rstrip()
        print(line())
        print(C.c(row(headers), C.BRIGHT_CYAN, C.BOLD))
        print(line("="))
        for r in srows:
            print(row(r))
        print(line())

    # -------------------------------------------------------------- targets
    def add_target(self, t):
        t = str(t).strip().rstrip("/")
        if t and t not in self.targets:
            self.targets.append(t)
            self.success("target added: %s" % C.c(t, C.BOLD))
            return True
        return False

    def clear_targets(self):
        self.targets = []
        self.success("target list cleared")

    # ------------------------------------------------------------- findings
    SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def add_finding(self, title, severity, target, evidence, tip=None, cwe=None):
        sev = (severity or "info").lower()
        if sev not in self.SEV_ORDER:
            sev = "info"
        finding = {
            "id": len(self.findings) + 1,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": str(title)[:300],
            "severity": sev,
            "target": str(target)[:400],
            "evidence": str(evidence)[:3000],
            "tip": str(tip)[:600] if tip else "",
            "cwe": str(cwe)[:80] if cwe else "",
        }
        with self._lock:
            self.findings.append(finding)
        color = {
            "critical": C.BRIGHT_MAGENTA,
            "high": C.BRIGHT_RED,
            "medium": C.BRIGHT_YELLOW,
            "low": C.CYAN,
            "info": C.BRIGHT_BLACK,
        }[sev]
        print(
            C.c("  [FINDING #%d] " % finding["id"], color, C.BOLD)
            + C.c("%s - %s" % (sev.upper(), title), color)
        )
        return finding

    def findings_sorted(self):
        return sorted(
            self.findings,
            key=lambda f: (-self.SEV_ORDER.get(f["severity"], 0), f["id"]),
        )

    def summary(self):
        counts = {s: 0 for s in self.SEV_ORDER}
        for f in self.findings:
            counts[f["severity"]] += 1
        return counts

    def add_output(self, module, data):
        with self._lock:
            self.outputs.setdefault(module, [])
            self.outputs[module].append(data)

    # ------------------------------------------------------------- persistence
    def session_path(self, name):
        return os.path.join(self.workspace, name)

    def save_session(self, name="tveye-session.json"):
        path = self.session_path(name)
        data = {
            "tool": "TV-EYE 1.0.0 (Mr_TV)",
            "saved": datetime.now(timezone.utc).isoformat(),
            "workspace": self.workspace,
            "options": dict(self.options),
            "targets": list(self.targets),
            "findings": self.findings,
            "elapsed_sec": round(time.time() - self.started_at, 1),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        self.success("session saved -> %s" % path)
        return path

    def load_session(self, name="tveye-session.json"):
        path = self.session_path(name)
        if not os.path.exists(path):
            self.error("session file not found: %s" % path)
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            self.error("session load failed: %s" % exc)
            return False
        self.options = data.get("options", {})
        self.targets = data.get("targets", [])
        self.findings = data.get("findings", [])
        for k in ("threads", "timeout", "proxy", "user-agent", "cookie", "delay",
                  "retries", "verify-tls", "offline"):
            if k in self.options:
                self.set_option(k, self.options[k])
        self.success("session loaded: %d targets, %d findings" % (
            len(self.targets), len(self.findings)))
        return True

    def clear_findings(self):
        self.findings = []
        self.success("findings cleared")

    def findings_path(self, name):
        if not os.path.isabs(name):
            name = os.path.join(self.workspace, name)
        return name
