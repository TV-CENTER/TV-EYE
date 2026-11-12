"""Interactive console for TV-EYE (command-driven, like pro pentest suites)."""

import os
import shlex
import shutil
import subprocess
import sys
import time
import platform as plat

from . import colors as C
from . import core, logo
from . import report as REP
from . import util as U
from . import __version__, __author__, __telegram__, __github__
from .context import Context
from .core import BaseModule, ModuleError

AUTHOR_INFO = (
    "  %-14s %s\n"
    "  %-14s %s\n"
    "  %-14s %s"
) % ("Author:", "Mr_TV", "Telegram:", "@Mr_TV_ir", "GitHub:", __github__)

LEGAL_NOTE = (
    "TV-EYE is built for AUTHORIZED security work only:\n"
    "  - bug bounty testing inside published program scope\n"
    "  - penetration tests with written permission\n"
    "  - your own lab and infrastructure\n"
    "Anything outside explicit permission is illegal. You are responsible\n"
    "for how you use this tool."
)

BUILTIN_TOOL_CHECK = ["nmap", "nikto", "sqlmap", "ffuf", "gobuster", "dirb",
                      "whatweb", "hydra", "wpscan", "amass", "masscan", "curl"]

SPECIAL_OPTIONS = {
    "threads", "timeout", "proxy", "user-agent", "cookie", "delay", "retries",
    "verify-tls", "offline", "verbose",
}


def color_of(prompt="TV-EYE"):
    return C.c("[ ", C.BRIGHT_MAGENTA) + C.c(prompt, C.BRIGHT_CYAN, C.BOLD) + \
        C.c(" ] > ", C.BRIGHT_MAGENTA)


class Console(object):
    def __init__(self):
        self.ctx = Context()
        self.current = None
        self.running = True
        C.enable()
        C.enable_windows_vt()

    # ----------------------------------------------------------------- entry
    def start(self, banner=True):
        if banner:
            print(core.banner())
        self.ctx.info("TV-EYE v%s loaded - type 'help' to see commands" % __version__)
        self.loop()

    def loop(self):
        while self.running:
            try:
                line = input(color_of()).strip()
            except (EOFError, KeyboardInterrupt):
                print("")
                self.cmd_exit()
                break
            if not line:
                continue
            try:
                if line.startswith("!"):
                    self.cmd_shell([line[1:]])
                    continue
                self.dispatch(line)
            except KeyboardInterrupt:
                print("")
                self.ctx.warn("interrupted (module aborted)")
            except ModuleError as exc:
                self.ctx.error(str(exc))
            except Exception as exc:
                self.ctx.error("console error: %s" % exc)
                self.ctx.debug(repr(exc))

    # ------------------------------------------------------------- dispatch
    def dispatch(self, line):
        self.ctx.commands.append((time.strftime("%H:%M:%S"), line))
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        handler = getattr(self, "cmd_%s" % cmd.replace("-", "_").replace(".", "_"), None)
        if handler:
            handler(args)
        else:
            self.ctx.error("unknown command '%s' - try 'help'" % cmd)

    # ------------------------------------------------------------- commands
    def cmd_help(self, args):
        topics = {
            "core": [
                ("help [cmd]", "show this help"),
                ("banner", "reprint the TV-EYE logo"),
                ("clear", "clear the screen"),
                ("exit | quit | q", "leave the console"),
                ("history", "show command history"),
                ("sysinfo", "host + python information"),
                ("tools", "list external tools available (nmap, sqlmap...)"),
                ("shell <cmd> | ! <cmd>", "run an OS command"),
            ],
            "targets": [
                ("target add <url|host|ip>", "add a target (URL, host or IP)"),
                ("target list", "list current targets"),
                ("target clear", "empty the target list"),
                ("workspace <path>", "set output workspace directory"),
            ],
            "modules": [
                ("modules", "list every module (grouped by category)"),
                ("modules <category>", "list modules in one category"),
                ("search <keyword>", "find modules matching a keyword"),
                ("use <module>", "select the active module"),
                ("info <module>", "show module description + options"),
                ("set <option> <value>", "set an option for the active module"),
                ("run", "execute the active module"),
                ("run <module>", "execute a module directly"),
            ],
            "offense": [
                ("quick <target>", "fast recon chain (dns, tech, headers, secrets)"),
                ("deep <target>", "adds subdomain enum + dir buster + port scan"),
                ("selftest", "offline self-test against the built-in safe lab"),
                ("findings", "show all findings sorted by severity"),
                ("findings clear", "drop all findings"),
                ("report md|html|json|all [name]", "write a report file"),
                ("save [name]", "save session to workspace"),
                ("load [name]", "load a session"),
                ("status", "options, targets and finding summary"),
            ],
            "misc": [
                ("authors", "tool author information"),
                ("legal", "authorized-use policy reminder"),
                ("version", "show tool version"),
            ],
        }
        for section, rows in topics.items():
            print(C.c("\n[%s]" % section.upper(), C.BRIGHT_MAGENTA, C.BOLD))
            for cmd, desc in rows:
                print("  %-34s %s" % (C.c(cmd, C.BRIGHT_CYAN, C.BOLD), desc))
        print("")

    def cmd_banner(self, args):
        print(core.banner())

    def cmd_clear(self, args):
        os.system("cls" if os.name == "nt" else "clear")

    def cmd_exit(self, args=None):
        print(C.c("goodbye from TV-EYE - hack responsibly!", C.BRIGHT_MAGENTA, C.BOLD))
        self.running = False

    cmd_quit = cmd_exit
    cmd_q = cmd_exit

    def cmd_history(self, args):
        for t, c0 in self.ctx.commands[-30:]:
            print("  %s  %s" % (C.c(t, C.BRIGHT_BLACK), c0))

    def cmd_sysinfo(self, args):
        self.ctx.info("system information")
        rows = [
            ("TV-EYE", "%s (author %s)" % (__version__, __author__)),
            ("OS", "%s %s" % (plat.system(), plat.release())),
            ("Kernel", plat.version()[:60]),
            ("Python", sys.version.split()[0]),
            ("Machine", plat.machine()),
            ("Workspace", self.ctx.workspace),
        ]
        for k, v in rows:
            print("   %-12s %s" % (C.c(k + ":", C.BRIGHT_CYAN), v))

    def cmd_tools(self, args):
        self.ctx.info("checking external tools (optional integrations)...")
        found, missing = [], []
        for t in BUILTIN_TOOL_CHECK:
            p = shutil.which(t)
            if p:
                found.append((t, p))
                print("   %-12s %s %s" % (C.c(t, C.BRIGHT_GREEN, C.BOLD), "ok ->", p))
            else:
                missing.append(t)
                print("   %-12s %s" % (C.c(t, C.BRIGHT_BLACK), "not installed"))
        self.ctx.info("%d available, %d missing (TV-EYE works fully without them)"
                      % (len(found), len(missing)))

    def cmd_shell(self, args):
        if not args:
            raise ModuleError("usage: shell <os-command>")
        cmd = " ".join(args)
        self.ctx.warn("executing OS command: %s" % cmd)
        try:
            rc = os.system(cmd)
            self.ctx.info("exit code: %s" % rc)
        except Exception as exc:
            self.ctx.error("shell failed: %s" % exc)

    def cmd_target(self, args):
        if not args:
            raise ModuleError("usage: target add|list|clear <value>")
        sub = args[0].lower()
        if sub == "add" and len(args) > 1:
            for t in args[1:]:
                self.ctx.add_target(t)
        elif sub == "list":
            if not self.ctx.targets:
                self.ctx.info("no targets yet - use: target add <url>")
            for i, t in enumerate(self.ctx.targets, 1):
                print("   %d. %s" % (i, C.c(t, C.BOLD)))
        elif sub == "clear":
            self.ctx.clear_targets()
        else:
            raise ModuleError("usage: target add|list|clear <value>")

    def cmd_workspace(self, args):
        if not args:
            self.ctx.info("workspace: %s" % self.ctx.workspace)
            return
        path = args[0]
        try:
            os.makedirs(path, exist_ok=True)
            self.ctx.workspace = os.path.abspath(path)
            self.ctx.success("workspace set: %s" % self.ctx.workspace)
        except Exception as exc:
            self.ctx.error("cannot set workspace: %s" % exc)

    def cmd_modules(self, args):
        mods = core.modules()
        if not mods:
            self.ctx.error("no modules loaded")
            return
        cats = core.categories()
        if args:
            want = args[0].lower()
            cats = {k: v for k, v in cats.items() if k.lower() == want}
            if not cats:
                self.ctx.error("no such category: %s" % want)
                return
        total = 0
        for cat, names in sorted(cats.items()):
            print(C.c("\n  [%s]" % cat.upper(), C.BRIGHT_MAGENTA, C.BOLD))
            for n in names:
                cls = mods[n]
                total += 1
                print("    %-22s %s" % (C.c(n, C.BRIGHT_CYAN, C.BOLD), cls.DESCRIPTION[:66]))
        print("")
        self.ctx.success("%d modules available" % len(mods))

    def cmd_search(self, args):
        if not args:
            raise ModuleError("usage: search <keyword>")
        kw = args[0].lower()
        mods = core.modules()
        found = [(n, c) for n, c in sorted(mods.items())
                 if kw in n.lower() or kw in c.DESCRIPTION.lower() or kw in c.CATEGORY.lower()]
        if not found:
            self.ctx.warn("no module matches '%s'" % kw)
            return
        for n, c in found:
            print("   %-22s [%s] %s" % (C.c(n, C.BRIGHT_CYAN, C.BOLD), c.CATEGORY,
                                        c.DESCRIPTION[:70]))

    def cmd_use(self, args):
        if not args:
            raise ModuleError("usage: use <module>  (see 'modules')")
        cls = core.get_module_class(args[0])
        if not cls:
            raise ModuleError("unknown module: %s" % args[0])
        self.current = cls
        self.ctx.success("module selected: %s" % C.c(cls.NAME, C.BOLD))
        self.ctx.info(cls.DESCRIPTION)
        inst = cls(self.ctx)
        opts = inst.options()
        if opts:
            self.ctx.info("options:")
            for k, v in opts.items():
                cur = self.ctx.get_option(k)
                shown = "(%s)" % cur if cur else ""
                print("    %-16s %-60s %s" % (C.c(k, C.BRIGHT_YELLOW), v, C.c(shown, C.BRIGHT_BLACK)))
        req = getattr(cls, "REQUIRED", [])
        if req:
            self.ctx.info("required: %s" % ", ".join(C.c(r, C.BRIGHT_RED, C.BOLD) for r in req))

    def cmd_info(self, args):
        if not args:
            if self.current:
                args = [self.current.NAME]
            else:
                raise ModuleError("usage: info <module>")
        cls = core.get_module_class(args[0])
        if not cls:
            raise ModuleError("unknown module: %s" % args[0])
        print(C.c("\n  Module    :", C.BRIGHT_CYAN) + " %s" % cls.NAME)
        print(C.c("  Category  :", C.BRIGHT_CYAN) + " %s" % cls.CATEGORY)
        print(C.c("  Desc      :", C.BRIGHT_CYAN) + " %s" % cls.DESCRIPTION)
        inst = cls(self.ctx)
        opts = inst.options()
        req = getattr(cls, "REQUIRED", [])
        if opts:
            print(C.c("  Options   :", C.BRIGHT_CYAN))
            for k, v in opts.items():
                cur = self.ctx.get_option(k)
                print("    %-18s %s %s" % (k, v, C.c("(=%s)" % cur if cur else "",
                                                        C.BRIGHT_BLACK)))
        if req:
            print(C.c("  Required  :", C.BRIGHT_CYAN) + " %s" % ", ".join(req))
        print("")

    def cmd_set(self, args):
        if len(args) < 2:
            raise ModuleError("usage: set <option> <value>")
        key, value = args[0], " ".join(args[1:])
        self.ctx.set_option(key, value)
        if key in SPECIAL_OPTIONS:
            self.ctx.success("%s = %s (global)" % (key, value))
        else:
            self.ctx.success("%s = %s" % (key, value))

    def cmd_run(self, args):
        modname = args[0] if args else (self.current.NAME if self.current else None)
        if not modname:
            raise ModuleError("usage: run <module>  (or 'use <module>' first)")
        self.ctx.info("running module %s ..." % C.c(modname, C.BOLD))
        t0 = time.time()
        ok, msg = core.execute(modname, self.ctx)
        dt = time.time() - t0
        if ok:
            self.ctx.success("%s (%.2fs)" % (msg, dt))
        else:
            self.ctx.error(msg)

    cmd_exploit = cmd_run

    def cmd_quick(self, args):
        if not args:
            raise ModuleError("usage: quick <target>")
        self._chain(args[0], ["dns_recon", "tech_fingerprint", "security_headers",
                              "sensitive_files", "js_secrets"], "QUICK")

    def cmd_deep(self, args):
        if not args:
            raise ModuleError("usage: deep <target>")
        self._chain(args[0], ["subdomain_enum", "dns_recon", "tech_fingerprint",
                              "security_headers", "sensitive_files", "dir_buster",
                              "port_scan"], "DEEP")

    def cmd_selftest(self, args):
        """Run the whole scanner stack against the built-in safe local lab."""
        import importlib
        lab_mod = importlib.import_module("tests.local_vuln_server")
        lab = lab_mod.LabServer()
        port = lab.start()
        target = "http://127.0.0.1:%d" % port
        self.ctx.warn("self-test lab started at %s (offline, safe, fake data)" % target)
        self.ctx.set_option("threads", 10)
        self.ctx.set_option("timeout", 5)
        base_ctx_findings = len(self.ctx.findings)
        plan = [
            ("tech_fingerprint", {"target": target}),
            ("security_headers", {"target": target}),
            ("sensitive_files", {"target": target}),
            ("js_secrets", {"target": target}),
            ("param_miner", {"target": target + "/search?q=1"}),
            ("xss_scan", {"target": target + "/search?q=1"}),
            ("sqli_scan", {"target": target + "/item?id=3"}),
            ("lfi_scan", {"target": target + "/view?page=about"}),
            ("ssti_scan", {"target": target + "/template?name=x"}),
            ("open_redirect", {"target": target + "/redirect?next=/"}),
            ("cors_scan", {"target": target}),
            ("graphql_scan", {"target": target}),
            ("login_brute", {"target": target + "/login",
                              "body": "username={USER}&password={PASS}",
                              "users": "admin,tveyeowner,guest",
                              "passwords": "admin,labpass,password123",
                              "success": "Welcome back", "delay": "0.05"}),
            ("port_scan", {"target": "127.0.0.1", "ports": str(port)}),
            ("jwt_audit", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                   "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                                   "7d0C1fEgM9vJpLqK7rXwZo8yTn3bVcA5uS2hD6mGxQo"}),
            ("hash_id", {"value": "admin123"}),
            ("header_gen", {"domain": "example.com"}),
            ("payload_gen", {}),
        ]
        try:
            t0 = time.time()
            ok_n = 0
            for m, opts in plan:
                for k, v in opts.items():
                    self.ctx.set_option(k, v)
                ok, msg = core.execute(m, self.ctx)
                if ok:
                    ok_n += 1
                    self.ctx.success("%s -> %s" % (m, msg))
                else:
                    self.ctx.error("%s -> %s" % (m, msg))
        finally:
            lab.stop()
            self.ctx.warn("lab server stopped")
        counts = self.ctx.summary()
        self.ctx.info("self-test complete: %d/%d modules OK in %.1fs" % (
            ok_n, len(plan), time.time() - t0))
        self.ctx.info("lab findings recorded: %s" % counts)
        if len(self.ctx.findings) > base_ctx_findings:
            try:
                prefix = os.path.join(self.ctx.workspace, "tveye_selftest_report")
                paths = REP.generate_all(self.ctx, prefix)
                for p in paths:
                    self.ctx.success("self-test report: %s" % os.path.abspath(p))
            except Exception as exc:
                self.ctx.debug("report write failed: %s" % exc)
        return "selftest finished"

    def _chain(self, target, mods, label):
        self.ctx.add_target(target)
        self.ctx.set_option("target", target)
        t0 = time.time()
        self.ctx.info("%s chain starting on %s (%d modules)" % (
            C.c(label, C.BRIGHT_MAGENTA, C.BOLD), target, len(mods)))
        for m in mods:
            cls = core.get_module_class(m)
            if cls and getattr(cls, "REQUIRED", []) and "domain" in cls.REQUIRED:
                host = U.normalize_target(target)[1]
                self.ctx.set_option("domain", host)
            ok, msg = core.execute(m, self.ctx)
            (self.ctx.success if ok else self.ctx.error)("%s -> %s" % (m, msg))
        self.ctx.info("%s chain complete in %.1fs - %s" % (
            label, time.time() - t0, self.ctx.summary()))

    def cmd_findings(self, args):
        if args and args[0].lower() == "clear":
            self.ctx.clear_findings()
            return
        if not self.ctx.findings:
            self.ctx.info("no findings yet")
            return
        rows = []
        for f in self.ctx.findings_sorted():
            rows.append((f["id"], f["severity"].upper(), f["title"][:52],
                         f["target"][:34]))
        self.ctx.table(["id", "severity", "title", "target"], rows)
        counts = self.ctx.summary()
        self.ctx.info("summary: %s" % counts)

    def cmd_report(self, args):
        fmt = "all"
        name = None
        if args:
            fmt = args[0].lower()
            if len(args) > 1:
                name = args[1]
        if fmt not in ("md", "html", "json", "all"):
            raise ModuleError("usage: report md|html|json|all [name]")
        if not self.ctx.findings and not self.ctx.outputs:
            self.ctx.warn("nothing to report yet (run modules first)")
            return
        prefix = os.path.join(self.ctx.workspace, name) if name else None
        ext = {"md": ".md", "html": ".html", "json": ".json"}
        if fmt == "all":
            out = REP.generate_all(self.ctx, prefix)
        else:
            if prefix and prefix.endswith(ext[fmt]):
                target_path = prefix
            else:
                target_path = (prefix or os.path.join(self.ctx.workspace,
                                                      "tveye_report")) + ext[fmt]
            fn = {"md": REP.generate_markdown, "html": REP.generate_html,
                  "json": REP.generate_json}[fmt]
            out = [fn(self.ctx, target_path)]
        for p in out:
            self.ctx.success("report written: %s" % os.path.abspath(p))

    def cmd_save(self, args):
        self.ctx.save_session(args[0] if args else "tveye-session.json")

    def cmd_load(self, args):
        self.ctx.load_session(args[0] if args else "tveye-session.json")

    def cmd_status(self, args):
        self.ctx.info("TV-EYE status")
        counts = self.ctx.summary()
        rows = [
            ("workspace", self.ctx.workspace),
            ("targets", ", ".join(self.ctx.targets) or "-"),
            ("findings", "critical:%d high:%d med:%d low:%d info:%d" % (
                counts["critical"], counts["high"], counts["medium"],
                counts["low"], counts["info"])),
            ("threads", str(self.ctx.threads)),
            ("timeout", str(self.ctx.timeout)),
            ("proxy", self.ctx.proxy or "-"),
            ("cookie", "set" if self.ctx.cookie else "-"),
            ("verify-tls", str(self.ctx.verify_tls)),
            ("current module", self.current.NAME if self.current else "-"),
        ]
        for k, v in rows:
            print("   %-16s %s" % (C.c(k + ":", C.BRIGHT_CYAN), v))

    def cmd_authors(self, args):
        print(C.c("\n" + "=" * 62, C.BRIGHT_MAGENTA))
        print(C.c("           TV-EYE  -  created by Mr_TV", C.BRIGHT_CYAN, C.BOLD))
        print(C.c("=" * 62, C.BRIGHT_MAGENTA))
        print(AUTHOR_INFO)
        print(C.c("=" * 62 + "\n", C.BRIGHT_MAGENTA))

    cmd_credits = cmd_authors

    def cmd_legal(self, args):
        print(C.c("\n" + LEGAL_NOTE + "\n", C.BRIGHT_YELLOW))

    def cmd_version(self, args):
        self.ctx.info("TV-EYE v%s by %s (Telegram %s)" % (__version__, __author__,
                                                          __telegram__))
