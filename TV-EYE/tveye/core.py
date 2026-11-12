"""Core framework: module registry, execution engine and shared helpers."""

import importlib
import pkgutil
import time
import traceback

from . import colors as C
from . import logo


class ModuleError(Exception):
    pass


class BaseModule(object):
    """Every TV-EYE capability is a module deriving from this class."""

    NAME = "base"
    DESCRIPTION = "no description"
    CATEGORY = "misc"
    AUTHOR = "Mr_TV"

    def __init__(self, ctx):
        self.ctx = ctx

    # ------------------------------------------------------------------ utils
    def options(self):
        """Return dict of option-name -> help string (override in modules)."""
        return {}

    def validate(self):
        missing = []
        required = getattr(self, "REQUIRED", [])
        for opt in required:
            if not self.ctx.get_option(opt):
                missing.append(opt)
        if missing:
            raise ModuleError("missing required option(s): " + ", ".join(missing))

    def run(self):
        raise ModuleError("module %s does not implement run()" % self.NAME)

    # ------------------------------------------------------------- reporting
    def info(self, msg):
        self.ctx.info("[%s] %s" % (self.NAME, msg))

    def success(self, msg):
        self.ctx.success("[%s] %s" % (self.NAME, msg))

    def warn(self, msg):
        self.ctx.warn("[%s] %s" % (self.NAME, msg))

    def error(self, msg):
        self.ctx.error("[%s] %s" % (self.NAME, msg))

    def output(self, data):
        self.ctx.add_output(self.NAME, data)

    def add_finding(self, title, severity, target, evidence, tip=None, cwe=None):
        f = self.ctx.add_finding(
            title=title,
            severity=severity,
            target=target,
            evidence=evidence,
            tip=tip,
            cwe=cwe,
        )
        f["_module"] = self.NAME
        return f


# --------------------------------------------------------------------- registry
_MODULES = {}
_ERRORS = []


def load_all():
    """Import every module package present under tveye.modules."""
    global _MODULES
    if _MODULES:
        return _MODULES
    import tveye.modules as pkg

    for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        try:
            mod = importlib.import_module("tveye.modules." + name)
        except Exception as exc:  # keep the console usable even if one module breaks
            _ERRORS.append((name, str(exc), traceback.format_exc(limit=4)))
            continue
        for attr in dir(mod):
            m = getattr(mod, attr)
            if (isinstance(m, type) and issubclass(m, BaseModule)
                    and getattr(m, "NAME", "") not in ("", "base")
                    and m.__module__.startswith("tveye.modules.")):
                _MODULES[m.NAME] = m
    return _MODULES


def load_errors():
    return list(_ERRORS)


def modules():
    return load_all()


def get_module_class(name):
    load_all()
    return _MODULES.get(name)


def categories():
    cats = {}
    for name, cls in sorted(_MODULES.items()):
        cats.setdefault(cls.CATEGORY, []).append(name)
    return cats


def execute(modname, ctx):
    """Instantiate and run one module, with exception containment."""
    cls = get_module_class(modname)
    if not cls:
        return False, "unknown module: %s" % modname
    started = time.time()
    try:
        instance = cls(ctx)
        instance.validate()
        result = instance.run()
        elapsed = time.time() - started
        if isinstance(result, str):
            return True, result
        return True, "module %s finished in %.2fs" % (modname, elapsed)
    except ModuleError as exc:
        return False, str(exc)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        ctx.debug("traceback: %s" % traceback.format_exc(limit=6))
        return False, "module crashed: %s" % exc


# ---------------------------------------------------------------- banner/paint
def banner(width=76):
    """The TV-EYE big-block logo with shadow, author credits and frame."""
    out = []
    color = C.enabled()
    art = logo.shadowed("TV-EYE")
    f = logo.frame(width)
    if color:
        out.append(C.c(f, C.BRIGHT_MAGENTA, C.BOLD))
    else:
        out.append(f)
    for row in art:
        line = "  " + row
        if color:
            line = C.c(line, C.BRIGHT_CYAN, C.BOLD)
        out.append(line)
    sub = "  %s  v1.0.0  |  Offensive Security & Bug Bounty Console" % logo_tag()
    if color:
        sub = C.c(sub, C.BRIGHT_WHITE, C.BOLD)
    out.append(sub)
    credits = (
        "  Author   : Mr_TV      Telegram : @Mr_TV_ir      GitHub : github.com/TV-CENTER"
    )
    if color:
        credits = C.c(credits, C.BRIGHT_YELLOW)
    out.append(credits)
    legal = "  Authorized testing only - use only on assets you are permitted to test."
    if color:
        legal = C.c(legal, C.BRIGHT_BLACK)
    out.append(legal)
    if color:
        out.append(C.c(f, C.BRIGHT_MAGENTA, C.BOLD))
    else:
        out.append(f)
    return "\n".join(out)


def logo_tag():
    """Small keyboard-art wordmark used next to the prompt."""
    return "[ TV-EYE ]"


def cat_header(title, width=76):
    f = logo.frame(width)
    bar = "+%s+" % ("=" * (width - 2))
    return "\n".join([f, ("== %s ==" % title).center(width), f])
