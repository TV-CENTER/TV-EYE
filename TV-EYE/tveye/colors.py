"""Color handling for TV-EYE.

Colors are enabled when the console supports them: real terminals, Git Bash,
Windows Terminal, and PowerShell 5+/cmd.exe on Windows 10 1511+ with VT
processing enabled. TV-EYE enables ANSI processing on Windows at startup so
colors work in cmd.exe and PowerShell too.
"""

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BRIGHT_BLACK = "\033[90m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_WHITE = "\033[97m"

_BG_BLUE = "\033[44m"
_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"
_BG_MAGENTA = "\033[45m"
_BG_CYAN = "\033[46m"

_state = {"enabled": None}


def _host_supports_vt():
    """Best-effort detection without external dependencies."""
    if sys.platform != "win32":
        return True
    try:
        if os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"):
            return True
        if os.environ.get("ANSICON"):
            return True
        if os.environ.get("ConEmuANSI") == "ON":
            return True
    except Exception:
        pass
    # Windows 10 1511+ consoles accept VT sequences once enabled.
    ver = sys.getwindowsversion()  # noqa: PR01
    return (ver.major, ver.minor, ver.build) >= (10, 0, 10240)


def enable_windows_vt():
    """Enable ANSI escape processing for the legacy Windows console."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        hOut = kernel32.GetStdHandle(-11)
        mode = (ctypes.c_uint32)()
        if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
            new_mode = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            if kernel32.SetConsoleMode(hOut, new_mode):
                return True
    except Exception:
        pass
    return False


def enable(force=None):
    """Enable or disable color output globally."""
    if force is None:
        if _state["enabled"] is None:
            _state["enabled"] = _host_supports_vt() and _open_tty()
        return _state["enabled"]
    _state["enabled"] = bool(force)
    return _state["enabled"]


def _open_tty():
    try:
        return sys.stdout.isatty() or os.environ.get("TVEYE_FORCE_COLOR") == "1"
    except Exception:
        return False


def enabled():
    return bool(_state["enabled"])


def disable():
    _state["enabled"] = False


def c(text, *codes):
    """Wrap text in one or more color codes; no-op when colors are off."""
    if not _state["enabled"]:
        return str(text)
    prefix = "".join(codes)
    return "%s%s%s" % (prefix, text, RESET)


def paint(text, *codes):
    """Always paint, regardless of the global switch (for captured logs)."""
    prefix = "".join(codes)
    return "%s%s%s" % (prefix, text, RESET)
