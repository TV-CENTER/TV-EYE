"""TV-EYE entry point: `python -m tveye` or `python tveye.py`."""

import argparse
import sys

from . import __version__, __author__, __telegram__, __github__
from . import core, colors as C


def build_parser():
    p = argparse.ArgumentParser(
        prog="TV-EYE",
        description="TV-EYE v%s - Offensive Security & Bug Bounty Console\n"
                    "Author: %s | Telegram: %s | GitHub: %s"
                    % (__version__, __author__, __telegram__, __github__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python tveye.py                       # interactive console\n"
                "  python tveye.py -e \"modules\"\n"
                "  python tveye.py -e \"quick http://target.local\"\n"
                "  python tveye.py -m security_headers -o target=http://10.0.0.5 --run\n"
                "  python tveye.py -e \"report html\"\n"))
    p.add_argument("-e", "--execute", action="append", default=[],
                   help="run one or more console commands then exit")
    p.add_argument("-m", "--module", help="module to run directly")
    p.add_argument("-o", "--opt", action="append", default=[],
                   help="option key=value (repeatable), e.g. -o target=http://x")
    p.add_argument("--run", action="store_true", help="execute -m module and exit")
    p.add_argument("-w", "--workspace", help="workspace directory for outputs")
    p.add_argument("--no-banner", action="store_true", help="skip the logo")
    p.add_argument("--no-color", action="store_true", help="disable colors")
    p.add_argument("--authors", action="store_true", help="show author info and exit")
    p.add_argument("--version", action="version",
                   version="TV-EYE %s (Mr_TV - %s - %s)" % (__version__, __telegram__,
                                                            __github__))
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()
    else:
        C.enable()
    C.enable_windows_vt()
    if args.authors:
        print("TV-EYE v%s" % __version__)
        print("Author   : %s" % __author__)
        print("Telegram : %s" % __telegram__)
        print("GitHub   : %s" % __github__)
        return 0
    from .console import Console
    con = Console()
    if args.workspace:
        con.cmd_workspace([args.workspace])
    # pre-apply options so -e and -m can use them
    for kv in args.opt:
        if "=" in kv:
            k, v = kv.split("=", 1)
            con.ctx.set_option(k, v)
    if args.module:
        con.cmd_use([args.module])
    if args.execute or args.run:
        if not args.no_banner:
            print(core.banner())
        for cmdline in args.execute:
            con.dispatch(cmdline)
        if args.run and args.module:
            con.cmd_run([])
            con.cmd_report(["all"])
        return 0
    con.start(banner=not args.no_banner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
