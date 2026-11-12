"""Report generator for TV-EYE: JSON / Markdown / HTML deliverables."""

import html
import json
import os
from datetime import datetime, timezone

from . import colors as C
from . import __tool__, __version__

SEV_COLORS = {"critical": "#b71c1c", "high": "#e53935", "medium": "#f9a825",
              "low": "#039be5", "info": "#78909c"}


def generate_json(ctx, path):
    data = {
        "tool": "%s %s - Author: Mr_TV - Telegram: @Mr_TV_ir - GitHub: https://github.com/TV-CENTER" % (__tool__, __version__),
        "generated": datetime.now(timezone.utc).isoformat(),
        "workspace": ctx.workspace,
        "options": ctx.options,
        "targets": ctx.targets,
        "summary": ctx.summary(),
        "findings": ctx.findings,
        "outputs": {k: v for k, v in ctx.outputs.items()},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def generate_markdown(ctx, path):
    s = ctx.summary()
    lines = []
    lines.append("# %s v%s - Assessment Report" % (__tool__, __version__))
    lines.append("")
    lines.append("**Author:** Mr_TV  |  **Telegram:** @Mr_TV_ir  |  "
                 "**GitHub:** https://github.com/TV-CENTER")
    lines.append("")
    lines.append("**Generated:** %s" % datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append("| %s | %d |" % (sev, s[sev]))
    lines.append("")
    lines.append("**Targets:** %s" % (", ".join(ctx.targets) or "-"))
    lines.append("")
    lines.append("## Findings")
    if not ctx.findings:
        lines.append("_No findings recorded._")
    for f in ctx.findings_sorted():
        lines.append("")
        lines.append("### #%d [%s] %s" % (f["id"], f["severity"].upper(), f["title"]))
        lines.append("")
        lines.append("- **Target:** `%s`" % f["target"])
        lines.append("- **Time:** %s" % f["time"])
        if f.get("cwe"):
            lines.append("- **CWE:** %s" % f["cwe"])
        if f.get("_module"):
            lines.append("- **Module:** %s" % f["_module"])
        lines.append("")
        lines.append("**Evidence:**")
        lines.append("")
        lines.append("```")
        lines.append(f["evidence"])
        lines.append("```")
        if f.get("tip"):
            lines.append("")
            lines.append("**Remediation tip:** %s" % f["tip"])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def generate_html(ctx, path):
    s = ctx.summary()
    rows = []
    for f in ctx.findings_sorted():
        rows.append("""
        <tr>
          <td>#{id}</td>
          <td><span class="sev {sev}">{sev_u}</span></td>
          <td>{title}</td>
          <td><code>{target}</code></td>
          <td>{cwe}</td>
        </tr>""".format(id=f["id"], sev=f["severity"], sev_u=f["severity"].upper(),
                        title=html.escape(f["title"]), target=html.escape(f["target"][:120]),
                        cwe=html.escape(f.get("cwe", ""))))
    detail = []
    for f in ctx.findings_sorted():
        detail.append("""
        <div class="card">
          <h3>#{id} [{sev}] {title}</h3>
          <p><b>Target:</b> <code>{target}</code> &nbsp; <b>Module:</b> {mod} &nbsp; <b>CWE:</b> {cwe}</p>
          <pre>{evidence}</pre>
          <p><b>Tip:</b> {tip}</p>
        </div>""".format(id=f["id"], sev=f["severity"], title=html.escape(f["title"]),
                         target=html.escape(f["target"][:160]),
                         mod=html.escape(f.get("_module", "-")),
                         cwe=html.escape(f.get("cwe", "-")),
                         evidence=html.escape(f["evidence"]),
                         tip=html.escape(f.get("tip", "-"))))
    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>TV-EYE Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:24px}}
h1{{color:#58a6ff}} h3{{margin:4px 0}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600}}
.sev.critical{{background:#b71c1c}}.sev.high{{background:#e53935}}
.sev.medium{{background:#f9a825;color:#111}}.sev.low{{background:#039be5}}
.sev.info{{background:#546e7a}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left}}
pre{{background:#161b22;border:1px solid #30363d;padding:10px;border-radius:6px;
overflow-x:auto;white-space:pre-wrap}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
padding:14px;margin:12px 0}}
.footer{{color:#8b949e;margin-top:30px;font-size:12px}}
</style></head><body>
<h1>TV-EYE v{ver} - Security Assessment Report</h1>
<p><b>Author:</b> Mr_TV &nbsp;|&nbsp; <b>Telegram:</b> @Mr_TV_ir &nbsp;|&nbsp;
<b>GitHub:</b> <a href="https://github.com/TV-CENTER" style="color:#58a6ff">github.com/TV-CENTER</a></p>
<p><b>Generated:</b> {gen}</p>
<p>Findings: <span class="badge sev critical">CRITICAL {critical}</span>
<span class="badge sev high">HIGH {high}</span>
<span class="badge sev medium">MEDIUM {medium}</span>
<span class="badge sev low">LOW {low}</span>
<span class="badge sev info">INFO {info}</span></p>
<p><b>Targets:</b> {targets}</p>
<h2>Findings table</h2>
<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Target</th><th>CWE</th></tr>
{rows}
</table>
<h2>Details</h2>
{detail}
<div class="footer">Generated by TV-EYE {ver} (Mr_TV) - authorized testing only.</div>
</body></html>""".format(ver=__version__,
                         gen=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                         critical=s["critical"], high=s["high"], medium=s["medium"],
                         low=s["low"], info=s["info"],
                         targets=html.escape(", ".join(ctx.targets) or "-"),
                         rows="".join(rows), detail="".join(detail))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def generate_all(ctx, prefix=None):
    if not prefix:
        prefix = "tveye_report_%s" % datetime.now().strftime("%Y%m%d_%H%M%S")
    out = []
    out.append(generate_json(ctx, prefix + ".json"))
    out.append(generate_markdown(ctx, prefix + ".md"))
    out.append(generate_html(ctx, prefix + ".html"))
    return out
