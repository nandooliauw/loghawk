"""Report renderers for loghawk: console, Markdown, JSON and self-contained HTML."""

from __future__ import annotations

import html
import json

from .models import SEVERITY_ORDER, Event, Finding, Report

SEV_COLOUR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[90m"

HTML_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _fmt_ts(event: Event) -> str:
    return event.ts.strftime("%Y-%m-%d %H:%M:%S")


def _range(finding: Finding) -> str:
    first, last = finding.first_seen(), finding.last_seen()
    if not first or not last:
        return "n/a"
    if first == last:
        return first.strftime("%H:%M:%S")
    return f"{first.strftime('%H:%M:%S')} → {last.strftime('%H:%M:%S')}"


# --- console -----------------------------------------------------------------


def to_text(report: Report, colour: bool = True, log_format: str = "auto") -> str:
    def paint(severity: str) -> str:
        return SEV_COLOUR.get(severity, "") if colour else ""

    def dim(text: str) -> str:
        return f"{DIM}{text}{RESET}" if colour else text

    def bold(text: str) -> str:
        return f"{BOLD}{text}{RESET}" if colour else text

    lines: list[str] = []
    lines.append(f"{bold('loghawk')}  {report.generated_at}")
    lines.append(f"source    {report.source}  ({log_format}, {len(report.events)} events parsed)")
    lines.append(
        f"params    window={report.window}s  threshold={report.threshold}  "
        f"parse errors={len(report.parse_errors)}"
    )
    counts = report.counts
    lines.append("")
    lines.append(
        f"{bold('findings')} {len(report.findings)}   "
        + "  ".join(
            f"{paint(sev)}{counts.get(sev, 0)} {sev}{RESET if colour else ''}"
            for sev in ("critical", "high", "medium", "low")
        )
    )
    lines.append("")

    if not report.findings:
        lines.append("no detections — the rules in rules.py all came back clean")
        return "\n".join(lines)

    for finding in report.sorted_findings():
        lines.append(
            f"{paint(finding.severity)}{finding.severity.upper():<8}{RESET if colour else ''} "
            f"{bold(finding.title)}  {dim(f'[{finding.id}]')}"
        )
        lines.append(f"         {finding.summary}")
        lines.append(
            dim(
                f"         first {finding.first_seen().strftime('%Y-%m-%d %H:%M:%S') if finding.first_seen() else 'n/a'}"
                f"  last {finding.last_seen().strftime('%H:%M:%S') if finding.last_seen() else 'n/a'}"
                f"  events {finding.count or len(finding.events)}"
            )
        )
        for event in finding.events:
            lines.append(
                dim(
                    f"           L{event.line_no:<4} {event.ts.strftime('%H:%M:%S')}  "
                    f"{event.action:<12} {event.user or '-':<14} {event.ip or '-':<16} {event.detail[:52]}"
                )
            )
        omitted = (finding.count or len(finding.events)) - len(finding.events)
        if omitted > 0:
            lines.append(dim(f"           … {omitted} more event(s) not shown (evidence capped)"))
        if finding.remediation:
            lines.append(f"         {dim('fix:')} {finding.remediation}")
        lines.append("")

    if report.parse_errors:
        lines.append(dim(f"{len(report.parse_errors)} line(s) could not be parsed:"))
        for error in report.parse_errors[:5]:
            lines.append(dim(f"  {error}"))
    return "\n".join(lines)


# --- markdown ----------------------------------------------------------------


def to_markdown(report: Report, log_format: str = "auto") -> str:
    counts = report.counts
    lines = [
        "# loghawk report",
        "",
        f"- **Source:** `{report.source}` ({log_format})",
        f"- **Generated:** {report.generated_at}",
        f"- **Events parsed:** {len(report.events)}",
        f"- **Parameters:** window {report.window}s, threshold {report.threshold}",
        f"- **Parse errors:** {len(report.parse_errors)}",
        "",
        "## Findings",
        "",
        f"`{counts['critical']} critical` · `{counts['high']} high` · "
        f"`{counts['medium']} medium` · `{counts['low']} low`",
        "",
    ]
    if not report.findings:
        lines += ["No detections.", ""]
    else:
        lines += [
            "| ID | Rule | Finding | Severity | Events | Window |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for finding in report.sorted_findings():
            lines.append(
                f"| `{finding.id}` | {finding.rule} | {finding.title} | **{finding.severity.upper()}** | "
                f"{finding.count or len(finding.events)} | {_range(finding)} |"
            )
        lines.append("")

        for index, finding in enumerate(report.sorted_findings(), 1):
            lines += [
                f"### {index}. {finding.id} — {finding.title}",
                "",
                f"- **Severity:** {finding.severity.upper()}",
                f"- **Summary:** {finding.summary}",
                f"- **Events:** {finding.count or len(finding.events)}",
                f"- **Remediation:** {finding.remediation}",
            ]
            for reference in finding.references:
                lines.append(f"- **Reference:** {reference}")
            lines += ["", "| Line | Time | Action | User | Source | Detail |", "| --- | --- | --- | --- | --- | --- |"]
            for event in finding.events:
                lines.append(
                    f"| {event.line_no} | {event.ts.strftime('%H:%M:%S')} | {event.action} | "
                    f"{event.user or '-'} | {event.ip or '-'} | {event.detail.replace('|', '/')[:80]} |"
                )
            omitted = (finding.count or len(finding.events)) - len(finding.events)
            if omitted > 0:
                lines.append(f"| … | | | | | {omitted} more event(s) not shown (evidence capped) |")
            lines.append("")

    if report.parse_errors:
        lines += ["## Unparsed lines", ""]
        lines += [f"- `{error}`" for error in report.parse_errors[:20]]
        lines.append("")
    return "\n".join(lines)


# --- json --------------------------------------------------------------------


def to_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=False)


# --- html --------------------------------------------------------------------

HTML_CSS = """
:root{--bg:#0b0f14;--panel:#111823;--line:#1e2a3a;--text:#dbe6f3;--dim:#7d8fa6;
--crit:#e74c3c;--high:#f0603c;--med:#f5b041;--low:#4aa8ff;--accent:#4aa8ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:40px 22px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:26px}
h1{font-size:22px;margin:0 0 6px}
.meta{color:var(--dim);font-size:13px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:22px 0 30px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.8px}
.card .v{font-size:24px;font-weight:700;margin-top:4px}
.critical .v{color:var(--crit)}.high .v{color:var(--high)}
.medium .v{color:var(--med)}.low .v{color:var(--low)}
h2{font-size:16px;margin:34px 0 10px}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--accent);
border-radius:8px;padding:16px 18px;margin-bottom:14px}
.finding.critical{border-left-color:var(--crit)}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}
.finding.low{border-left-color:var(--low)}
.finding h3{margin:0 0 6px;font-size:15px}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.5px}
.pill.critical{background:rgba(231,76,60,.16);color:var(--crit)}
.pill.high{background:rgba(240,96,60,.16);color:var(--high)}
.pill.medium{background:rgba(245,176,65,.16);color:var(--med)}
.pill.low{background:rgba(74,168,255,.16);color:var(--low)}
.summary{margin:8px 0;color:#c2d0e0}
table{width:100%;border-collapse:collapse;margin:10px 0 4px;background:#0e1520;border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);font-size:12.5px;vertical-align:top}
th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
tr:last-child td{border-bottom:none}
code,.mono{font-family:Consolas,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.fix{margin-top:10px;border-top:1px dashed var(--line);padding-top:8px;color:var(--dim);font-size:13px}
footer{margin-top:36px;border-top:1px solid var(--line);padding-top:14px;color:var(--dim);font-size:12px}
"""


def to_html(report: Report, log_format: str = "auto") -> str:
    esc = html.escape
    counts = report.counts

    cards = "".join(
        f"<div class='card {sev}'><div class='k'>{sev}</div><div class='v'>{counts.get(sev, 0)}</div></div>"
        for sev in ("critical", "high", "medium", "low")
    )
    cards += (
        f"<div class='card'><div class='k'>events</div><div class='v'>{len(report.events)}</div></div>"
        f"<div class='card'><div class='k'>parse errors</div><div class='v'>{len(report.parse_errors)}</div></div>"
    )

    blocks: list[str] = []
    for finding in report.sorted_findings():
        rows = "".join(
            f"<tr><td class='mono'>{event.line_no}</td>"
            f"<td class='mono'>{event.ts.strftime('%H:%M:%S')}</td>"
            f"<td class='mono'>{esc(event.action)}</td>"
            f"<td class='mono'>{esc(event.user or '-')}</td>"
            f"<td class='mono'>{esc(event.ip or '-')}</td>"
            f"<td class='mono'>{esc(event.detail[:70])}</td></tr>"
            for event in finding.events
        )
        refs = "".join(f"<div class='mono'>{esc(r)}</div>" for r in finding.references)
        omitted = (finding.count or len(finding.events)) - len(finding.events)
        omission_note = (
            f"<div class='mono' style='color:var(--dim);font-size:12px;padding:6px 10px'>"
            f"… {omitted} more event(s) not shown (evidence capped)</div>"
            if omitted > 0
            else ""
        )
        blocks.append(
            f"<div class='finding {HTML_SEV.get(finding.severity, 'low')}'>"
            f"<h3><span class='pill {HTML_SEV.get(finding.severity, 'low')}'>"
            f"{esc(finding.severity.upper())}</span> {esc(finding.title)} "
            f"<span class='mono' style='color:var(--dim)'>[{esc(finding.id)}]</span></h3>"
            f"<div class='summary'>{esc(finding.summary)}</div>"
            f"<div class='mono' style='color:var(--dim);font-size:12px'>"
            f"{finding.count or len(finding.events)} event(s) · window {esc(_range(finding))} · "
            f"rule {esc(finding.rule)}</div>"
            f"<table><thead><tr><th>Line</th><th>Time</th><th>Action</th><th>User</th>"
            f"<th>Source</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"
            f"{omission_note}"
            f"<div class='fix'><b>Remediation:</b> {esc(finding.remediation)}</div>"
            f"<div class='fix'>{refs}</div>"
            f"</div>"
        )

    errors_html = ""
    if report.parse_errors:
        items = "".join(f"<li class='mono'>{esc(e)}</li>" for e in report.parse_errors[:20])
        errors_html = f"<h2>Unparsed lines</h2><ul>{items}</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>loghawk · {esc(report.source)}</title>
<style>{HTML_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>loghawk detection report</h1>
  <div class="meta">{esc(report.source)} · format {esc(log_format)} · generated {esc(report.generated_at)}</div>
  <div class="meta">window {report.window}s · threshold {report.threshold} failures ·
  events by action: {esc(", ".join(f"{k}={v}" for k, v in report.action_counts.items()))}</div>
</header>

<div class="cards">{cards}</div>

<h2>Detections</h2>
{''.join(blocks) or "<p class='meta'>No detections.</p>"}

{errors_html}

<footer>
Generated by loghawk — offline rule engine over exported authentication logs.
Thresholds are printed with every report so a finding can always be reproduced.
</footer>
</div>
</body>
</html>
"""


def render(report: Report, fmt: str, colour: bool = True, log_format: str = "auto") -> str:
    if fmt == "md":
        return to_markdown(report, log_format)
    if fmt == "html":
        return to_html(report, log_format)
    if fmt == "json":
        return to_json(report)
    return to_text(report, colour=colour, log_format=log_format)


def sort_key(finding: Finding) -> int:
    return SEVERITY_ORDER.get(finding.severity, 9)
