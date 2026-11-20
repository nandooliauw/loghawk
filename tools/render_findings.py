#!/usr/bin/env python3
"""Render a loghawk JSON report to a PNG findings card.

All values come from the report file, so the image cannot drift from the data.

    python tools/render_findings.py examples/report-example.json docs/findings.png
"""

from __future__ import annotations

import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

S = 2
W = 720 * S
BG = (11, 15, 20)
PANEL = (17, 24, 35)
LINE = (30, 42, 58)
TEXT = (219, 230, 243)
DIM = (125, 143, 166)
ACCENT = (74, 168, 255)
SEV = {
    "critical": (255, 92, 92),
    "high": (231, 76, 60),
    "medium": (245, 176, 65),
    "low": (74, 168, 255),
    "info": (125, 143, 166),
}

MONO = [r"C:\Windows\Fonts\consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
SANS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\Arial Bold.ttf"]


def font(paths, size):
    for path in paths:
        if os.path.isfile(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def fit(text: str, fnt, max_width: float) -> str:
    if fnt.getlength(text) <= max_width:
        return text
    out = text
    while out and fnt.getlength(out + "…") > max_width:
        out = out[:-1]
    return out + "…"


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else "examples/report-example.json"
    target = sys.argv[2] if len(sys.argv) > 2 else "docs/findings.png"

    with open(source, encoding="utf-8") as handle:
        data = json.load(handle)

    f_title = font(SANS, 22 * S)
    f_body = font(MONO, 12 * S)
    f_small = font(MONO, 10 * S)
    f_meta = font(MONO, 11 * S)

    findings = data["findings"]
    summary = data["summary"]
    pad = 26 * S
    header_h = 128 * S
    row_h = 44 * S
    height = header_h + 52 * S + row_h * len(findings) + 64 * S

    image = Image.new("RGB", (W, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([(S, S), (W - S, height - S)], radius=12 * S, outline=LINE, width=S)

    draw.text((pad, 26 * S), "loghawk detection report", font=f_title, fill=TEXT)
    draw.text(
        (pad, 56 * S),
        f"{data['source']} · {summary['events']} events parsed · generated {data['generated_at']}",
        font=f_meta,
        fill=DIM,
    )
    draw.text(
        (pad, 78 * S),
        f"window {data['parameters']['window_seconds']}s · threshold {data['parameters']['threshold']} failures "
        f"· {summary['findings']} finding(s)",
        font=f_meta,
        fill=DIM,
    )

    # severity chips
    x = pad
    for sev in ("critical", "high", "medium", "low"):
        count = summary["by_severity"].get(sev, 0)
        label = f"{count} {sev}"
        width = f_small.getlength(label) + 22 * S
        draw.rounded_rectangle(
            [(x, header_h - 26 * S), (x + width, header_h - 6 * S)],
            radius=9 * S,
            fill=(24, 32, 44),
            outline=SEV[sev],
            width=S,
        )
        draw.text((x + 11 * S, header_h - 23 * S), label, font=f_small, fill=SEV[sev])
        x += width + 8 * S

    # table head
    draw.line([(pad, header_h + 12 * S), (W - pad, header_h + 12 * S)], fill=LINE, width=S)
    cols = {"id": pad, "title": 150 * S, "sev": 480 * S, "events": 570 * S, "window": 640 * S}
    for label, key in (("ID", "id"), ("FINDING", "title"), ("SEVERITY", "sev"), ("EVENTS", "events"), ("TIME", "window")):
        draw.text((cols[key], header_h + 28 * S), label, font=f_small, fill=DIM)

    y = header_h + 52 * S
    for item in findings:
        colour = SEV.get(item["severity"], DIM)
        draw.rounded_rectangle([(pad, y - 12 * S), (pad + 3 * S, y + 14 * S)], radius=1 * S, fill=colour)
        draw.text((cols["id"], y), item["id"].split("/")[0], font=f_body, fill=DIM)
        draw.text(
            (cols["title"], y),
            fit(item["title"], f_body, cols["sev"] - cols["title"] - 18 * S),
            font=f_body,
            fill=TEXT,
        )
        draw.text((cols["sev"], y), item["severity"].upper(), font=f_small, fill=colour)
        draw.text((cols["events"], y), str(item["count"]), font=f_body, fill=DIM)
        stamp = (item["first_seen"] or "")[11:19]
        draw.text((cols["window"], y), stamp, font=f_body, fill=DIM)
        y += row_h

    draw.text(
        (pad, height - 32 * S),
        f"generated from {os.path.basename(source)} · rules documented in README · no network access",
        font=f_small,
        fill=DIM,
    )

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    image.save(target, "PNG", optimize=True)
    print(f"wrote {target} ({image.width}x{image.height}, {os.path.getsize(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
