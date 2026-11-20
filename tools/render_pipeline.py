#!/usr/bin/env python3
"""Draw the loghawk pipeline diagram as a PNG.

Stages mirror the real call order in ``loghawk/cli.py``:

    parse_any() -> run(rules) -> Report -> render()

    python tools/render_pipeline.py docs/pipeline.png
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw, ImageFont

S = 2
W, H = 1140 * S, 340 * S
BG = (11, 15, 20)
PANEL = (17, 24, 35)
LINE = (30, 42, 58)
TEXT = (219, 230, 243)
DIM = (125, 143, 166)
ACCENT = (74, 168, 255)
GREEN = (46, 204, 113)
AMBER = (245, 176, 65)
RED = (231, 76, 60)

MONO = [r"C:\Windows\Fonts\consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
SANS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\Arial Bold.ttf"]


def font(paths, size):
    for path in paths:
        if os.path.isfile(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def box(draw, x, y, w, h, title, lines, accent=ACCENT):
    draw.rounded_rectangle([(x, y), (x + w, y + h)], radius=10 * S, fill=PANEL, outline=LINE, width=S)
    draw.rounded_rectangle([(x, y), (x + 4 * S, y + h)], radius=2 * S, fill=accent)
    draw.text((x + 18 * S, y + 14 * S), title, font=font(SANS, 15 * S), fill=TEXT)
    for index, line in enumerate(lines):
        draw.text((x + 18 * S, y + 40 * S + index * 18 * S), line, font=font(MONO, 11 * S), fill=DIM)


def arrow(draw, x1, y1, x2, y2):
    draw.line([(x1, y1), (x2, y2)], fill=(60, 78, 100), width=2 * S)
    draw.polygon([(x2, y2), (x2 - 8 * S, y2 - 5 * S), (x2 - 8 * S, y2 + 5 * S)], fill=(60, 78, 100))


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "docs/pipeline.png"
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)

    draw.text((28 * S, 22 * S), "loghawk — detection pipeline", font=font(SANS, 20 * S), fill=TEXT)
    draw.text(
        (28 * S, 50 * S),
        "offline · no network calls · 7 rules · every threshold printed with the report",
        font=font(MONO, 11 * S),
        fill=DIM,
    )

    bw, bh = 176 * S, 118 * S
    y = 96 * S
    xs = [28 * S, 246 * S, 464 * S, 682 * S, 900 * S]

    box(draw, xs[0], y, bw, bh, "log file", ["auth.log", "Windows CSV", "format auto-detect"])
    box(draw, xs[1], y, bw, bh, "parsers.py", ["normalise events", "unparsed lines", "reported, not dropped"], accent=GREEN)
    box(draw, xs[2], y, bw, bh, "rules.py", ["7 detections", "sliding window", "per-IP / per-user"], accent=AMBER)
    box(draw, xs[3], y, bw, bh, "engine.py", ["run all rules", "severity sort", "evidence capped"], accent=AMBER)
    box(draw, xs[4], y, bw, bh, "report.py", ["text · markdown", "html · json", "exit code 0/1/2"])

    for index in range(4):
        arrow(draw, xs[index] + bw + 4 * S, y + bh // 2, xs[index + 1] - 4 * S, y + bh // 2)

    # rule strip
    ry = 244 * S
    draw.rounded_rectangle([(xs[2], ry), (xs[2] + 460 * S, ry + 70 * S)], radius=10 * S, fill=PANEL, outline=LINE, width=S)
    draw.rounded_rectangle([(xs[2], ry), (xs[2] + 4 * S, ry + 70 * S)], radius=2 * S, fill=RED)
    draw.text((xs[2] + 18 * S, ry + 12 * S), "R-01 … R-07", font=font(SANS, 14 * S), fill=TEXT)
    draw.text(
        (xs[2] + 18 * S, ry + 36 * S),
        "brute force · success-after-failure · enumeration · spray",
        font=font(MONO, 10 * S),
        fill=DIM,
    )
    draw.text(
        (xs[2] + 18 * S, ry + 52 * S),
        "privileged login · sudo escalation · off-hours",
        font=font(MONO, 10 * S),
        fill=DIM,
    )
    arrow(draw, xs[2] + 90 * S, y + bh + 4 * S, xs[2] + 90 * S, ry - 4 * S)

    draw.text(
        (28 * S, H - 26 * S),
        "Nothing leaves the machine: loghawk never uploads, never connects, and never modifies the input file.",
        font=font(MONO, 10 * S),
        fill=DIM,
    )

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    image.save(target, "PNG", optimize=True)
    print(f"wrote {target} ({image.width}x{image.height}, {os.path.getsize(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
