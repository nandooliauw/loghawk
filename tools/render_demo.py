#!/usr/bin/env python3
"""Render a captured CLI transcript to a PNG terminal card.

The text is real output (see examples/); this script only styles it.

    python tools/render_demo.py examples/demo-output.txt docs/demo.png "loghawk — auth.log"
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw, ImageFont

SCALE = 2
FONT_SIZE = 15 * SCALE
LINE_HEIGHT = int(FONT_SIZE * 1.45)
PAD = 26 * SCALE
BAR = 42 * SCALE
MAX_CHARS = 104

BG = (11, 15, 20)
BORDER = (30, 42, 58)
TEXT = (219, 230, 243)
DIM = (125, 143, 166)
ACCENT = (74, 168, 255)
GREEN = (46, 204, 113)
AMBER = (245, 176, 65)
RED = (231, 76, 60)
CRIMSON = (255, 92, 92)
GREY = (84, 101, 122)

FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]


def load_font() -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if os.path.isfile(path):
            return ImageFont.truetype(path, FONT_SIZE)
    return ImageFont.load_default()


def wrap(line: str, limit: int) -> list[str]:
    if len(line) <= limit:
        return [line]
    indent = " " * (len(line) - len(line.lstrip()) + 2)
    words = line.split(" ")
    out: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= limit or not current:
            current = candidate
        else:
            out.append(current)
            current = indent + word
    if current:
        out.append(current)
    return out


def colour_for(line: str) -> tuple[int, int, int]:
    stripped = line.lstrip()
    if stripped.startswith("CRITICAL"):
        return CRIMSON
    if stripped.startswith("HIGH"):
        return RED
    if stripped.startswith("MEDIUM"):
        return AMBER
    if stripped.startswith("LOW"):
        return ACCENT
    if stripped.startswith("loghawk") or stripped.startswith("findings"):
        return TEXT
    if stripped.startswith("fix:") or stripped.startswith("L") and stripped[1:4].strip().isdigit():
        return DIM
    return TEXT


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else "examples/demo-output.txt"
    target = sys.argv[2] if len(sys.argv) > 2 else "docs/demo.png"
    title = sys.argv[3] if len(sys.argv) > 3 else "loghawk"
    max_lines = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    with open(source, encoding="utf-8", errors="replace") as handle:
        raw_lines = handle.read().replace("\t", "    ").rstrip("\n").split("\n")

    truncated = False
    if max_lines and len(raw_lines) > max_lines:
        raw_lines = raw_lines[:max_lines]
        truncated = True

    lines: list[str] = []
    for line in raw_lines:
        lines.extend(wrap(line, MAX_CHARS))
    if truncated:
        lines.append("")
        lines.append(f"… truncated for the README — full transcript: {source}")

    font = load_font()
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    text_width = max(probe.textlength(line, font=font) for line in lines)
    width = int(text_width) + PAD * 2
    height = BAR + PAD * 2 + LINE_HEIGHT * len(lines)

    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle([(0, 0), (width - 1, height - 1)], radius=14 * SCALE, outline=BORDER, width=SCALE)
    draw.rectangle([(0, BAR), (width, BAR + SCALE)], fill=BORDER)
    for index, colour in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = PAD // 2 + index * 20 * SCALE
        draw.ellipse([(cx, BAR // 2 - 6 * SCALE), (cx + 12 * SCALE, BAR // 2 + 6 * SCALE)], fill=colour)
    draw.text((width // 2, BAR // 2), title, font=font, fill=DIM, anchor="mm")

    y = BAR + PAD
    for line in lines:
        draw.text((PAD, y), line, font=font, fill=colour_for(line))
        y += LINE_HEIGHT

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    image.save(target, "PNG", optimize=True)
    print(f"wrote {target} ({image.width}x{image.height}, {os.path.getsize(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
