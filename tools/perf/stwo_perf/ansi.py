"""Terminal formatting: colors, rules, key-value panels, and aligned tables.

Stdlib only. Honors NO_COLOR and non-TTY output so piped output stays clean.
"""

from __future__ import annotations

import os
import sys

_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

RESET = "\x1b[0m"
_STYLES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "iris": "38;5;99",
    "amber": "38;5;179",
}

OK = "✓"
FAIL = "✗"
NEUTRAL = "◦"
ARROW = "→"


def style(text: str, *names: str) -> str:
    if not _ENABLED or not names:
        return text
    codes = ";".join(_STYLES[n] for n in names if n in _STYLES)
    return f"\x1b[{codes}m{text}{RESET}"


def rule(title: str = "", width: int = 72) -> str:
    if not title:
        return style("─" * width, "dim")
    label = f" {title} "
    pad = max(0, width - len(label) - 2)
    return style("──", "dim") + style(label, "bold") + style("─" * pad, "dim")


def kv_panel(title: str, pairs: list[tuple[str, str]], width: int = 72) -> str:
    """A labeled block of aligned key/value lines under a rule."""
    lines = [rule(title, width)]
    if pairs:
        key_w = max(len(k) for k, _ in pairs)
        for key, value in pairs:
            lines.append(f"  {style(key.ljust(key_w), 'dim')}  {value}")
    return "\n".join(lines)


def table(headers: list[str], rows: list[list[str]], aligns: str | None = None) -> str:
    """Aligned table. `aligns` is one char per column: 'l' or 'r'."""
    aligns = aligns or "l" * len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(_strip(cell)))

    def fmt(cells: list[str]) -> str:
        out = []
        for i, cell in enumerate(cells):
            pad = widths[i] - len(_strip(cell))
            out.append(cell + " " * pad if aligns[i] == "l" else " " * pad + cell)
        return "  ".join(out)

    header = style(fmt(headers), "dim")
    sep = style("  ".join("─" * w for w in widths), "dim")
    return "\n".join([header, sep] + [fmt(r) for r in rows])


def gate_mark(passed: bool) -> str:
    return style(OK, "green") if passed else style(FAIL, "red")


def ratio(value: float) -> str:
    """Color a paired ratio: <1 improves (iris), >1 regresses (red)."""
    text = f"{value:.4f}"
    if value < 1.0:
        return style(text, "iris")
    if value > 1.0:
        return style(text, "red")
    return text


def _strip(text: str) -> str:
    """Length of text without ANSI escapes."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\x1b":
            j = text.find("m", i)
            i = (j + 1) if j != -1 else len(text)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)
