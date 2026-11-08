"""Parse the stable hotspot section emitted by macOS ``sample``."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .model import CaptureError


HOTSPOT_MARKER = "Sort by top of stack, same collapsed"
HOTSPOT_RE = re.compile(r"^\s*(.+?)\s+\(in .+\)\s+(\d+)$")


def parse_hotspots(text: str, *, top: int = 32) -> list[dict[str, Any]]:
    start = text.find(HOTSPOT_MARKER)
    if start < 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in text[start:].splitlines()[1:]:
        if line.startswith("Binary Images:"):
            break
        match = HOTSPOT_RE.match(line)
        if match is None:
            continue
        rows.append({"symbol": match.group(1).strip(), "samples": int(match.group(2))})
        if len(rows) == top:
            break
    return rows


def build_sample_summary(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="strict")
    hotspots = parse_hotspots(text)
    if not hotspots:
        raise CaptureError(f"CPU sample has no parsed top-of-stack hotspots: {path}")
    total = sum(row["samples"] for row in hotspots)
    if total <= 0:
        raise CaptureError(f"CPU sample has no positive hotspot samples: {path}")
    return {
        "schema": "stwo-native-cpu-sample-summary-v1",
        "collector": "macos_usr_bin_sample_v1",
        "hotspots": hotspots,
        "top_hotspot_samples": total,
    }
