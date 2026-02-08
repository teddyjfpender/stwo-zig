#!/usr/bin/env python3
"""Validate API parity ledger coverage and metadata."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
API_PARITY_PATH = ROOT / "API_PARITY.md"
UPSTREAM_PATH = ROOT / "UPSTREAM.md"

API_PARITY_JSON_START = "<!-- API_PARITY_JSON_START -->"
API_PARITY_JSON_END = "<!-- API_PARITY_JSON_END -->"

EXPORT_FILES: dict[str, str] = {
    "src/stwo.zig": "stwo",
    "src/core/mod.zig": "stwo.core",
    "src/prover/mod.zig": "stwo.prover",
    "src/examples/mod.zig": "stwo.examples",
    "src/interop/mod.zig": "stwo.interop",
    "src/std_shims/mod.zig": "stwo.std_shims",
    "src/tracing/mod.zig": "stwo.tracing",
    "src/core/fields/mod.zig": "stwo.core.fields",
    "src/core/channel/mod.zig": "stwo.core.channel",
    "src/core/crypto/mod.zig": "stwo.core.crypto",
    "src/core/poly/mod.zig": "stwo.core.poly",
    "src/core/vcs/mod.zig": "stwo.core.vcs",
    "src/core/vcs_lifted/mod.zig": "stwo.core.vcs_lifted",
    "src/core/pcs/mod.zig": "stwo.core.pcs",
    "src/core/air/mod.zig": "stwo.core.air",
    "src/core/constraint_framework/mod.zig": "stwo.core.constraint_framework",
    "src/prover/air/mod.zig": "stwo.prover.air",
    "src/prover/channel/mod.zig": "stwo.prover.channel",
    "src/prover/lookups/mod.zig": "stwo.prover.lookups",
    "src/prover/pcs/mod.zig": "stwo.prover.pcs",
    "src/prover/poly/mod.zig": "stwo.prover.poly",
    "src/prover/vcs/mod.zig": "stwo.prover.vcs",
    "src/prover/vcs_lifted/mod.zig": "stwo.prover.vcs_lifted",
}


def parse_upstream_commit() -> str:
    text = UPSTREAM_PATH.read_text(encoding="utf-8")
    match = re.search(r"Pinned commit:\s*`([0-9a-f]{40})`", text)
    if not match:
        raise RuntimeError("failed to parse pinned commit from UPSTREAM.md")
    return match.group(1)


def parse_exports() -> dict[str, dict[str, str]]:
    pat = re.compile(r"^pub\s+(const|fn)\s+([A-Za-z0-9_]+)")
    out: dict[str, dict[str, str]] = {}
    for rel_path, prefix in EXPORT_FILES.items():
        path = ROOT / rel_path
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            match = pat.match(line)
            if not match:
                continue
            kind, name = match.group(1), match.group(2)
            symbol = f"{prefix}.{name}"
            out[symbol] = {"kind": kind, "source": rel_path}
    return out


def parse_api_parity_json() -> dict:
    text = API_PARITY_PATH.read_text(encoding="utf-8")
    start = text.find(API_PARITY_JSON_START)
    end = text.find(API_PARITY_JSON_END)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("failed to locate API parity JSON markers in API_PARITY.md")
    snippet = text[start + len(API_PARITY_JSON_START) : end]
    match = re.search(r"```json\s*(\{.*\})\s*```", snippet, re.DOTALL)
    if not match:
        raise RuntimeError("failed to locate JSON code block between parity markers")
    return json.loads(match.group(1))


def validate() -> int:
    upstream_commit = parse_upstream_commit()
    expected_exports = parse_exports()
    parity_payload = parse_api_parity_json()

    errors: list[str] = []
    payload_commit = parity_payload.get("upstream_commit")
    if payload_commit != upstream_commit:
        errors.append(
            f"upstream commit mismatch: API_PARITY.md has {payload_commit}, UPSTREAM.md has {upstream_commit}"
        )

    symbols = parity_payload.get("symbols")
    if not isinstance(symbols, dict):
        errors.append("API parity payload missing object field 'symbols'")
        symbols = {}

    expected_keys = set(expected_exports.keys())
    actual_keys = set(symbols.keys())
    missing = sorted(expected_keys - actual_keys)
    extra = sorted(actual_keys - expected_keys)
    if missing:
        errors.append("missing parity entries:\n  " + "\n  ".join(missing))
    if extra:
        errors.append("unexpected parity entries:\n  " + "\n  ".join(extra))

    for symbol in sorted(expected_keys & actual_keys):
        entry = symbols.get(symbol)
        if not isinstance(entry, dict):
            errors.append(f"{symbol}: entry must be an object")
            continue

        rust_path = entry.get("rust_path")
        rationale = entry.get("rationale")
        has_rust_path = isinstance(rust_path, str) and len(rust_path.strip()) > 0
        has_rationale = isinstance(rationale, str) and len(rationale.strip()) > 0
        if not has_rust_path and not has_rationale:
            errors.append(f"{symbol}: must define non-empty rust_path or rationale")
        if rust_path is not None and not isinstance(rust_path, str):
            errors.append(f"{symbol}: rust_path must be string or null")
        if rationale is not None and not isinstance(rationale, str):
            errors.append(f"{symbol}: rationale must be string or null")

        kind = entry.get("kind")
        source = entry.get("source")
        expected = expected_exports[symbol]
        if kind != expected["kind"]:
            errors.append(f"{symbol}: kind mismatch ({kind} != {expected['kind']})")
        if source != expected["source"]:
            errors.append(f"{symbol}: source mismatch ({source} != {expected['source']})")

    if errors:
        sys.stderr.write("API parity validation failed:\n")
        for err in errors:
            sys.stderr.write(f"- {err}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(validate())
