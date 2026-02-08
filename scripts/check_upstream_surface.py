#!/usr/bin/env python3
"""Validate that API_PARITY rust_path entries resolve in pinned upstream."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
API_PARITY_PATH = ROOT / "API_PARITY.md"
UPSTREAM_PATH = ROOT / "UPSTREAM.md"

API_PARITY_JSON_START = "<!-- API_PARITY_JSON_START -->"
API_PARITY_JSON_END = "<!-- API_PARITY_JSON_END -->"

REQUIRED_CRATE_ROOTS = {
    "crates/stwo/src/lib.rs",
    "crates/constraint-framework/src/lib.rs",
    "crates/air-utils/src/lib.rs",
    "crates/air-utils-derive/src/lib.rs",
    "crates/examples/src/lib.rs",
    "crates/std-shims/src/lib.rs",
}


def parse_upstream_commit() -> str:
    text = UPSTREAM_PATH.read_text(encoding="utf-8")
    match = re.search(r"Pinned commit:\s*`([0-9a-f]{40})`", text)
    if not match:
        raise RuntimeError("failed to parse pinned commit from UPSTREAM.md")
    return match.group(1)


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


def exists_in_upstream(repo: str, commit: str, path: str) -> tuple[bool, str]:
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    req = urllib.request.Request(url=url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=20):
            return True, url
    except urllib.error.HTTPError as e:
        if e.code == 405:
            # Some paths may not support HEAD in intermediate proxies; retry GET.
            try:
                with urllib.request.urlopen(url, timeout=20):
                    return True, url
            except urllib.error.HTTPError as inner:
                return False, f"{url} (HTTP {inner.code})"
            except urllib.error.URLError as inner:
                return False, f"{url} ({inner})"
        return False, f"{url} (HTTP {e.code})"
    except urllib.error.URLError as e:
        return False, f"{url} ({e})"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate upstream rust_path parity references")
    parser.add_argument(
        "--repo",
        default="starkware-libs/stwo",
        help="GitHub repo path used for rust_path verification",
    )
    args = parser.parse_args()

    commit = parse_upstream_commit()
    payload = parse_api_parity_json()

    symbols = payload.get("symbols")
    if not isinstance(symbols, dict):
        raise RuntimeError("API_PARITY payload missing symbols object")

    rust_paths = {
        str(entry.get("rust_path"))
        for entry in symbols.values()
        if isinstance(entry, dict) and isinstance(entry.get("rust_path"), str)
    }

    failures: list[str] = []

    missing_roots = sorted(REQUIRED_CRATE_ROOTS - rust_paths)
    if missing_roots:
        failures.append("missing required crate root mappings: " + ", ".join(missing_roots))

    for path in sorted(rust_paths):
        ok, detail = exists_in_upstream(args.repo, commit, path)
        if not ok:
            failures.append(f"rust_path not found upstream: {path} ({detail})")

    if failures:
        sys.stderr.write("upstream surface check failed:\n")
        for failure in failures:
            sys.stderr.write(f"- {failure}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
