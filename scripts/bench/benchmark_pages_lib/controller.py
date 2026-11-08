"""Command-line boundary for deterministic benchmark site generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import CatalogError, build_catalog


ROOT = Path(__file__).resolve().parents[2]
HISTORY_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_history"
SITE_DEFAULT = ROOT / "bench" / "site"
REQUIRED_ASSETS = (
    "index.html",
    "assets/styles.css",
    "assets/responsive.css",
    "assets/app.js",
)


def encoded_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-dir", type=Path, default=HISTORY_DEFAULT)
    parser.add_argument("--site-dir", type=Path, default=SITE_DEFAULT)
    parser.add_argument("--validate", action="store_true")
    return parser.parse_args(argv)


def validate_assets(site_dir: Path) -> None:
    missing = [name for name in REQUIRED_ASSETS if not (site_dir / name).is_file()]
    if missing:
        raise CatalogError("benchmark site assets are missing: " + ", ".join(missing))
    html = (site_dir / "index.html").read_text(encoding="utf-8")
    for marker in ('role="tablist"', 'id="overview-panel"', 'id="provenance-panel"'):
        if marker not in html:
            raise CatalogError(f"benchmark site shell is missing {marker}")


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    catalog = build_catalog(args.history_dir)
    expected = encoded_json(catalog)
    output = args.site_dir / "data" / "catalog.json"
    if args.validate:
        validate_assets(args.site_dir)
        if not output.is_file():
            raise CatalogError("benchmark site catalog is missing")
        if output.read_bytes() != expected:
            raise CatalogError("benchmark site catalog is stale; regenerate it")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected)
    validate_assets(args.site_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except (CatalogError, OSError) as error:
        print(f"benchmark pages: {error}")
        return 1
