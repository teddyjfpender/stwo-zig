#!/usr/bin/env python3
"""Capture the ready PIE catalogue and flatten its per-PIE metadata to CSV.

Metadata from the API describes PIE generation, not proof generation. The
result deliberately keeps proving columns empty until measured receipts are
joined by PIE name. A JSONL cache permits safe restarts of large catalogues.
"""

import argparse
import concurrent.futures
import csv
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

from fetch_starknet_pies import DEFAULT_BASE, SafeRedirect, fetch_meta, open_api


def catalogue(base: str, key: str) -> list[dict]:
    opener = urllib.request.build_opener(SafeRedirect())
    rows: list[dict] = []
    seen: set[str] = set()
    after = None
    while True:
        query = {"status": "ready", "limit": 1000}
        if after is not None:
            query["after"] = after
        with open_api(opener, base, "/v1/pies?" + urllib.parse.urlencode(query), key) as response:
            page = json.load(response)
        if not isinstance(page, dict) or not isinstance(page.get("pies"), list):
            raise ValueError("invalid ready PIE catalogue page")
        for row in page["pies"]:
            name = row.get("pie")
            if (not isinstance(name, str) or name in seen or row.get("status") != "ready"
                    or not isinstance(row.get("os_steps"), int)):
                raise ValueError(f"invalid or duplicate ready PIE row: {name}")
            seen.add(name)
            rows.append(row)
        next_after = page.get("next_after")
        if next_after is None:
            return rows
        if next_after == after:
            raise ValueError("catalogue cursor did not advance")
        after = next_after


def load_cache(path: Path) -> dict[str, dict]:
    cache: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            row = json.loads(line)
            cache[row["pie"]] = row["meta"]
    return cache


def collect_metadata(base: str, key: str, names: list[str], cache_path: Path,
                     workers: int) -> dict[str, dict]:
    cache = load_cache(cache_path)
    missing = [name for name in names if name not in cache]
    if not missing:
        return cache
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    def fetch(name: str) -> tuple[str, dict]:
        for attempt in range(4):
            try:
                opener = urllib.request.build_opener(SafeRedirect())
                return name, fetch_meta(opener, base, name, key)
            except urllib.error.HTTPError as error:
                if error.code < 500 or attempt == 3:
                    raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 3:
                    raise
            time.sleep(0.5 * (2 ** attempt))
        raise AssertionError("unreachable")

    with cache_path.open("a") as sink, concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (name, meta) in enumerate(pool.map(fetch, missing), 1):
            cache[name] = meta
            sink.write(json.dumps({"pie": name, "meta": meta}, separators=(",", ":")) + "\n")
            sink.flush()
            if index % 250 == 0 or index == len(missing):
                print(f"metadata {index}/{len(missing)} fetched; {len(cache)} cached", flush=True)
    return cache


def flatten(row: dict, meta: dict) -> dict:
    timings = meta.get("timings_s") or {}
    result = {
        "pie": row["pie"], "first": row["first"], "last": row["last"],
        "n_blocks": row["last"] - row["first"] + 1,
        "txs": meta.get("txs", row.get("txs")), "os_steps": meta["os_steps"],
        "n_memory_holes": meta.get("n_memory_holes"),
        "archive_bytes": meta.get("bytes"), "header_matches_chain": meta.get("header_matches_chain"),
        "final_block_hash": meta.get("final_block_hash"),
        "final_state_root": meta.get("final_state_root"),
        "starknet_version": meta.get("starknet_version"), "generator": meta.get("generator"),
        "baked_at": meta.get("baked_at"), "bake_peak_rss_gb": meta.get("peak_rss_gb"),
    }
    result.update({f"builtin_{name}": count for name, count in (meta.get("builtins") or {}).items()})
    result.update({f"bake_{name if name.endswith('_s') else name + '_s'}": value
                   for name, value in timings.items()})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache-jsonl", type=Path, required=True)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-pies", type=int, help="development limit; omit for full catalogue")
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 16 or (args.max_pies is not None and args.max_pies < 1):
        parser.error("workers must be 1..16 and max-pies positive")
    if urllib.parse.urlsplit(args.base).scheme != "https":
        parser.error("--base must use HTTPS")
    key = os.environ.get("STWO_PIE_API_KEY")
    if not key and (file := os.environ.get("STWO_PIE_API_KEY_FILE")):
        key = Path(file).read_text().strip()
    if not key:
        parser.error("STWO_PIE_API_KEY or STWO_PIE_API_KEY_FILE must be set")
    rows = catalogue(args.base, key)
    if args.max_pies:
        rows = rows[:args.max_pies]
    print(f"catalogue contains {len(rows)} selected ready PIEs", flush=True)
    cache = collect_metadata(args.base, key, [row["pie"] for row in rows], args.cache_jsonl, args.workers)
    flat = [flatten(row, cache[row["pie"]]) for row in rows]
    fields = list(dict.fromkeys(key for row in flat for key in row))
    fields = [key for key in fields if not key.startswith(("builtin_", "bake_"))] + sorted(
        key for key in fields if key.startswith(("builtin_", "bake_")))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(flat)
    print(f"wrote {len(flat)} rows and {len(fields)} columns to {args.out}")


if __name__ == "__main__":
    main()
