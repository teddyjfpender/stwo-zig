"""Assemble contiguous multi-block leaf PIEs from recorded blocks.

Runs SNOS ``generate-pie`` over consecutive blocks against a *replay* proxy,
so no live proof window is involved. Each leaf is checked against the chain's
state roots (the first block's ``old_root`` and the last block's ``new_root``).

    python assemble.py --data block-data --start 15628000 --blocks-per-leaf 30 --leaves 5

Output: ``<data>/mainnet/pies/leaves/<first>-<last>.zip`` and ``leaves.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pie_info import pie_summary  # noqa: E402
from rpc_store import RpcStore  # noqa: E402


def ok_blocks(store: RpcStore) -> set[int]:
    good = set()
    for meta in store.blocks.glob("*/meta.json"):
        try:
            if json.loads(meta.read_text()).get("status") == "ok":
                good.add(int(meta.parent.name))
        except (ValueError, OSError):
            pass
    return good


def contiguous_runs(blocks: set[int]) -> list[tuple[int, int]]:
    runs, start = [], None
    for b in sorted(blocks):
        if start is None or b != prev + 1:
            if start is not None:
                runs.append((start, prev))
            start = b
        prev = b
    if start is not None:
        runs.append((start, prev))
    return runs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--network", default="mainnet")
    ap.add_argument("--replay-port", type=int, default=9546)
    ap.add_argument("--generate-pie", type=Path, default=Path.home() / "Coding/snos/target/release/generate-pie")
    ap.add_argument("--start", type=int, help="first block (default: start of the longest ok run)")
    ap.add_argument("--blocks-per-leaf", type=int, required=True)
    ap.add_argument("--leaves", type=int, default=1)
    ap.add_argument("--runs", action="store_true", help="only list contiguous ok runs")
    args = ap.parse_args()

    store = RpcStore(args.data, args.network)
    good = ok_blocks(store)
    runs = contiguous_runs(good)
    if args.runs:
        for a, b in sorted(runs, key=lambda r: r[0] - r[1])[:10]:
            print(f"{a}..{b}  ({b - a + 1} blocks)")
        return
    start = args.start or max(runs, key=lambda r: r[1] - r[0])[0]
    need = range(start, start + args.blocks_per_leaf * args.leaves)
    missing = [b for b in need if b not in good]
    if missing:
        sys.exit(f"blocks not collected ok: {missing[:10]}{'…' if len(missing) > 10 else ''}")

    out_dir = store.base / "pies" / "leaves"
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "leaves.json"
    index = json.loads(index_path.read_text()) if index_path.exists() else {}
    for j in range(args.leaves):
        first = start + j * args.blocks_per_leaf
        last = first + args.blocks_per_leaf - 1
        name = f"{first}-{last}"
        pie = out_dir / f"{name}.zip"
        log = out_dir / f"{name}.log"
        t0 = time.time()
        if not pie.exists():
            with open(log, "wb") as f:
                rc = subprocess.run(
                    [str(args.generate_pie), "--blocks", ",".join(str(b) for b in range(first, last + 1)),
                     "--rpc-url", f"http://127.0.0.1:{args.replay_port}/b/{first}", "--chain", args.network,
                     "--output", str(pie)],
                    stdout=f, stderr=f, env={**os.environ, "RUST_LOG": "info"}).returncode
            if rc != 0:
                print(f"{name}: generate-pie failed (see {log})")
                continue
        info = pie_summary(pie)
        su_first = store.lookup("starknet_getStateUpdate", {"block_id": {"block_number": first}})["result"]
        su_last = store.lookup("starknet_getStateUpdate", {"block_id": {"block_number": last}})["result"]
        info["roots_match"] = (int(info["initial_root"], 16) == int(su_first["old_root"], 16)
                               and int(info["final_root"], 16) == int(su_last["new_root"], 16))
        info["generate_s"] = round(time.time() - t0, 1)
        index[name] = info
        index_path.write_text(json.dumps(index, indent=1))
        print(f"{name}: blocks={info['n_blocks']} steps={info['n_steps']:,} roots_match={info['roots_match']} "
              f"size={info['pie_bytes'] / 1e6:.0f}MB t={info['generate_s']}s")


if __name__ == "__main__":
    main()
