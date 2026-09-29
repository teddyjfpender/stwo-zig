"""End-to-end run over contiguous mainnet blocks: leaves -> proofs -> aggregation.

1. assemble contiguous multi-block leaf PIEs from recorded blocks (``assemble.py``,
   replay proxy) and check each against the chain's state roots;
2. prove each leaf with stwo-zig (``run-and-prove --program-type pie``, the PIE
   run as a task of the simple bootloader) and verify in-process;
3. verify every proof again with the official Rust Stwo-Cairo verifier;
4. run the Starknet aggregator (``core/aggregator/main.cairo``) over the leaf
   outputs, which checks that each leaf starts where the previous one ended;
5. prove and verify the aggregator PIE the same way.

Stages run one at a time with a swap guard: this host has 36 GB.
What this does NOT do: verify the leaf proofs inside the aggregation (recursion),
which needs StarkWare's circuit verifier / applicative bootloader.

    python prove_pipeline.py --data block-data --start 15627902 --blocks-per-leaf 3 --leaves 2
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROVER = REPO / "zig-out/bin/stwo-cairo-cpu"
VERIFIER = REPO / "tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier"
AGGREGATOR = Path.home() / "Coding/snos/target/release/starknet-aggregator"
MAX_SWAP_MB = 20_000


def swap_used_mb() -> float:
    out = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True).stdout
    m = re.search(r"used = ([0-9.]+)M", out)
    return float(m.group(1)) if m else 0.0


def timed(cmd: list[str], log: Path) -> dict:
    """Run under /usr/bin/time -l; return wall seconds, peak memory and exit code."""
    if swap_used_mb() > MAX_SWAP_MB:
        sys.exit(f"swap above {MAX_SWAP_MB} MB; refusing to start {cmd[0]}")
    t0 = time.time()
    with open(log, "w") as f:
        rc = subprocess.run(["/usr/bin/time", "-l", *cmd], stdout=f, stderr=subprocess.STDOUT).returncode
    text = log.read_text(errors="replace")
    peak = re.search(r"(\d+)\s+peak memory footprint", text)
    return {"exit": rc, "wall_s": round(time.time() - t0, 3),
            "peak_gb": round(int(peak.group(1)) / 1e9, 3) if peak else None}


def prove_and_verify(pie: Path, out: Path) -> dict:
    proof = out / f"{pie.stem}.proof"
    proof.unlink(missing_ok=True)
    r = {"pie": str(pie)}
    r["prove"] = timed([str(PROVER), "run-and-prove", "--program", str(pie), "--program-type", "pie",
                        "--proof", str(proof), "--proof-format", "binary",
                        "--report-out", str(out / f"{pie.stem}.report.json"), "--verify"],
                       out / f"{pie.stem}.prove.log")
    if r["prove"]["exit"] != 0 or not proof.exists():
        r["error"] = (out / f"{pie.stem}.prove.log").read_text(errors="replace")[-600:]
        return r
    r["proof_bytes"] = proof.stat().st_size
    verdict = out / f"{pie.stem}.official-verdict.json"
    verdict.unlink(missing_ok=True)
    r["official_verify"] = timed([str(VERIFIER), "verify", "--proof", str(proof), "--channel", "blake2s",
                                  "--proof-format", "binary", "--result", str(verdict)],
                                 out / f"{pie.stem}.verify.log")
    if verdict.exists():
        r["official_verdict"] = json.loads(verdict.read_text())
    return r


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--blocks-per-leaf", type=int, required=True)
    ap.add_argument("--leaves", type=int, required=True)
    ap.add_argument("--replay-port", type=int, default=9546)
    args = ap.parse_args()

    base = args.data / "mainnet"
    first, last = args.start, args.start + args.blocks_per_leaf * args.leaves - 1
    out = base / "pipeline" / f"{first}-{last}_x{args.leaves}"
    out.mkdir(parents=True, exist_ok=True)
    results: dict = {"blocks": [first, last], "blocks_per_leaf": args.blocks_per_leaf, "leaves": []}

    print(f"[1/5] assembling {args.leaves} leaves of {args.blocks_per_leaf} blocks from {first}")
    rc = subprocess.run([sys.executable, str(HERE / "assemble.py"), "--data", str(args.data), "--start", str(first),
                         "--blocks-per-leaf", str(args.blocks_per_leaf), "--leaves", str(args.leaves),
                         "--replay-port", str(args.replay_port)]).returncode
    if rc != 0:
        sys.exit("assembly failed")
    index = json.loads((base / "pies/leaves/leaves.json").read_text())
    leaf_pies = []
    for j in range(args.leaves):
        a = first + j * args.blocks_per_leaf
        name = f"{a}-{a + args.blocks_per_leaf - 1}"
        info = index[name]
        if not info.get("roots_match"):
            sys.exit(f"leaf {name} does not match the chain's state roots")
        leaf_pies.append(base / "pies/leaves" / f"{name}.zip")
        results["leaves"].append({"name": name, **{k: info[k] for k in ("n_blocks", "n_steps", "pie_bytes", "roots_match")}})

    for j, pie in enumerate(leaf_pies):
        print(f"[2-3/5] proving + verifying leaf {pie.stem}")
        results["leaves"][j].update(prove_and_verify(pie, out))
        print("   ", json.dumps({k: results["leaves"][j].get(k) for k in ("prove", "proof_bytes", "official_verdict")}))

    print("[4/5] running the Starknet aggregator over the leaf outputs")
    agg = out / f"aggregator-{first}-{last}.zip"
    agg_out = out / f"aggregator-{first}-{last}.output.json"
    agg_log = out / "aggregator.log"
    agg_run = timed([str(AGGREGATOR), "--leaves", *map(str, leaf_pies), "--output", str(agg), "--program-output", str(agg_out)], agg_log)
    summary = [line for line in agg_log.read_text().splitlines() if line.startswith("{")]
    results["aggregator"] = {"run": agg_run, **(json.loads(summary[-1]) if summary else {})}
    if agg_run["exit"] != 0:
        results["aggregator"]["error"] = agg_log.read_text()[-600:]
        (out / "results.json").write_text(json.dumps(results, indent=1))
        sys.exit("aggregator failed")

    print("[5/5] proving + verifying the aggregator PIE")
    results["aggregator"].update(prove_and_verify(agg, out))
    (out / "results.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
