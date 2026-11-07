#!/usr/bin/env python3
"""Measure admitted OP Mainnet or OP-Sepolia execution; never label execution as a STARK proof."""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.riscv64_csp_compare import elf_info


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    return subprocess.run(
        [str(x) for x in args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=900,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument(
        "--host", type=Path, default=ROOT / "opstack/kona/target/release/stwo-kona-host"
    )
    parser.add_argument("--guest", type=Path)
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--network", choices=("mainnet", "sepolia"), default="mainnet")
    parser.add_argument(
        "--blocks",
        type=int,
        nargs="+",
        default=None,
    )
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument(
        "--pairing-hints",
        action="store_true",
        help="generate advice with the canonical-glv-hinted build's host",
    )
    parser.add_argument("--isolated-only", action="store_true")
    parser.add_argument(
        "--profile", choices=("software", "ethereum_services_v3"), default="software"
    )
    args = parser.parse_args()
    if args.blocks is None:
        args.blocks = (
            [120794432, 121003241, 121049889, 121057303, 121065789, 121135704]
            if args.network == "mainnet"
            else [26207960, 26207961, 26207962, 26207963]
        )
    expected_chain = 10 if args.network == "mainnet" else 11155420
    for block in args.blocks:
        fixture = json.loads(
            (args.fixtures / f"block-{block}" / "fixture.json").read_text()
        )
        chain = fixture["rollup_config"]["l2_chain_id"]
        chain = {"optimism": 10, "optimism-sepolia": 11155420}.get(str(chain), chain)
        if int(str(chain), 0) != expected_chain:
            parser.error("fixture chain does not match selected network")
    if args.network == "mainnet":
        args.isolated_only = True  # Historical archive blocks are nonadjacent.
    if not 1 <= args.samples <= 9 or not 1 <= len(args.blocks) <= 32:
        parser.error("samples 1..9; blocks 1..32")
    if args.pairing_hints and not args.guest:
        parser.error("--pairing-hints requires the hinted guest and runner")
    if bool(args.guest) != bool(args.runner):
        parser.error("guest and runner are required together")
    args.artifacts.mkdir(parents=True, exist_ok=False)
    cases = [(str(block), [block]) for block in args.blocks]
    if len(args.blocks) > 1 and not args.isolated_only:
        cases.append((f"range-{len(args.blocks)}", args.blocks))
    rows = []
    for name, blocks in cases:
        path = (args.artifacts / f"{name}.opx").resolve()
        run([args.host, "pack", path, *[args.fixtures / f"block-{b}" for b in blocks]])
        for mode in ("eager", "lazy"):
            observed = []
            for sample in range(args.samples):
                record = json.loads(run([args.host, "run", path, mode]).stdout)
                record.update(case=name, sample=sample, input_sha256=sha(path))
                observed.append(record)
            if len({r["digest"] for r in observed}) != 1:
                raise ValueError("native output varies")
            rows.append(
                {
                    "case": name,
                    "mode": mode,
                    "samples": observed,
                    "median_s": statistics.median(r["total_s"] for r in observed),
                }
            )
        eager, lazy = rows[-2:]
        if eager["samples"][0]["digest"] != lazy["samples"][0]["digest"]:
            raise ValueError("eager/lazy mismatch")
        if args.pairing_hints:
            hinted = path.with_suffix(".hinted.opx")
            start = time.monotonic_ns()
            run([args.host, "pairing-hints", path, hinted])
            rows.append(
                {
                    "case": name,
                    "mode": "pairing-hint-generation",
                    "wall_ns": time.monotonic_ns() - start,
                    "base_sha256": sha(path),
                    "hinted_sha256": sha(hinted),
                    "added_bytes": hinted.stat().st_size - path.stat().st_size,
                }
            )
            path = hinted
        if args.guest:
            _, symbols, _ = elf_info(args.guest)
            names = (
                "input_start",
                "input_end",
                "halt_flag",
                "output_len",
                "output_data",
                "output_end",
                "stack_bottom",
                "stack_top",
                "heap_start",
                "heap_end",
            )
            config = {
                "elf": str(args.guest.resolve()),
                "input": str(path),
                "expected_output": lazy["samples"][0]["output"],
                "elf_sha256": sha(args.guest),
                "input_sha256": sha(path),
                "max_steps": 10_000_000_000,
                "engine": "fast",
                "execution_profile": args.profile,
                "symbols": {n: symbols["__" + n] for n in names},
            }
            config_path = args.artifacts / f"{name}-config.json"
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            record = json.loads(run([args.runner, config_path]).stdout)
            # Retain trapping/incomplete candidates as evidence too. Promotion
            # and proof-config generation still require complete exact output.
            (args.artifacts / f"{name}-rv64.json").write_text(
                json.dumps(record, indent=2) + "\n"
            )
            if (
                record.get("status") != "completed"
                or record.get("verified_output") is not True
            ):
                raise ValueError(
                    "production RV64 execution did not complete with expected output"
                )
            record.update(completed=True, proof_verified=False)
            record["sponge_calls"] = record["keccak_sponge_calls"]
            gas = lazy["samples"][0]["gas_used"]
            proof_config = {k: v for k, v in config.items() if k not in ("engine",)}
            proof_config.update(
                terminal_pc=record["pc"],
                execution_profile="ethereum_services_v3",
                batch_steps=4_194_303,
                max_steps=record["instructions"] + 1,
                output_directory=str((args.artifacts / f"{name}-proof").resolve()),
                workers=2,
            )
            (args.artifacts / f"{name}-proof-config.json").write_text(
                json.dumps(proof_config, indent=2) + "\n"
            )
            record.update(
                case=name,
                gas_used=gas,
                instructions_per_gas=record["instructions"] / gas,
            )
            (args.artifacts / f"{name}-rv64.json").write_text(
                json.dumps(record, indent=2) + "\n"
            )
            if args.oracle:
                from opstack.oracle import execute

                independent = execute(config, record["instructions"])
                if (
                    independent["output"] != record["output"]
                    or independent["final_registers"] != record["final_registers"]
                    or independent["post_store_pc"] != record["pc"]
                ):
                    raise ValueError("RV64/oracle mismatch")
                for key, value in independent["services"].items():
                    if record[key] != value:
                        raise ValueError(
                            f"RV64/oracle service count mismatch {key}: {record[key]} vs {value}"
                        )
                (args.artifacts / f"{name}-oracle.json").write_text(
                    json.dumps(independent, indent=2) + "\n"
                )
            rows.append(
                {"case": name, "mode": "rv64-" + args.profile, "samples": [record]}
            )
        # Write a checkpoint after each completed case, so a large failure loses no receipts.
        (args.artifacts / "measurements.json").write_text(
            json.dumps(rows, indent=2) + "\n"
        )
        print(name, "native execution accepted", flush=True)
    sources = {
        str(p.relative_to(ROOT)): sha(p)
        for p in (ROOT / "opstack").rglob("*")
        if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts
    }
    provenance = {
        "schema": "stwo.opstack.benchmark.v1",
        "network": args.network,
        "chain_id": expected_chain,
        "source_head": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "source_hashes": sources,
        "host_sha256": sha(args.host),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "cpu_quota": Path("/sys/fs/cgroup/cpu.max").read_text().strip()
        if Path("/sys/fs/cgroup/cpu.max").exists()
        else None,
        "scope": "native execution and optional RV64 instruction counts; no STARK proof or GPU measurement",
        "native_process_state": "fresh process for every sample; fixture I/O excluded from internal total_s",
        "rows": rows,
    }
    (args.artifacts / "summary.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
