#!/usr/bin/env python3
"""Fresh expected-state verification of one PCS CPU/ROM/range/DIV proof."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def qualify(verifier, artifacts):
    public_path, claims_path, proof_path = [artifacts / name for name in ("public.json", "claims.json", "proof.bin")]
    public, claims = json.loads(public_path.read_text()), json.loads(claims_path.read_text())
    negative = artifacts / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", public_path, claims_path, proof_path, None)]
    public_mutations = [
        ("division-count", lambda p: p.__setitem__("division_requests", p["division_requests"] + 1), "Rv64FullStateClosure"),
        ("immutable-program", lambda p: p["statement"]["program"]["words"].__setitem__(-1, p["statement"]["program"]["words"][-1] ^ 0x100000), "Rv64LeanFixedRootMismatch"),
        ("terminal-register", lambda p: p["statement"]["final_registers"].__setitem__(3, p["statement"]["final_registers"][3] ^ 1), "Rv64FullStateClosure"),
        ("terminal-pc", lambda p: p["statement"].__setitem__("final_pc", p["statement"]["final_pc"] + 4), "Rv64FullStateClosure"),
        ("initial-ram", lambda p: p["statement"]["cells"][0].__setitem__("initial", 1), "Rv64FullStateClosure"),
        ("terminal-ram", lambda p: p["statement"]["cells"][0].__setitem__("final", p["statement"]["cells"][0]["final"] ^ 1), "Rv64FullStateClosure"),
        ("ram-write-permission", lambda p: p["statement"]["cells"][0].__setitem__("writable", False), "Rv64FullStateClosure"),
    ]
    for name, mutate, error in public_mutations:
        value = copy.deepcopy(public)
        mutate(value)
        path = negative / (name + ".json")
        path.write_text(json.dumps(value))
        cases.append((name, path, claims_path, proof_path, error))
    for name, family, limb, value, error in (
            ("division-claim", "division", "a", (claims["division"]["c0"]["a"]["v"] + 1) % 2147483647, "OodsNotMatching"),
            ("noncanonical-division", "division", "a", 2147483647, "InvalidRv64LeanClaim")):
        changed = copy.deepcopy(claims)
        changed[family]["c0"][limb]["v"] = value
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, public_path, path, proof_path, error))
    cases.append(("previous-cpu-division-prefix", public_path, claims_path, artifacts / "bad-previous-prefix.bin", "OodsNotMatching"))
    outcomes = []
    receiver_cost = None
    for name, public_file, claims_file, proof, expected in cases:
        result = subprocess.run([str(verifier), str(public_file), str(claims_file), str(proof)], capture_output=True, text=True, timeout=120)
        passed = (result.returncode == 0 and json.loads(result.stdout).get("verified") is True) if expected is None else (result.returncode > 0 and expected in result.stderr)
        if not passed:
            raise ValueError(f"unexpected receiver result {name}: {result.returncode} {result.stderr[:500]}")
        if expected is None:
            receiver_cost = json.loads(result.stdout)
        outcomes.append({"case": name, "expected_accept": expected is None, "passed": True,
                         "receiver_exit": result.returncode, "error": result.stderr.splitlines()[0] if result.stderr else None})
    return {"schema": "rv64-lean-one-pcs-qualification-v1", "profile": "division_service_v2",
            "one_pcs_cpu_rom_range_division_verified": True, "ethereum_block_proof": False,
            "steps": public["statement"]["steps"], "division_requests": public["division_requests"],
            "queries": 70, "pow_bits": 26,
            "components": {"cpu_log": 7, "rom_log": 7, "byte_log": 8, "and_log": 16, "shift_log": 11, "division_log": 5},
            "execution": "DIVW/REMW signed W, DIVU/REMU zero divisor, SD/LD, AND/SRA, ADDI; full64 PC and RAM address",
            "receiver_cost_single_run": receiver_cost,
            "receiver_cost_scope": "fresh process including independently derived preprocessing; one diagnostic sample, not a latency benchmark",
            "source_ownership": "CPU+DIV source arenas consumed by one main commitment; cached tuples checked by AIR; all provider main sealed before challenges",
            "artifacts": [identity(path) for path in (public_path, claims_path, proof_path, artifacts / "bad-previous-prefix.bin", verifier)],
            "cases": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.verifier.resolve(), args.artifacts.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    temporary.replace(args.report)
    print(json.dumps({"one_pcs_cpu_rom_range_division_verified": True, "receiver_cases": len(result["cases"]), "ethereum_block_proof": False}))


if __name__ == "__main__":
    main()
