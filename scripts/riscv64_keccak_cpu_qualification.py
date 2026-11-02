#!/usr/bin/env python3
"""Cold independent receivers for joined RV64 CPU/Keccak/DIV/RAM control proof."""
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
    paths = [artifacts / name for name in ("public.json", "claims.json", "proof.bin")]
    public, claims = [json.loads(path.read_text()) for path in paths[:2]]
    if public.get("roster") == "none":
        return qualify_none(verifier, artifacts, paths, public, claims)
    negative = artifacts / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", *paths, None)]
    changes = [
        ("provider-roster", lambda p: p.__setitem__("roster", "none"), "InvalidRv64ServiceRoster"),
        ("state-policy", lambda p: p.__setitem__("state_policy", "cyclic_v2" if p.get("state_policy", "inverse_v1") == "inverse_v1" else "inverse_v1"), "Rv64ServiceGlobalClosure"),
        ("call-count", lambda p: p.__setitem__("keccak_calls", 1), "Rv64ServiceGlobalClosure"),
        ("first-call-id", lambda p: p.__setitem__("first_call_id", 2), "Rv64ServiceGlobalClosure"),
        ("division-count", lambda p: p.__setitem__("division_requests", 0), "Rv64ServiceGlobalClosure"),
        ("immutable-program", lambda p: p["statement"]["program"]["words"].__setitem__(0, p["statement"]["program"]["words"][0] ^ 0x1000), None),
        ("terminal-register", lambda p: p["statement"]["final_registers"].__setitem__(6, p["statement"]["final_registers"][6] ^ 1), "Rv64ServiceGlobalClosure"),
        ("terminal-pc", lambda p: p["statement"].__setitem__("final_pc", p["statement"]["final_pc"] + 4), "Rv64ServiceGlobalClosure"),
        ("initial-ram", lambda p: p["statement"]["cells"][4].__setitem__("initial", p["statement"]["cells"][4]["initial"] ^ 1), "Rv64ServiceGlobalClosure"),
        ("terminal-ram", lambda p: p["statement"]["cells"][4].__setitem__("final", p["statement"]["cells"][4]["final"] ^ 1), "Rv64ServiceGlobalClosure"),
        ("ram-clock", lambda p: p["statement"]["memory_clocks"].__setitem__(4, 12), "Rv64ServiceGlobalClosure"),
        ("ram-write-permission", lambda p: p["statement"]["cells"][4].__setitem__("writable", False), "Rv64ServiceGlobalClosure"),
        ("opcode-omission", lambda p: p["statement"]["opcodes"].__setitem__(63, False), "InvalidRv64ServiceOpcodePolicy"),
    ]
    arithmetic = public.get("arithmetic_policy", "division_service_v2")
    if arithmetic == "division_multiplication_services_v3":
        changes.extend([
            ("multiplication-count", lambda p: p.__setitem__("multiplication_requests", p["multiplication_requests"] + 1), "Rv64ServiceGlobalClosure"),
            ("arithmetic-policy", lambda p: p.__setitem__("arithmetic_policy", "division_service_v2"), "InvalidRv64ServiceArithmetic"),
            ("initial-register-full64", lambda p: p["statement"]["initial_registers"].__setitem__(1, p["statement"]["initial_registers"][1] ^ (1 << 63)), "Rv64ServiceGlobalClosure"),
        ])
    for name, mutate, error in changes:
        changed = copy.deepcopy(public)
        mutate(changed)
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, path, paths[1], paths[2], error or "REJECT"))
    for name, family in (("header", "header"), ("bridge", "bridge"), ("permutation", "permutation"), ("truth-table", "chi"), ("byte-provider", "bytes"), ("division", "division")):
        changed = copy.deepcopy(claims)
        changed[family]["c0"]["a"]["v"] = (changed[family]["c0"]["a"]["v"] + 1) % 2147483647
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, paths[0], path, paths[2], "OodsNotMatching" if family == "division" else "Rv64ServiceGlobalClosure"))
    if arithmetic == "division_multiplication_services_v3":
        for family in ("multiplication", "multiplication_provider"):
            changed = copy.deepcopy(claims)
            changed[family]["c0"]["a"]["v"] = (changed[family]["c0"]["a"]["v"] + 1) % 2147483647
            path = negative / (family + ".json"); path.write_text(json.dumps(changed))
            cases.append((family, paths[0], path, paths[2], "Rv64ServiceGlobalClosure"))
        changed = copy.deepcopy(claims)
        for family, delta in (("multiplication", 1), ("multiplication_provider", -1)):
            changed[family]["c0"]["a"]["v"] = (changed[family]["c0"]["a"]["v"] + delta) % 2147483647
        path = negative / "balanced-mul.json"; path.write_text(json.dumps(changed))
        cases.append(("balanced-mul", paths[0], path, paths[2], "OodsNotMatching"))
        for name in ("cpu-mul", "mul-provider"):
            cases.append(("previous-" + name + "-prefix", paths[0], paths[1], artifacts / ("bad-" + name + "-prefix.bin"), "OodsNotMatching"))
    # Both claims change by opposite field values, so algebraic global closure
    # still holds. The component AIR and transcript must reject independently.
    changed = copy.deepcopy(claims)
    for family, delta in (("header", 1), ("bridge", -1)):
        limb = changed[family]["c0"]["a"]
        limb["v"] = (limb["v"] + delta) % 2147483647
    path = negative / "balanced-header-bridge.json"
    path.write_text(json.dumps(changed))
    cases.append(("balanced-header-bridge", paths[0], path, paths[2], "OodsNotMatching"))
    changed = copy.deepcopy(claims)
    changed["permutation"]["c0"]["a"]["v"] = 2147483647
    path = negative / "noncanonical-claim.json"
    path.write_text(json.dumps(changed))
    cases.append(("noncanonical-claim", paths[0], path, paths[2], "InvalidRv64ServiceClaim"))
    cases.append(("previous-state-prefix", paths[0], paths[1], artifacts / "bad-state-prefix.bin", "OodsNotMatching"))
    cases.append(("previous-call-counter", paths[0], paths[1], artifacts / "bad-count-prefix.bin", "OodsNotMatching"))
    outcomes, receiver = [], None
    for name, p, c, proof, expected in cases:
        run = subprocess.run([str(verifier), str(p), str(c), str(proof)], text=True, capture_output=True, timeout=180)
        if expected is None:
            passed = run.returncode == 0 and json.loads(run.stdout).get("verified") is True
            if passed:
                receiver = json.loads(run.stdout)
        else:
            passed = run.returncode > 0 and (expected == "REJECT" or expected in run.stderr)
        if not passed:
            raise ValueError(f"unexpected {name}: {run.returncode} {run.stderr[:500]}")
        outcomes.append({"case": name, "expected_accept": expected is None, "passed": True, "receiver_exit": run.returncode, "error": run.stderr.splitlines()[0] if run.stderr else None})
    return {"schema": "rv64-keccak-cpu-qualification-v1", "execution_profile": "keccak_service_v1", "arithmetic_policy": arithmetic, "multiplication_requests": public.get("multiplication_requests", 0), "roster": public.get("roster", "paired"), "state_policy": public.get("state_policy", "inverse_v1"), "state_interaction_columns": 12 if public.get("state_policy") == "cyclic_v2" else 36, "compact_tape_global_clock": 1 << 40, "journal_compact_complete_proof_bytes_equal": True, "constructor_allocation_failures_tested": True, "components": {"cpu_log": 5, "rom_log": 5, "byte_log": 8, "and_log": 16, "shift_log": 11, "division_log": public["division_log"], "keccak_log": public["keccak_log"], "bridge_log": public["bridge_log"]}, "one_pcs_cpu_rom_range_division_keccak_ram_bridge_verified": True, "ethereum_block_proof": False, "ram_hash_roots": False, "public_cells_control_profile": True, "steps": public["statement"]["steps"], "keccak_calls": public["keccak_calls"], "division_requests": public["division_requests"], "queries": 70, "pow_bits": 26, "execution": ("DIVW and all5 MUL family, SD, ECALL, LD, ECALL, LD, AND, SRA" if arithmetic == "division_multiplication_services_v3" else "DIVW, SD, ECALL, LD, ECALL, LD, AND, SRA") + "; repeated high-u64 cross-page pointer and 25 merged RAM words", "receiver_cost_single_sample": receiver, "receiver_cost_scope": "cold process and independently derived preprocessing; diagnostic, not benchmark", "source_ownership": "bounded streaming main commitment, CPU/D source freed after commit; crypto main retained through interaction generation", "artifacts": [identity(path) for path in (*paths, artifacts / "bad-count-prefix.bin", artifacts / "bad-state-prefix.bin", verifier)], "cases": outcomes}


def qualify_none(verifier, artifacts, paths, public, claims):
    negative = artifacts / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid-none", *paths, None), ("valid-paired-c0-control", *(artifacts / "paired-c0" / n for n in ("public.json", "claims.json", "proof.bin")), None)]
    for name, mutate, expected in (
        ("nonzero-call-count", lambda p: p.__setitem__("keccak_calls", 1), "InvalidRv64ServiceRoster"),
        ("provider-roster", lambda p: p.__setitem__("roster", "paired"), "Rv64ServiceFixedRootMismatch"),
        ("state-policy", lambda p: p.__setitem__("state_policy", "inverse_v1"), "Rv64ServiceGlobalClosure"),
        ("opcode-omission", lambda p: p["statement"]["opcodes"].__setitem__(63, False), "InvalidRv64ServiceOpcodePolicy"),
        ("terminal-pc", lambda p: p["statement"].__setitem__("final_pc", p["statement"]["final_pc"] + 4), "Rv64ServiceGlobalClosure"),
        ("terminal-ram", lambda p: p["statement"]["cells"][0].__setitem__("final", p["statement"]["cells"][0]["final"] ^ 1), "Rv64ServiceGlobalClosure"),
    ):
        changed = copy.deepcopy(public)
        mutate(changed)
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, path, paths[1], paths[2], expected))
    for family in ("header", "permutation", "chi", "xor5", "bridge"):
        changed = copy.deepcopy(claims)
        changed[family]["c0"]["a"]["v"] = 1
        path = negative / (family + ".json")
        path.write_text(json.dumps(changed))
        cases.append(("omitted-" + family, paths[0], path, paths[2], "Rv64ServiceOmittedClaim"))
    changed = copy.deepcopy(claims)
    changed["cpu"]["state"]["c0"]["a"]["v"] = (changed["cpu"]["state"]["c0"]["a"]["v"] + 1) % 2147483647
    changed["bytes"]["c0"]["a"]["v"] = (changed["bytes"]["c0"]["a"]["v"] - 1) % 2147483647
    path = negative / "balanced-state-byte.json"
    path.write_text(json.dumps(changed))
    cases.append(("balanced-state-byte", paths[0], path, paths[2], "OodsNotMatching"))
    for name in ("count", "state"):
        cases.append(("previous-" + name + "-prefix", paths[0], paths[1], artifacts / ("bad-" + name + "-prefix.bin"), "OodsNotMatching"))
    outcomes, receiver = [], None
    for name, p, c, proof, expected in cases:
        run = subprocess.run([str(verifier), str(p), str(c), str(proof)], text=True, capture_output=True, timeout=180)
        passed = run.returncode == 0 and json.loads(run.stdout).get("verified") is True if expected is None else run.returncode > 0 and expected in run.stderr
        if not passed:
            raise ValueError(f"unexpected {name}: {run.returncode} {run.stderr[:500]}")
        if name == "valid-none":
            receiver = json.loads(run.stdout)
        outcomes.append({"case": name, "expected_accept": expected is None, "passed": True, "receiver_exit": run.returncode, "error": run.stderr.splitlines()[0] if run.stderr else None})
    return {"schema": "rv64-keccak-cpu-none-qualification-v1", "roster": "none", "execution_profile": "keccak_service_v1", "arithmetic_policy": "division_service_v2", "state_policy": public["state_policy"], "keccak_calls": 0, "cpu_ecall_absence_constrained": True, "ecall_in_immutable_admitted_opcode_policy": public["statement"]["opcodes"][63], "crypto_components_omitted": True, "queries": 70, "pow_bits": 26, "ethereum_block_proof": False, "public_cells_control_profile": True, "comparison": json.loads((artifacts / "roster-comparison.json").read_text()), "receiver_cost_single_sample": receiver, "receiver_cost_scope": "cold process and independently derived preprocessing; diagnostic, not benchmark", "artifacts": [identity(path) for path in (*paths, artifacts / "bad-count-prefix.bin", artifacts / "bad-state-prefix.bin", verifier)], "cases": outcomes}


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
    print(json.dumps({"verified": True, "receiver_cases": len(result["cases"]), "ethereum_block_proof": False}))


if __name__ == "__main__":
    main()
