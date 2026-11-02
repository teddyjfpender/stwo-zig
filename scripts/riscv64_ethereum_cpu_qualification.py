#!/usr/bin/env python3
"""Fresh-process receivers for actual CPU/K/secp/MUL/DIV control proofs.

This fixture has public RAM boundaries; it is not a private-RAM or block proof.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def qualify(verifier, directory):
    paths = [directory / n for n in ("public.json", "claims.json", "proof.bin")]
    public, claims = [json.loads(p.read_text()) for p in paths[:2]]
    assert public["execution_profile"] in ("ethereum_services_v1", "ethereum_services_v2")
    negative = directory / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", *paths, False)]
    public_changes = [
        ("execution-profile", lambda p: p.__setitem__("execution_profile", "ethereum_services_v2" if p["execution_profile"].endswith("v1") else "ethereum_services_v1")),
        ("arithmetic-policy", lambda p: p.__setitem__("arithmetic_policy", "division_service_v2")),
        ("state-policy", lambda p: p.__setitem__("state_policy", "inverse_v1")),
        ("terminal-pc", lambda p: p["statement"].__setitem__("final_pc", p["statement"]["final_pc"] + 4)),
        ("terminal-register", lambda p: p["statement"]["final_registers"].__setitem__(13, p["statement"]["final_registers"][13] ^ (1 << 63))),
        ("rom-high-pc", lambda p: p["statement"]["program"].__setitem__("base", p["statement"]["program"]["base"] ^ (1 << 32))),
        ("immutable-instruction", lambda p: p["statement"]["program"]["words"].__setitem__(0, p["statement"]["program"]["words"][0] ^ 0x1000)),
        ("initial-ram", lambda p: p["statement"]["cells"][0].__setitem__("initial", p["statement"]["cells"][0]["initial"] ^ 1)),
        ("final-ram", lambda p: p["statement"]["cells"][0].__setitem__("final", p["statement"]["cells"][0]["final"] ^ 1)),
        ("ram-clock", lambda p: p["statement"]["memory_clocks"].__setitem__(0, p["statement"]["memory_clocks"][0] - 1)),
        ("ram-permission", lambda p: p["statement"]["cells"][0].__setitem__("writable", False)),
    ]
    for kind in ("add", "double"):
        public_changes.extend([
            (kind + "-count", lambda p, k=kind: p["secp"][k].__setitem__("calls", 0)),
            (kind + "-first-id", lambda p, k=kind: p["secp"][k].__setitem__("first_id", 2)),
            (kind + "-roster", lambda p, k=kind: p["secp"][k].__setitem__("roster", "none")),
            (kind + "-geometry", lambda p, k=kind: p["secp"][k]["geometry"].__setitem__("product_log", p["secp"][k]["geometry"]["product_log"] + 1)),
        ])
    for name, mutate in public_changes:
        value = copy.deepcopy(public)
        mutate(value)
        path = negative / (name + ".json")
        path.write_text(json.dumps(value))
        cases.append((name, path, paths[1], paths[2], True))
    families = [("secp_header",), ("secp_add", "product"), ("secp_add", "linear"), ("secp_add", "bridge"), ("secp_double", "product"), ("secp_double", "linear"), ("secp_double", "bridge"), ("bytes",)]
    def alter(value, family, delta):
        for part in family:
            value = value[part]
        value["c0"]["a"]["v"] = (value["c0"]["a"]["v"] + delta) % 2147483647
    for family in families:
        value = copy.deepcopy(claims)
        alter(value, family, 1)
        path = negative / ("claim-" + "-".join(family) + ".json")
        path.write_text(json.dumps(value))
        cases.append((path.stem, paths[0], path, paths[2], True))
    for kind in ("add", "double"):
        value = copy.deepcopy(claims)
        alter(value, ("secp_header",), 1)
        alter(value, ("secp_" + kind, "bridge"), -1)
        path = negative / ("balanced-header-" + kind + ".json")
        path.write_text(json.dumps(value))
        cases.append((path.stem, paths[0], path, paths[2], True))
    for name in ("add-counter", "double-counter", "secp-prefix"):
        cases.append(("previous-" + name, paths[0], paths[1], directory / ("bad-" + name + ".bin"), True))
    truncated = negative / "truncated.bin"
    truncated.write_bytes(paths[2].read_bytes()[:-1])
    cases.append(("truncated", paths[0], paths[1], truncated, True))
    outcomes = []
    receiver = None
    for name, p, c, proof, reject in cases:
        run = subprocess.run([str(verifier), str(p), str(c), str(proof)], capture_output=True, text=True, timeout=240)
        passed = run.returncode != 0 if reject else run.returncode == 0
        if not passed:
            raise RuntimeError(f"{name}: unexpected exit {run.returncode}: {run.stderr[-2000:]}")
        if not reject:
            receiver = json.loads(run.stdout)
            if receiver.get("verified") is not True:
                raise RuntimeError("fresh receiver did not report successful verification")
        outcomes.append({"case": name, "rejected": reject, "exit_code": run.returncode})
    return {"execution_profile": public["execution_profile"], "one_pcs_cpu_rom_state_keccak_secp_mul_div": True, "public_ram_boundary_control": True, "ethereum_block_proof": False, "proof_bytes": paths[2].stat().st_size, "proof_sha256": hashlib.sha256(paths[2].read_bytes()).hexdigest(), "suite": {"fri_queries": 70, "pow_bits": 26}, "artifacts": {path.name: {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in paths}, "verifier": {"path": str(verifier), "bytes": verifier.stat().st_size, "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest()}, "receiver": receiver, "fresh_receiver_cases": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.verifier.resolve(), args.artifacts.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(result['fresh_receiver_cases'])} independent receiver cases passed")


if __name__ == "__main__":
    main()
