#!/usr/bin/env python3
"""Fresh receivers for count-zero omitted DIV/MUL providers and retained CPU buses."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def qualify(verifier, directory):
    public_path, claims_path, proof_path = [directory / n for n in ("public.json", "claims.json", "proof.bin")]
    public, claims = [json.loads(p.read_text()) for p in (public_path, claims_path)]
    assert public["division_roster"] == public["multiplication_roster"] == "none"
    negative = directory / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", public_path, claims_path, proof_path, False)]
    mutations = [
        ("division-count", lambda p: p.__setitem__("division_requests", 1)),
        ("division-domain", lambda p: p.__setitem__("division_log", 6)),
        ("division-roster", lambda p: p.__setitem__("division_roster", "present")),
        ("multiplication-count", lambda p: p.__setitem__("multiplication_requests", 1)),
        ("multiplication-domain", lambda p: p.__setitem__("multiplication_log", 6)),
        ("multiplication-roster", lambda p: p.__setitem__("multiplication_roster", "present")),
        ("arithmetic-policy", lambda p: p.__setitem__("arithmetic_policy", "division_service_v2")),
        ("state-policy", lambda p: p.__setitem__("state_policy", "inverse_v1")),
        ("initial-pc", lambda p: p["statement"].__setitem__("initial_pc", p["statement"]["initial_pc"] ^ (1 << 32))),
        ("final-pc", lambda p: p["statement"].__setitem__("final_pc", p["statement"]["final_pc"] + 4)),
        ("terminal-register", lambda p: p["statement"]["final_registers"].__setitem__(1, 18)),
        ("immutable-program", lambda p: p["statement"]["program"]["words"].__setitem__(0, p["statement"]["program"]["words"][0] ^ 0x100000)),
    ]
    for name, mutate in mutations:
        changed = copy.deepcopy(public)
        mutate(changed)
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, path, claims_path, proof_path, True))
    for family in ("division", "multiplication", "multiplication_provider"):
        changed = copy.deepcopy(claims)
        changed[family]["c0"]["a"]["v"] = 1
        path = negative / (family + ".json")
        path.write_text(json.dumps(changed))
        cases.append((family + "-omitted-claim", public_path, path, proof_path, True))
    changed = copy.deepcopy(claims)
    changed["multiplication"]["c0"]["a"]["v"] = 1
    changed["multiplication_provider"]["c0"]["a"]["v"] = 2147483646
    path = negative / "balanced-mul.json"
    path.write_text(json.dumps(changed))
    cases.append(("balanced-omitted-mul", public_path, path, proof_path, True))
    changed = copy.deepcopy(claims)
    changed["division"]["c0"]["a"]["v"] = 1
    changed["secp_header"]["c0"]["a"]["v"] = 2147483646
    path = negative / "balanced-div.json"
    path.write_text(json.dumps(changed))
    cases.append(("balanced-omitted-div", public_path, path, proof_path, True))
    for family in ("div", "mul"):
        cases.append(("retained-cpu-" + family + "-prefix", public_path, claims_path, directory / ("bad-" + family + "-prefix.bin"), True))
    truncated = negative / "truncated.bin"
    truncated.write_bytes(proof_path.read_bytes()[:-1])
    cases.append(("truncated", public_path, claims_path, truncated, True))
    outcomes = []
    receiver = None
    for name, p, c, proof, reject in cases:
        run = subprocess.run([str(verifier), str(p), str(c), str(proof)], text=True, capture_output=True, timeout=240)
        if (run.returncode != 0) != reject:
            raise RuntimeError(f"{name}: unexpected exit {run.returncode}: {run.stderr[-2000:]}")
        if not reject:
            receiver = json.loads(run.stdout)
            assert receiver["verified"] is True
        outcomes.append({"case": name, "rejected": reject, "exit_code": run.returncode})
    def identity(path):
        return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    return {"suite": {"fri_queries": 70, "pow_bits": 26}, "provider_omission": "explicit-count-zero-only", "cpu_div_mul_request_buses_retained": True, "ethereum_block_proof": False, "metrics": json.loads((directory / "metrics.json").read_text()), "artifacts": {p.name: identity(p) for p in (public_path, claims_path, proof_path)}, "verifier": identity(verifier), "receiver": receiver, "fresh_receiver_cases": outcomes}


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
