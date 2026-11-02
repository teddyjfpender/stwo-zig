#!/usr/bin/env python3
"""Fresh-process standalone DIV/REM service qualification; no CPU ingress claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def qualify(verifier, artifacts):
    requests_path, claim_path, proof_path = [artifacts / name for name in ("requests.json", "claim.json", "proof.bin")]
    requests, claim = json.loads(requests_path.read_text()), json.loads(claim_path.read_text())
    negative = artifacts / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", requests_path, claim_path, proof_path, None)]
    for name, index, field, value in (("word-upper-operand", 32, "a", requests[32]["a"] ^ (1 << 60)),
                                       ("typed-opcode", 0, "opcode", "DIVU"),
                                       ("result", 63, "result", requests[63]["result"] ^ (1 << 63))):
        changed = json.loads(json.dumps(requests))
        changed[index][field] = value
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, path, claim_path, proof_path, "Rv64DivisionRequestClosure"))
    path = negative / "count.json"
    path.write_text(json.dumps(requests[:-1]))
    cases.append(("count", path, claim_path, proof_path, "Rv64DivisionRequestClosure"))
    for name, value, error in (("claim", (claim[0] + 1) % 2147483647, "Rv64DivisionRequestClosure"),
                                ("noncanonical-claim", 2147483647, "InvalidRv64DivisionClaim")):
        changed = list(claim)
        changed[0] = value
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, requests_path, path, proof_path, error))
    changed = bytearray(proof_path.read_bytes())
    changed[-1] ^= 1
    path = negative / "proof.bin"
    path.write_bytes(changed)
    cases.append(("proof-byte", requests_path, claim_path, path, "error:"))
    cases.append(("committed-count-previous", requests_path, claim_path, artifacts / "bad-count-prefix.bin", "OodsNotMatching"))
    outcomes = []
    for name, request, claims, proof, expected in cases:
        result = subprocess.run([str(verifier), str(request), str(claims), str(proof)], capture_output=True, text=True, timeout=120)
        if expected is None:
            accepted = result.returncode == 0 and json.loads(result.stdout).get("verified") is True
        else:
            accepted = result.returncode > 0 and expected in result.stderr
        if not accepted:
            raise ValueError(f"unexpected receiver result for {name}: {result.returncode} {result.stderr[:500]}")
        outcomes.append({"case": name, "expected_accept": expected is None, "passed": True,
                         "receiver_exit": result.returncode, "error": result.stderr.splitlines()[0] if result.stderr else None})
    return {"schema": "rv64-division-service-qualification-v1", "standalone_arithmetic_verified": True,
            "cpu_ingress_verified": False, "whole_guest_proof": False,
            "profile": {"version": "division_service_v2", "queries": 70, "pow_bits": 26},
            "artifacts": [identity(path) for path in (requests_path, claim_path, proof_path, verifier)],
            "requests": len(requests), "main_columns": 1135, "interaction_columns": 8,
            "fixed_columns": 3, "constraints": 1567, "cases": outcomes,
            "ethereum_6270_requests_source_cost": {"padded_rows": 8192, "main_bytes": 37191680,
                                                   "fixed_bytes": 98304, "interaction_bytes": 262144,
                                                   "narrow_request_metadata_bytes": 200640,
                                                   "scope": "source only; excludes PCS/FFT/openings and caller"}}


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
    print(json.dumps({"standalone_arithmetic_verified": True, "receiver_cases": len(result["cases"]), "cpu_ingress_verified": False}))


if __name__ == "__main__":
    main()
