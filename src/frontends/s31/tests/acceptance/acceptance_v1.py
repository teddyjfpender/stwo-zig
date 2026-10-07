#!/usr/bin/env python3
"""End-to-end acceptance for S31 v0.1 sealed native packages."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))
from example_paths import example_path

import argparse
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path

HERE = S31_SOURCE_ROOT
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("s31_cli", HERE / "python/s31.py")
s31 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s31)


def run(*args: str, cwd: Path = ROOT, accept: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode}: {args}\n{result.stdout}{result.stderr}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "zig-out/s31/mvp-acceptance/summary.json")
    args = parser.parse_args()
    output = args.out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    compiler = s31.compiler_fingerprint()
    cases = ("preimage4", "array3", "arith4", "hash4", "mixed4")
    packages = {}
    proofs = {}
    with tempfile.TemporaryDirectory(prefix="s31-accept-") as temporary:
        temp = Path(temporary)
        for name in cases:
            source = example_path(f"{name}.s31.json")
            package = s31.build(source, ROOT / "zig-out/s31/mvp-acceptance" / f"{name}-{compiler[:16]}")
            packages[name] = package
            s31.verify_package(package)
            cost = json.loads((package / "cost-report.json").read_text())
            source_json = json.loads(source.read_text())
            if len(cost["source_map"]) != len(source_json["inputs"]) + len(source_json["nodes"]):
                raise AssertionError("incomplete source-node map")
            if len(cost["assertion_map"]) != len(source_json["assertions"]):
                raise AssertionError("incomplete assertion map")
            if len(cost["public_binding"]) != sum(item["visibility"] == "public" for item in source_json["inputs"]) + len(source_json["public_outputs"]):
                raise AssertionError("incomplete public binding map")
            if name in ("hash4", "mixed4") and not any(
                item["blake_g_end"] > item["blake_g_start"] for item in cost["source_map"]
            ):
                raise AssertionError("hash gates missing from source map")
            prover = package / "bin" / f"s31-{name}-prover"
            verifier = package / "bin" / f"s31-{name}-native-verifier"
            proof = temp / f"{name}.proof"
            proofs[name] = proof
            assignment = example_path(f"{name}.valid.json")
            statement = example_path(f"{name}.statement.json")
            key = package / "verification-key.json"
            run(str(prover), "run", str(assignment))
            run(str(prover), "prove", str(assignment), str(proof))
            run(str(verifier), str(proof), str(statement), str(key), cwd=temp)
            if name in ("preimage4", "hash4", "mixed4"):
                invalid = example_path(f"{name}.invalid.json")
                run(str(prover), "prove", str(invalid), str(temp / f"{name}.invalid.proof"), accept=False)
            changed = json.loads(statement.read_text())
            first = next(iter(changed["public_outputs"]))
            changed["public_outputs"][first][0] += 1
            changed_path = temp / f"{name}.changed.json"
            changed_path.write_text(json.dumps(changed))
            run(str(verifier), str(proof), str(changed_path), str(key), cwd=temp, accept=False)
            print(f"{name}: valid proof accepted; changed statement rejected", flush=True)

        hash_package = packages["hash4"]
        verifier = hash_package / "bin/s31-hash4-native-verifier"
        statement = HERE / "examples/hashes/hash4.statement.json"
        key = hash_package / "verification-key.json"
        original = bytearray(proofs["hash4"].read_bytes())
        changed_proof = temp / "tampered.proof"
        original[len(original) // 2] ^= 1
        changed_proof.write_bytes(original)
        run(str(verifier), str(changed_proof), str(statement), str(key), cwd=temp, accept=False)
        truncated = temp / "truncated.proof"
        truncated.write_bytes(original[:100])
        run(str(verifier), str(truncated), str(statement), str(key), cwd=temp, accept=False)
        bad_key = json.loads(key.read_text())
        bad_key["circuit_hash"] = "0" * 64
        bad_key_path = temp / "altered-key.json"
        bad_key_path.write_text(json.dumps(bad_key))
        run(str(verifier), str(proofs["hash4"]), str(statement), str(bad_key_path), cwd=temp, accept=False)
        mixed_verifier = packages["mixed4"] / "bin/s31-mixed4-native-verifier"
        run(str(mixed_verifier), str(proofs["hash4"]), str(statement),
            str(packages["mixed4"] / "verification-key.json"), cwd=temp, accept=False)

        report = {
            "schema": "s31-mvp-acceptance-v1",
            "compiler_sha256": compiler,
            "cases": {name: {
                "program_sha256": s31.file_hash(packages[name] / "source.s31.json"),
                "proof_bytes": proofs[name].stat().st_size,
                "native_verified_outside_repo": True,
                "changed_public_rejected": True,
                "bad_witness_rejected": name in ("preimage4", "hash4", "mixed4"),
            } for name in cases},
            "tampered_proof_rejected": True,
            "truncated_proof_rejected": True,
            "altered_key_rejected": True,
            "wrong_program_rejected": True,
        }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(output)


if __name__ == "__main__":
    main()
