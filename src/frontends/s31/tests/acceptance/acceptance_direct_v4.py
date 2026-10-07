#!/usr/bin/env python3
"""Direct-M31 v4 native-verifier agreement and rejection corpus."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import json
import subprocess
import tempfile
from pathlib import Path

import s31

HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples" / "arithmetic" / "arith4_m31.s31.json"
ASSIGNMENT = HERE / "examples" / "arithmetic" / "arith4.valid.json"
PROFILES = ("sparse-gate", "sparse-chip", "direct-gate", "direct-chip")
MUTATIONS = (
    "first_input", "middle_output", "duplicate_index", "last_output",
    "wrong_constant", "interaction_cell", "claimed_sum",
)


def call(*args: str, accepted: bool) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def main() -> None:
    assignment = json.loads(ASSIGNMENT.read_text())
    with tempfile.TemporaryDirectory(prefix="s31-direct-") as temporary:
        work = Path(temporary)
        statement = work / "statement.json"
        s31.write_json(statement, {
            "public_inputs": assignment["public_inputs"],
            "public_outputs": assignment["public_outputs"],
        })
        packages = {}
        proofs = {}
        for profile in PROFILES:
            package = s31.build(SOURCE, work / profile, profile)
            prover = package / "bin" / "s31-arith4_m31-prover"
            verifier = package / "bin" / "s31-arith4_m31-native-verifier"
            proof = work / f"{profile}.proof"
            call(str(prover), "prove", str(ASSIGNMENT), str(proof), accepted=True)
            call(str(verifier), str(proof), str(statement), str(package / "verification-key.json"), accepted=True)
            packages[profile] = package
            proofs[profile] = proof
            print(f"accepted {profile}: {proof.stat().st_size} bytes", flush=True)

        changed = json.loads(statement.read_text())
        changed["public_outputs"]["result"][0] += 1
        changed_statement = work / "changed-statement.json"
        s31.write_json(changed_statement, changed)
        changed_input = json.loads(statement.read_text())
        changed_input["public_inputs"]["x"][0] += 1
        changed_input_path = work / "changed-input.json"
        s31.write_json(changed_input_path, changed_input)
        noncanonical = json.loads(statement.read_text())
        noncanonical["public_inputs"]["x"][0] = (1 << 31) - 1
        noncanonical_path = work / "noncanonical-input.json"
        s31.write_json(noncanonical_path, noncanonical)
        for profile in PROFILES:
            package = packages[profile]
            verifier = package / "bin" / "s31-arith4_m31-native-verifier"
            key = package / "verification-key.json"
            call(str(verifier), str(proofs[profile]), str(changed_statement), str(key), accepted=False)
            call(str(verifier), str(proofs[profile]), str(changed_input_path), str(key), accepted=False)
            call(str(verifier), str(proofs[profile]), str(noncanonical_path), str(key), accepted=False)
            altered_key = json.loads(key.read_text())
            altered_key["preprocessed_root"] = "00" * 32
            altered_key_path = work / f"{profile}.bad-key.json"
            s31.write_json(altered_key_path, altered_key)
            call(str(verifier), str(proofs[profile]), str(statement), str(altered_key_path), accepted=False)
            damaged = bytearray(proofs[profile].read_bytes())
            damaged[-1] ^= 1
            damaged_path = work / f"{profile}.damaged.proof"
            damaged_path.write_bytes(damaged)
            call(str(verifier), str(damaged_path), str(statement), str(key), accepted=False)
            for other in PROFILES:
                if other != profile:
                    call(str(verifier), str(proofs[other]), str(statement), str(key), accepted=False)
            print(f"rejected public/key/proof/replay mutations: {profile}", flush=True)

        for profile in ("sparse-chip", "direct-chip"):
            prover = packages[profile] / "bin" / "s31-arith4_m31-prover"
            for mutation in MUTATIONS:
                result = call(
                    str(prover), "prove-adversarial", str(ASSIGNMENT),
                    str(work / f"{profile}-{mutation}.proof"), mutation, accepted=False,
                )
                if "InvalidChipLookupSum" not in result and "ConstraintsNotSatisfied" not in result:
                    raise AssertionError(f"unexpected adversarial failure {profile}/{mutation}: {result}")
                print(f"rejected {profile} chip witness: {mutation}", flush=True)

        record = {
            "schema": "s31-direct-acceptance-v4",
            "program_sha256": s31.file_hash(SOURCE),
            "compiler_sha256": s31.compiler_fingerprint(),
            "profiles": list(PROFILES),
            "proof_bytes": {profile: proofs[profile].stat().st_size for profile in PROFILES},
            "negative_per_profile": ["changed_public_output", "changed_public_input", "noncanonical_public_input", "altered_key", "damaged_proof", "three_cross_profile_replays"],
            "chip_witness_mutations": list(MUTATIONS),
        }
        output = s31.ROOT / "design" / "s31" / "measurements" / "direct-acceptance-v4-2026-10-06.json"
        s31.write_json(output, record)
        print(output)


if __name__ == "__main__":
    main()
