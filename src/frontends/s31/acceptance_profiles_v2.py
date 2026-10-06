#!/usr/bin/env python3
"""Positive and negative native-verifier checks for all S31 arithmetic profiles."""

import json
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "examples" / "arith4.s31.json"
ASSIGNMENT = HERE / "examples" / "arith4.valid.json"
PROFILES = ("gate", "chip", "sparse-gate", "sparse-chip")
MUTATIONS = (
    "first_input", "middle_output", "duplicate_index", "last_output",
    "wrong_constant", "interaction_cell", "claimed_sum",
)


def call(*args: str, accept: bool) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(
            f"unexpected exit {result.returncode}: {' '.join(args)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout + result.stderr


def main() -> None:
    source_digest = s31.file_hash(SOURCE)
    assignment = json.loads(ASSIGNMENT.read_text())
    with tempfile.TemporaryDirectory(prefix="s31-profiles-") as temporary:
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
            prover = package / "bin" / "s31-arith4-prover"
            verifier = package / "bin" / "s31-arith4-native-verifier"
            proof = work / f"{profile}.proof"
            call(str(prover), "prove", str(ASSIGNMENT), str(proof), accept=True)
            call(str(verifier), str(proof), str(statement), str(package / "verification-key.json"), accept=True)
            packages[profile] = package
            proofs[profile] = proof
            print(f"accepted {profile}: {proof.stat().st_size} bytes", flush=True)

        changed = json.loads(statement.read_text())
        changed["public_outputs"]["result"][0] += 1
        changed_statement = work / "changed-statement.json"
        s31.write_json(changed_statement, changed)
        for profile in PROFILES:
            package = packages[profile]
            verifier = package / "bin" / "s31-arith4-native-verifier"
            key = package / "verification-key.json"
            call(str(verifier), str(proofs[profile]), str(changed_statement), str(key), accept=False)

            altered_key = json.loads(key.read_text())
            altered_key["preprocessed_root"] = "00" * 32
            altered_key_path = work / f"{profile}.altered-key.json"
            s31.write_json(altered_key_path, altered_key)
            call(str(verifier), str(proofs[profile]), str(statement), str(altered_key_path), accept=False)

            damaged = bytearray(proofs[profile].read_bytes())
            damaged[-1] ^= 1
            damaged_path = work / f"{profile}.damaged.proof"
            damaged_path.write_bytes(damaged)
            call(str(verifier), str(damaged_path), str(statement), str(key), accept=False)

            for foreign_profile in PROFILES:
                if foreign_profile == profile:
                    continue
                call(str(verifier), str(proofs[foreign_profile]), str(statement), str(key), accept=False)
            print(f"rejected public/key/proof/replay mutations: {profile}", flush=True)

        chip_prover = packages["sparse-chip"] / "bin" / "s31-arith4-prover"
        for mutation in MUTATIONS:
            result = call(
                str(chip_prover), "prove-adversarial", str(ASSIGNMENT),
                str(work / f"{mutation}.proof"), mutation, accept=False,
            )
            if "InvalidChipLookupSum" not in result and "ConstraintsNotSatisfied" not in result:
                raise AssertionError(f"unexpected adversarial failure for {mutation}: {result}")
            print(f"rejected chip witness mutation: {mutation}", flush=True)

        record = {
            "schema": "s31-profile-acceptance-v2",
            "program_sha256": source_digest,
            "compiler_sha256": s31.compiler_fingerprint(),
            "profiles": list(PROFILES),
            "proof_bytes": {profile: proofs[profile].stat().st_size for profile in PROFILES},
            "negative_per_profile": ["changed_public_output", "altered_key", "damaged_proof", "three_cross_profile_replays"],
            "chip_witness_mutations": list(MUTATIONS),
        }
        output = s31.ROOT / "design" / "s31" / "measurements" / "profile-acceptance-v2-2026-10-06.json"
        s31.write_json(output, record)
        print(output)


if __name__ == "__main__":
    main()
