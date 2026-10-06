#!/usr/bin/env python3
"""Deterministic randomized source programs, assignments, and native proofs."""

import argparse
import hashlib
import importlib.util
import json
import random
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("s31_cli", HERE / "s31.py")
s31 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s31)
P = 2147483647


def run(*argv: str, accept: bool = True) -> str:
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode}: {argv}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=0x53333101)
    parser.add_argument("--out", type=Path, default=ROOT / "zig-out/s31/randomized-v1/summary.json")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    output = args.out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    work_dir = ROOT / "zig-out/s31/randomized-v1"
    work_dir.mkdir(parents=True, exist_ok=True)
    compiler = s31.compiler_fingerprint()
    results = []
    for case, length in enumerate((1, 3, 4)):
        offset = rng.randint(1, 200)
        scale = rng.randint(2, 19)
        step = rng.randint(1, 17)
        rounds = rng.randint(1, 5)
        name = f"random{case}"
        program = {
            "version": 1, "name": name,
            "inputs": [
                {"name": "target", "kind": "m31", "length": length, "visibility": "public"},
                {"name": "secret", "kind": "u16", "length": length, "visibility": "private"},
            ],
            "nodes": [
                {"name": "field", "op": "cast_m31", "lhs": "secret"},
                {"name": "offset", "op": "add_const", "lhs": "field", "constant": offset},
                {"name": "scaled", "op": "mul_const", "lhs": "offset", "constant": scale},
                {"name": "final", "op": "repeat", "lhs": "scaled", "rounds": rounds,
                 "body": [{"op": "square"}, {"op": "add_const", "constant": step}]},
            ],
            "assertions": [{"lhs": "final", "rhs": "target"}],
            "public_outputs": ["final"],
        }
        source = work_dir / f"{name}.s31.json"
        s31.write_json(source, program)
        package = s31.build(source, work_dir / f"{name}-{compiler[:16]}")
        prover = package / "bin" / f"s31-{name}-prover"
        verifier = package / "bin" / f"s31-{name}-native-verifier"
        key = package / "verification-key.json"
        reports = []
        for sample in range(3):
            secret = [rng.randrange(65536) for _ in range(length)]
            target = []
            for value in secret:
                value = (value + offset) * scale % P
                for _ in range(rounds):
                    value = (value * value + step) % P
                target.append(value)
            assignment = {"public_inputs": {"target": target},
                          "private_inputs": {"secret": secret},
                          "public_outputs": {"final": target}}
            statement = {"public_inputs": assignment["public_inputs"],
                         "public_outputs": assignment["public_outputs"]}
            assignment_path = work_dir / f"{name}.{sample}.assignment.json"
            statement_path = work_dir / f"{name}.{sample}.statement.json"
            proof_path = work_dir / f"{name}.{sample}.proof"
            s31.write_json(assignment_path, assignment)
            s31.write_json(statement_path, statement)
            expected = target + target + [0] * (8 - length * 2)
            reference = run(str(prover), "run", str(assignment_path))
            if [int(word) for word in reference.split("public words:", 1)[1].split()] != expected:
                raise AssertionError("reference evaluator differs from independent Python oracle")
            run(str(prover), "prove", str(assignment_path), str(proof_path))
            run(str(verifier), str(proof_path), str(statement_path), str(key))
            invalid = json.loads(assignment_path.read_text())
            invalid["private_inputs"]["secret"][0] = (secret[0] + 1) % 65536
            invalid_path = work_dir / f"{name}.{sample}.invalid.json"
            s31.write_json(invalid_path, invalid)
            run(str(prover), "prove", str(invalid_path), str(work_dir / "invalid.proof"), accept=False)
            reports.append({"secret": secret, "public_words": expected,
                            "proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
                            "proof_bytes": proof_path.stat().st_size})
            print(f"{name} sample {sample + 1}/3: verified", flush=True)
        results.append({"name": name, "length": length, "offset": offset, "scale": scale,
                        "step": step, "rounds": rounds, "program_sha256": s31.file_hash(source),
                        "samples": reports})
    summary = {"schema": "s31-randomized-proofs-v1", "seed": args.seed,
               "compiler_sha256": compiler, "programs": results}
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(output)


if __name__ == "__main__":
    main()
