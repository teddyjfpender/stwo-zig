#!/usr/bin/env python3
"""End-to-end sparse-wide leaf -> gate wrapper -> gate wrapper acceptance."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import s31

HERE = Path(__file__).resolve().parent
def call(*args: str, accepted: bool = True) -> tuple[str, float]:
    started = time.perf_counter()
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    elapsed = time.perf_counter() - started
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr, elapsed


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoin", action="store_true", help="use the two-header SHA256d/PoW source")
    args = parser.parse_args()
    name = "bitcoin_header_pair" if args.bitcoin else "wide_order"
    source = HERE / "examples" / f"{name}.s31"
    assignment = HERE / "examples" / f"{name}.valid.json"
    cli = (sys.executable, str(HERE / "s31.py"))
    with tempfile.TemporaryDirectory(prefix="s31-wide-recursion-") as temporary:
        work = Path(temporary)
        package = work / "package"
        started = time.perf_counter()
        s31.build(source, package, "sparse-wide-gate")
        build_seconds = time.perf_counter() - started
        manifest = s31.verify_package(package)
        child = work / "child.proof"
        first = work / "first.proof"
        second = work / "second.proof"
        _, child_seconds = call(*cli, "prove", str(package), str(assignment), str(child))
        audit_output, audit_seconds = call(*cli, "audit-recursive", str(package), str(child))
        count = int(re.search(r"rejected=(\d+)", audit_output).group(1))
        if count != 10 or "valid=true" not in audit_output:
            raise AssertionError(audit_output)
        _, first_seconds = call(*cli, "wrap", str(package), str(child), str(first), "--low-memory")
        call(*cli, "verify-recursive", str(package), str(first))
        _, second_seconds = call(*cli, "wrap-next", str(package), str(first), str(second), "--low-memory")
        call(*cli, "verify-recursive-next", str(package), str(second))
        next_audit, _ = call(*cli, "audit-recursive-next", str(package), str(first))
        if "valid=true rejected=7" not in next_audit:
            raise AssertionError(next_audit)

        checks = []
        statement = Path(str(child) + ".statement.json")
        key = package / "verification-key.json"
        prover = package / "bin" / f"s31-{manifest['name']}-prover"
        native = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        corrupted = bytearray(child.read_bytes())
        corrupted[-1] ^= 1
        corrupted_child = work / "corrupt-child.proof"
        corrupted_child.write_bytes(corrupted)
        call(str(prover), "recurse-wide-audit", str(corrupted_child), str(statement), str(key), accepted=False)
        checks.append("corrupt_child_proof")
        wrong_key = json.loads(key.read_text())
        wrong_key["preprocessed_root"] = "00" * 32
        wrong_key_path = work / "wrong-key.json"
        write(wrong_key_path, wrong_key)
        call(str(prover), "recurse-wide-audit", str(child), str(statement), str(wrong_key_path), accepted=False)
        checks.append("unsealed_child_key")
        wrong_public = json.loads(statement.read_text())
        next(iter(wrong_public["public_outputs"].values()))[0] ^= 1
        wrong_public_path = work / "wrong-public.json"
        write(wrong_public_path, wrong_public)
        call(str(prover), "recurse-wide-audit", str(child), str(wrong_public_path), str(key), accepted=False)
        checks.append("wrong_child_public_claim")

        first_statement = json.loads(Path(str(first) + ".statement.json").read_text())
        for field in ("child_public_words", "outer_public_words"):
            altered = json.loads(json.dumps(first_statement))
            altered[field][0] ^= 1
            path = work / f"wrong-{field}.json"
            write(path, altered)
            call(str(native), "recurse-verify", str(first), str(path), accepted=False)
            checks.append(f"wrong_first_{field}")
        altered = json.loads(json.dumps(first_statement))
        altered["outer_preprocessed_root"] = "00" * 32
        path = work / "wrong-outer-root.json"
        write(path, altered)
        call(str(native), "recurse-verify", str(first), str(path), accepted=False)
        checks.append("wrong_first_root")
        bad_first = bytearray(first.read_bytes())
        bad_first[-1] ^= 1
        bad_first_path = work / "corrupt-first.proof"
        bad_first_path.write_bytes(bad_first)
        call(str(native), "recurse-verify", str(bad_first_path), str(Path(str(first) + ".statement.json")), accepted=False)
        checks.append("corrupt_first_proof")

        chain = json.loads(Path(str(second) + ".statement.json").read_text())
        for target, field in (("leaf", "child_public_words"), ("head", "child_public_words"), ("head", "outer_public_words")):
            altered = json.loads(json.dumps(chain))
            altered[target][field][0] ^= 1
            path = work / f"wrong-{target}-{field}.json"
            write(path, altered)
            call(str(native), "recurse-verify-next", str(second), str(path), accepted=False)
            checks.append(f"wrong_chain_{target}_{field}")
        bad_second = bytearray(second.read_bytes())
        bad_second[-1] ^= 1
        bad_second_path = work / "corrupt-second.proof"
        bad_second_path.write_bytes(bad_second)
        call(str(native), "recurse-verify-next", str(bad_second_path), str(Path(str(second) + ".statement.json")), accepted=False)
        checks.append("corrupt_second_proof")

        record = {
            "schema": "s31-sparse-wide-recursion-acceptance-v1",
            "source_sha256": s31.file_hash(source),
            "source_name": name,
            "compiler_sha256": s31.compiler_fingerprint(),
            "profile": "sparse-wide-v5 child, two circuit-v1 wrappers",
            "proof_bytes": [child.stat().st_size, first.stat().st_size, second.stat().st_size],
            "wall_seconds": {"build": build_seconds, "leaf": child_seconds, "audit": audit_seconds, "wrap_1": first_seconds, "wrap_2": second_seconds},
            "circuit_witness_mutations_rejected": count,
            "second_level_mutations_rejected": 7,
            "host_negative_checks": checks,
        }
        filename = "bitcoin-sparse-wide-recursion-v1-2026-10-07.json" if args.bitcoin else "sparse-wide-recursion-v1-2026-10-07.json"
        path = s31.ROOT / "design" / "s31" / "measurements" / filename
        s31.write_json(path, record)
        print(json.dumps(record, indent=2))
        print(path)


if __name__ == "__main__":
    main()
