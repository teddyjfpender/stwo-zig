#!/usr/bin/env python3
"""Check that Bitcoin's nominal hash type is soundly erased by lowering."""

import json
import sys
import tempfile
from pathlib import Path

import s31
from text_frontend import compile_text


def rejected(source: str, expected: str) -> None:
    try:
        compile_text(source)
    except ValueError as exc:
        if expected not in str(exc):
            raise AssertionError(f"rejected for the wrong reason: {exc}") from exc
    else:
        raise AssertionError(f"source accepted an invalid BlockHash use: {expected}")


def main() -> None:
    examples = s31.S31_DIR / "examples"
    typed_source = (examples / "bitcoin_header_pair_typed.s31").read_text()
    typed_relation, _ = compile_text(typed_source)
    old_relation, _ = compile_text((examples / "bitcoin_header_pair.s31").read_text())
    pinned_relation = json.loads((examples / "bitcoin_header_pair.s31.json").read_text())
    if typed_relation != old_relation or typed_relation != pinned_relation:
        raise AssertionError("nominal BlockHash changed the constrained relation")

    rejected(typed_source.replace(
        "assert_eq(parent_hash, std::bitcoin::genesis_block_hash_mainnet());",
        "assert_eq(parent_hash, std::bitcoin::genesis_hash_mainnet());"),
        "assert_eq requires two values of the same relation type")
    rejected(typed_source.replace(
        "std::bitcoin::hash_bytes(parent_hash)",
        "std::bitcoin::hash_bytes(std::bitcoin::hash_bytes(parent_hash))", 1),
        "hash_bytes requires a BlockHash")

    with tempfile.TemporaryDirectory(prefix="s31-blockhash-") as directory:
        work = Path(directory)
        package = s31.build(examples / "bitcoin_header_pair_typed.s31",
                            work / "package", "sparse-wide-gate", 4)
        manifest = s31.verify_package(package)
        old_package = s31.build(examples / "bitcoin_header_pair.s31",
                                work / "old-package", "sparse-wide-gate", 4)
        s31.verify_package(old_package)
        if ((package / "verification-key.json").read_bytes() !=
                (old_package / "verification-key.json").read_bytes()):
            raise AssertionError("nominal BlockHash changed the native verification key")
        typed_cost = json.loads((package / "cost-report.json").read_text())
        old_cost = json.loads((old_package / "cost-report.json").read_text())
        for field in ("canonical_ir_sha256", "raw", "padded", "preprocessed_cells",
                      "preprocessed_columns", "preprocessed_root", "fri"):
            if typed_cost[field] != old_cost[field]:
                raise AssertionError(f"nominal BlockHash changed cost field {field}")
        packaged_relation = json.loads((package / "source.s31.json").read_text())
        if packaged_relation != pinned_relation:
            raise AssertionError("package lowered a different Bitcoin relation")
        assignment_path = examples / "bitcoin_header_pair.valid.json"
        assignment = json.loads(assignment_path.read_text())
        statement = work / "statement.json"
        s31.write_json(statement, {key: assignment[key] for key in
                                   ("public_inputs", "public_outputs")})
        proof = work / "pair.proof"
        prover = package / "bin" / f"s31-{manifest['name']}-prover"
        verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        key = package / "verification-key.json"
        s31.invoke(str(prover), "prove", str(assignment_path), str(proof))
        s31.invoke(str(verifier), str(proof), str(statement), str(key))
        wrong = json.loads(statement.read_text())
        output = next(iter(wrong["public_outputs"].values()))
        output[0] = (output[0] + 1) % ((1 << 31) - 1)
        wrong_path = work / "wrong-statement.json"
        s31.write_json(wrong_path, wrong)
        try:
            s31.invoke(str(verifier), str(proof), str(wrong_path), str(key))
        except RuntimeError:
            pass
        else:
            raise AssertionError("native verifier accepted a changed pair root")
        print(json.dumps({"schema": "s31-blockhash-type-acceptance-v1",
                          "normalized_relation_equal": True,
                          "verification_key_equal": True,
                          "cost_geometry_equal": True,
                          "source_type_errors_rejected": True,
                          "native_proof_verified": True,
                          "changed_root_rejected": True,
                          "proof_bytes": proof.stat().st_size}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f"s31 blockhash acceptance: {exc}", file=sys.stderr)
        raise SystemExit(1)
