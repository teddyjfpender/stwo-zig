#!/usr/bin/env python3
"""Prove one new Bitcoin header link and reject a forged predecessor."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import poseidon2_oracle as poseidon
import s31
from oracle import evaluate_relation
from text_frontend import compile_file


def bytes_of(words: list[int]) -> bytes:
    if len(words) != 40:
        raise AssertionError("expected exactly one serialized Bitcoin header")
    return b"".join(word.to_bytes(2, "little") for word in words)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def limbs(digest: bytes) -> list[int]:
    if len(digest) != 32:
        raise AssertionError("expected a 32-byte digest")
    return [int.from_bytes(digest[i:i + 2], "little") for i in range(0, 32, 2)]


def main() -> None:
    examples = s31.S31_DIR / "examples"
    source = examples / "bitcoin" / "bitcoin_header_link.s31"
    assignment_path = examples / "bitcoin" / "bitcoin_header_link.valid.json"
    relation, _ = compile_file(source)
    assignment = json.loads(assignment_path.read_text())
    pair = json.loads((examples / "bitcoin" / "bitcoin_header_pair.valid.json").read_text())
    parent_bytes = bytes_of(pair["private_inputs"]["parent"])
    child_bytes = bytes_of(assignment["private_inputs"]["child"])
    prior_digest = sha256d(parent_bytes)
    if (assignment["private_inputs"]["prior_hash"] != limbs(prior_digest) or
            child_bytes != bytes_of(pair["private_inputs"]["child"]) or
            child_bytes[4:36] != prior_digest):
        raise AssertionError("fixture is not the genesis-to-block-one link")
    child_digest = sha256d(child_bytes)
    expected_root = poseidon.pair(poseidon.leaf(limbs(prior_digest)),
                                  poseidon.leaf(limbs(child_digest)))
    if (assignment["public_outputs"] != {"link_root": expected_root} or
            expected_root != pair["public_outputs"]["segment_root"]):
        raise AssertionError("independent SHA256d/Poseidon2 oracle disagrees")
    if evaluate_relation(relation, assignment) != assignment["public_outputs"]:
        raise AssertionError("source relation disagrees with independent oracles")

    with tempfile.TemporaryDirectory(prefix="s31-header-link-") as directory:
        work = Path(directory)
        package = s31.build(source, work / "package", "sparse-wide-gate", 4)
        manifest = s31.verify_package(package)
        report = json.loads((package / "cost-report.json").read_text())
        statement = work / "statement.json"
        s31.write_json(statement, {"public_inputs": {},
                                   "public_outputs": assignment["public_outputs"]})
        proof = work / "link.proof"
        s31.write_json(Path(str(proof) + ".statement.json"),
                       json.loads(statement.read_text()))
        prover = package / "bin" / f"s31-{manifest['name']}-prover"
        verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        key = package / "verification-key.json"
        s31.invoke(str(prover), "prove", str(assignment_path), str(proof))
        s31.invoke(str(verifier), str(proof), str(statement), str(key))

        forged = json.loads(assignment_path.read_text())
        forged["private_inputs"]["prior_hash"][0] ^= 1
        # Give the forgery its *correct* new commitment. Rejection must come
        # from the constrained prev_hash equality, not a stale public root.
        forged["public_outputs"]["link_root"] = poseidon.pair(
            poseidon.leaf(forged["private_inputs"]["prior_hash"]),
            poseidon.leaf(limbs(child_digest)))
        if forged["public_outputs"] == assignment["public_outputs"]:
            raise AssertionError("forged predecessor did not change its commitment")
        try:
            evaluate_relation(relation, forged)
        except ValueError as exc:
            if "assertions[0] failed" not in str(exc):
                raise AssertionError(f"forged link failed for another reason: {exc}") from exc
        else:
            raise AssertionError("independent oracle accepted an unlinked predecessor")
        forged_path = work / "forged-prior.json"
        s31.write_json(forged_path, forged)
        try:
            s31.invoke(str(prover), "prove", str(forged_path),
                       str(work / "forged-prior.proof"))
        except RuntimeError:
            pass
        else:
            raise AssertionError("prover accepted an unlinked predecessor")

        wrong = json.loads(statement.read_text())
        wrong["public_outputs"]["link_root"][0] = (
            wrong["public_outputs"]["link_root"][0] + 1) % ((1 << 31) - 1)
        wrong_path = work / "wrong-root.json"
        s31.write_json(wrong_path, wrong)
        try:
            s31.invoke(str(verifier), str(proof), str(wrong_path), str(key))
        except RuntimeError:
            pass
        else:
            raise AssertionError("native verifier accepted a changed transition root")

        cli = (sys.executable, str(s31.S31_DIR / "python/s31.py"))
        outer = work / "link-recursive.proof"
        s31.invoke(*cli, "wrap", str(package), str(proof), str(outer), "--low-memory")
        s31.invoke(*cli, "verify-recursive", str(package), str(outer))
        outer_statement = json.loads(Path(str(outer) + ".statement.json").read_text())
        altered_outer = json.loads(json.dumps(outer_statement))
        altered_outer["child_public_words"][0] ^= 1
        altered_outer_path = work / "wrong-recursive-child.json"
        s31.write_json(altered_outer_path, altered_outer)
        try:
            s31.invoke(*cli, "verify-recursive", str(package), str(outer),
                       "--statement", str(altered_outer_path))
        except RuntimeError:
            pass
        else:
            raise AssertionError("recursive verifier accepted a changed child statement")

        print(json.dumps({"schema": "s31-header-link-acceptance-v1",
                          "oracle_agreed": True, "native_proof_verified": True,
                          "forged_predecessor_rejected": True,
                          "changed_transition_root_rejected": True,
                          "recursive_proof_verified": True,
                          "changed_recursive_child_rejected": True,
                          "raw": report["raw"], "padded": report["padded"],
                          "proof_bytes": proof.stat().st_size,
                          "recursive_proof_bytes": outer.stat().st_size}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f"s31 header link acceptance: {exc}", file=sys.stderr)
        raise SystemExit(1)
