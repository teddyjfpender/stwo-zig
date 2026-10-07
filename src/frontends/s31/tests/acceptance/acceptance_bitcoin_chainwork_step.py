#!/usr/bin/env python3
"""Native proof of one Bitcoin header's checked ChainWork transition."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tempfile
from collections import Counter
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))

import s31
from oracle import evaluate_relation
from poseidon2_oracle import leaf, pair
from text_frontend import compile_file

SOURCE = S31 / "examples/bitcoin/bitcoin_chainwork_step.s31"
RELATION = SOURCE.with_suffix(".s31.json")
FIXTURE = SOURCE.with_suffix(".valid.json")
MEASUREMENT = s31.ROOT / "design/s31/measurements/bitcoin/bitcoin-chainwork-step-mvp-2026-10-07.json"
LIMIT = 1 << 256


def from_limbs(limbs: list[int]) -> int:
    if len(limbs) != 16 or any(type(word) is not int or not 0 <= word < 65536 for word in limbs):
        raise AssertionError("expected sixteen canonical little-endian u16 limbs")
    return sum(word << (16 * index) for index, word in enumerate(limbs))


def to_limbs(number: int) -> list[int]:
    if not 0 <= number < LIMIT:
        raise AssertionError("ChainWork overflow")
    return [(number >> (16 * index)) & 0xffff for index in range(16)]


def independent_claim(assignment: dict) -> tuple[list[int], dict]:
    """Use hashlib, Python integer arithmetic, and the pinned Poseidon oracle."""
    previous_limbs = assignment["private_inputs"]["previous"]
    previous = from_limbs(previous_limbs)
    header_limbs = assignment["private_inputs"]["header"]
    if len(header_limbs) != 40 or any(type(word) is not int or not 0 <= word < 65536 for word in header_limbs):
        raise AssertionError("expected forty canonical little-endian header limbs")
    header = struct.pack("<40H", *header_limbs)
    compact = struct.unpack_from("<I", header, 72)[0]
    exponent, mantissa = compact >> 24, compact & 0x7fffff
    if compact & 0x800000 or not 3 <= exponent <= 32 or mantissa == 0:
        raise AssertionError("invalid mainnet compact target")
    target = mantissa << (8 * (exponent - 3))
    if target > 0xffff << 208:
        raise AssertionError("target exceeds mainnet powLimit")
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    if int.from_bytes(block_hash, "little") > target:
        raise AssertionError("header fails proof of work")
    work = LIMIT // (target + 1)
    next_work = previous + work
    next_limbs = to_limbs(next_work)
    hash_limbs = list(struct.unpack("<16H", block_hash))
    root = pair(pair(leaf(previous_limbs), leaf(next_limbs)), leaf(hash_limbs))
    return root, {
        "previous_chainwork_hex": f"{previous:064x}",
        "next_chainwork_hex": f"{next_work:064x}",
        "block_work": work,
        "block_hash_display_hex": block_hash[::-1].hex(),
        "target_hex": f"{target:064x}",
    }


def rejects(*command: object) -> None:
    try:
        s31.invoke(*(str(part) for part in command))
    except RuntimeError:
        return
    raise AssertionError(f"invalid proof, statement, key, or witness was accepted: {command}")


def main() -> None:
    relation, _ = compile_file(SOURCE)
    if relation != json.loads(RELATION.read_text()):
        raise AssertionError("checked-in normalized relation changed")
    inputs = {(item["name"], item["kind"], item["length"], item["visibility"])
              for item in relation["inputs"]}
    if inputs != {("previous", "u16", 16, "private"), ("header", "u16", 40, "private")}:
        raise AssertionError("ChainWork example input ABI changed")
    operations = Counter(node["op"] for node in relation["nodes"])
    for op in ("hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_block_work",
               "u256_add_checked", "u256_le"):
        if operations[op] != 1:
            raise AssertionError(f"expected one constrained {op}, got {operations[op]}")
    if operations["u256_add"]:
        raise AssertionError("ChainWork transition silently changed to wrapping addition")
    assignment = json.loads(FIXTURE.read_text())
    root, values = independent_claim(assignment)
    output_name = relation["public_outputs"][0]
    if assignment["public_outputs"] != {output_name: root}:
        raise AssertionError("fixture public ChainWork commitment differs from independent oracle")
    if evaluate_relation(relation, assignment) != assignment["public_outputs"]:
        raise AssertionError("independent relation interpreter disagrees with Bitcoin oracle")

    with tempfile.TemporaryDirectory(prefix="s31-chainwork-step-") as directory:
        work_dir = Path(directory)
        trial = s31.trial(SOURCE, FIXTURE, work_dir / "trial", "sparse-wide-gate")
        if trial["native_verifier_accepted"] is not True or trial["independent_value_oracle"]["status"] != "passed":
            raise AssertionError("native proof or independent relation oracle failed")
        if trial["changed_public_statement_rejected"] != f"public_outputs.{output_name}[0]":
            raise AssertionError("native verifier accepted changed ChainWork commitment")
        if trial["profile"] != "sparse-wide-v5":
            raise AssertionError("ChainWork step changed proof profile")
        if trial["raw"]["qm31_ops"] > 400_000 or trial["padded"]["qm31_ops"] > 524_288:
            raise AssertionError("ChainWork step exceeded the MVP circuit cost ceiling")
        measured = json.loads(MEASUREMENT.read_text())
        if measured.get("schema") != "s31-bitcoin-chainwork-step-mvp-v1":
            raise AssertionError("invalid ChainWork measurement record")
        for field in ("program_sha256", "canonical_ir_sha256", "raw", "padded", "preprocessed_cells"):
            if trial[field] != measured[field]:
                raise AssertionError(f"ChainWork pinned cost or program changed: {field}")
        if trial["proof_bytes"] > 1_000_000:
            raise AssertionError("ChainWork proof exceeded the MVP size ceiling")
        package = work_dir / "trial/package"
        prover = package / "bin/s31-bitcoin_chainwork_step-prover"
        verifier = package / "bin/s31-bitcoin_chainwork_step-native-verifier"
        key = package / "verification-key.json"
        proof = work_dir / "trial/proof.bin"
        statement = work_dir / "trial/statement.json"

        damaged_proof = bytearray(proof.read_bytes())
        damaged_proof[len(damaged_proof) // 2] ^= 1
        damaged_path = work_dir / "damaged.proof"
        damaged_path.write_bytes(damaged_proof)
        rejects(verifier, damaged_path, statement, key)

        changed_key = json.loads(key.read_text())
        changed_key["program_sha256"] = "0" * 64
        changed_key_path = work_dir / "changed-key.json"
        s31.write_json(changed_key_path, changed_key)
        rejects(verifier, proof, statement, changed_key_path)

        changed_claim = copy.deepcopy(assignment)
        changed_claim["public_outputs"][output_name][0] = (root[0] + 1) % ((1 << 31) - 1)
        false_claim_path = work_dir / "false-claim.json"
        s31.write_json(false_claim_path, changed_claim)
        rejects(prover, "prove", false_claim_path, work_dir / "false-claim.proof")

        changed_previous = copy.deepcopy(assignment)
        changed_previous["private_inputs"]["previous"][0] ^= 1
        alternate_root, _ = independent_claim(changed_previous)
        if alternate_root == root:
            raise AssertionError("changed previous ChainWork unexpectedly kept commitment")
        changed_previous_path = work_dir / "changed-previous.json"
        s31.write_json(changed_previous_path, changed_previous)
        rejects(prover, "prove", changed_previous_path, work_dir / "changed-previous.proof")

        overflow = copy.deepcopy(assignment)
        overflow["private_inputs"]["previous"] = [65535] * 16
        overflow_path = work_dir / "overflow.json"
        s31.write_json(overflow_path, overflow)
        try:
            independent_claim(overflow)
        except AssertionError as error:
            if str(error) != "ChainWork overflow":
                raise
        else:
            raise AssertionError("independent oracle accepted ChainWork overflow")
        rejects(prover, "prove", overflow_path, work_dir / "overflow.proof")

        bad_nonce = copy.deepcopy(assignment)
        bad_nonce["private_inputs"]["header"][39] ^= 1
        bad_nonce_path = work_dir / "bad-nonce.json"
        s31.write_json(bad_nonce_path, bad_nonce)
        try:
            independent_claim(bad_nonce)
        except AssertionError as error:
            if str(error) != "header fails proof of work":
                raise
        else:
            raise AssertionError("changed nonce unexpectedly retained valid PoW")
        rejects(prover, "prove", bad_nonce_path, work_dir / "bad-nonce.proof")

        print(json.dumps({
            "schema": "s31-bitcoin-chainwork-step-acceptance-v1",
            "source": str(SOURCE.relative_to(S31.parents[2])),
            "lowering": trial["lowering"],
            "profile": trial["profile"],
            "native_verifier_accepted": True,
            "independent_bitcoin_and_poseidon_oracle": True,
            "changed_public_claim_rejected": True,
            "changed_private_previous_rejected": True,
            "invalid_pow_rejected": True,
            "checked_chainwork_overflow_rejected": True,
            "damaged_proof_rejected": True,
            "changed_verification_key_rejected": True,
            "public_claim": root,
            "bitcoin_values": values,
            "canonical_ir_sha256": trial["canonical_ir_sha256"],
            "program_sha256": trial["program_sha256"],
            "proof_bytes": trial["proof_bytes"],
            "raw": trial["raw"],
            "padded": trial["padded"],
            "preprocessed_cells": trial["preprocessed_cells"],
            "fri": trial["visible_fri"],
            "prove_seconds": trial["prove_seconds"],
            "verify_seconds": trial["verify_seconds"],
            "timing_note": trial["timing_note"],
        }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as error:
        print(f"S31 Bitcoin ChainWork step acceptance: {error}", file=sys.stderr)
        raise SystemExit(1)
