#!/usr/bin/env python3
"""Join independently received OP Mainnet derivation and execution STARK trees."""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

STATEMENT = "stwo.opstack.anchored-transition.v1"
NATIVE_PROFILE = "conjectured128_b2_q108_p20_fold4"
FIELDS = (
    "chain_id",
    "l1_chain_id",
    "anchor_number",
    "anchor_hash",
    "previous_number",
    "previous_root",
    "next_number",
    "next_root",
    "next_origin_number",
    "next_origin_hash",
    "payload_commitment",
    "block_hash",
)


def read_object(path, limit):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate JSON key")
        return result

    with path.open("rb") as f:
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"oversized authority file: {path}")
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return raw, value


def hash_bytes(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected a canonical 32-byte lowercase hex value")
    return bytes.fromhex(value)


def statement_outputs(statement):
    if set(statement) != {*FIELDS, "schema"} or statement["schema"] != STATEMENT:
        raise ValueError("unsupported anchored transition statement")
    encoded = []
    for key in FIELDS:
        value = statement[key]
        if key.endswith(("_number", "_id")):
            if type(value) is not int or not 0 <= value < 1 << 64:
                raise ValueError(f"invalid u64: {key}")
            encoded.append(value.to_bytes(8, "little"))
        else:
            encoded.append(hash_bytes(value))
    if (statement["chain_id"], statement["l1_chain_id"]) != (10, 1):
        raise ValueError("this verifier joins only OP Mainnet and Ethereum Mainnet")
    if statement["previous_number"] + 1 != statement["next_number"]:
        raise ValueError("anchored transition must be exactly one L2 block")
    if statement["next_origin_number"] > statement["anchor_number"]:
        raise ValueError("next origin exceeds the L1 anchor")
    suffix = b"\x01" + encoded[0]
    derivation = hashlib.sha256(b"stwo/opstack/anchored-transition/v1\0" + b"".join(encoded))
    execution = hashlib.sha256(b"stwo/opstack/execution-range/v1\0" + b"".join(encoded[-2:]))
    return derivation.digest() + suffix + b"OD", execution.digest() + suffix + b"OP"


def wire_bytes(value, length):
    # Zig JSON encodes [N]u8 as a string when the bytes are valid UTF-8.
    if isinstance(value, str):
        value = value.encode()
    elif isinstance(value, list) and all(type(x) is int and 0 <= x < 256 for x in value):
        value = bytes(value)
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError("invalid receiver byte string")
    return value


def admit_receipt(report, expected_output):
    for flag in (
        "accepted",
        "completed_ethereum_block",
        "shared_fresh_native_authority",
        "native_verified_before_recursion",
        "existing_recursive_proofs_only",
        "trace_only_recursive_graphs",
    ):
        if report.get(flag) is not True:
            raise ValueError(f"strict recursive receiver did not attest {flag}")
    native = report["native"]
    tree = report["recursive"]
    if (
        report.get("security_qualified") is not False
        or native.get("security_profile") != NATIVE_PROFILE
        or wire_bytes(report["output"], 43) != expected_output
        or wire_bytes(native["output"], 43) != expected_output
        or tree.get("outer_backend") != "cpu_trace_only_receiver"
    ):
        raise ValueError("recursive receipt does not match the pinned statement and profile")
    cpu, truth = native["cpu_proofs"], native["truth_proofs"]
    leaves, folds = tree["leaf_proofs"], tree["fold_proofs"]
    for count in (cpu, truth, leaves, folds, tree["root_proof_bytes"]):
        if type(count) is not int or count < 0:
            raise ValueError("invalid recursive proof coverage")
    if (
        not cpu
        or not tree["root_proof_bytes"]
        or leaves != cpu + truth
        or (leaves > 1 and not folds)
        or tree["restored_leaves"] != leaves
        or tree["restored_folds"] != folds
    ):
        raise ValueError("incomplete recursive proof coverage")
    return {
        "output": expected_output.hex(),
        "root_digest": wire_bytes(tree["root_digest"], 32).hex(),
        "root_authority": wire_bytes(tree["root_authority"], 32).hex(),
        "manifest": wire_bytes(tree["manifest"], 32).hex(),
        "root_proof_bytes": tree["root_proof_bytes"],
        "cpu_proofs": cpu,
        "service_proofs": truth,
        "recursive_leaves": leaves,
        "recursive_folds": folds,
    }


def verify(args):
    proof_dirs = [p.resolve(strict=True) for p in (args.derivation_proof, args.execution_proof)]
    if any(not p.is_dir() for p in proof_dirs) or proof_dirs[0] == proof_dirs[1]:
        raise ValueError("derivation and execution must use distinct proof directories")
    runner = args.runner.resolve(strict=True)
    authority_paths = [
        p.resolve(strict=True)
        for p in (args.statement, args.derivation_request, args.execution_request)
    ]
    if any(p.is_relative_to(d) for p in [runner, *authority_paths] for d in proof_dirs):
        raise ValueError("receiver authority must be separate from the proof directories")
    _, statement = read_object(authority_paths[0], 16_384)
    outputs = statement_outputs(statement)
    requests = [read_object(p, 16_384) for p in authority_paths[1:]]
    program_ids = []
    for (_, request), output in zip(requests, outputs, strict=True):
        if request.get("expected_output") != output.hex():
            raise ValueError("request output does not match the anchored transition statement")
        program_ids.append(hash_bytes(request.get("elf_sha256")))
        hash_bytes(request.get("input_sha256"))
    if program_ids[0] == program_ids[1]:
        raise ValueError("derivation and execution must use distinct pinned programs")

    receipts = {}
    with tempfile.TemporaryDirectory(prefix="stwo-op-transition-") as work:
        for name, proof, (raw, _), output in zip(
            ("derivation", "execution"), proof_dirs, requests, outputs, strict=True
        ):
            # Pass precisely the request bytes that were checked above. The Zig
            # receiver independently pins the image and checks terminal memory.
            request_path = Path(work) / f"{name}.json"
            request_path.write_bytes(raw)
            command = [
                str(runner), "--security-profile", NATIVE_PROFILE,
                "verify-recursion-candidate", str(request_path), str(proof),
                str(args.fixed_setup_bytes), str(args.receiver_bytes),
            ]
            result = subprocess.run(command, stdout=subprocess.PIPE, check=True, timeout=args.timeout)
            receipts[name] = admit_receipt(json.loads(result.stdout), output)
    return {
        "schema": "stwo.opstack.recursive-transition-receipt.v1",
        "accepted": True,
        "security_qualified": False,
        "in_circuit_join": False,
        "scope": "two independently verified recursive STARK trees joined by the receiver",
        "statement": statement,
        **receipts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("runner", "statement", "derivation-request", "derivation-proof", "execution-request", "execution-proof"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--fixed-setup-bytes", required=True, type=int)
    parser.add_argument("--receiver-bytes", required=True, type=int)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    if not 0 < args.fixed_setup_bytes <= args.receiver_bytes or args.timeout <= 0:
        parser.error("invalid receiver budgets or timeout")
    try:
        print(json.dumps(verify(args), indent=2))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"recursive transition rejected: {error}\n")


if __name__ == "__main__":
    main()
