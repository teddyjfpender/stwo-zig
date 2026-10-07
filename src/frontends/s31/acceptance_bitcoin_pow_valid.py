#!/usr/bin/env python3
"""Differential and native-proof acceptance for std::bitcoin::pow_valid."""

import copy
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path

import s31
from s31_stdlib import encode_header80
from text_frontend import compile_file


EXAMPLES = Path(__file__).resolve().parent / "examples"
STANDARD = EXAMPLES / "bitcoin_pow_valid_std.s31"
MANUAL = EXAMPLES / "bitcoin_pow_valid_manual.s31"
ASSIGNMENT = EXAMPLES / "bitcoin_pow_valid.valid.json"


def structural_relation(relation: dict) -> dict:
    """Alpha-rename compiler temporaries while preserving every relation edge."""
    names = {item["name"]: f"input{index}" for index, item in enumerate(relation["inputs"])}
    nodes = []
    for index, node in enumerate(relation["nodes"]):
        entry = {key: names[value] if key in {"lhs", "rhs", "selector"} else value
                 for key, value in node.items() if key != "name"}
        nodes.append(entry)
        names[node["name"]] = f"node{index}"
    return {
        "inputs": [{key: value for key, value in item.items() if key != "name"}
                   for item in relation["inputs"]],
        "nodes": nodes,
        "assertions": [{key: names[value] for key, value in item.items()}
                       for item in relation["assertions"]],
        "public_outputs": [names[name] for name in relation["public_outputs"]],
    }


def independent_pow(header_limbs: list[int]) -> bool:
    header = encode_header80(header_limbs)
    raw_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    compact = struct.unpack_from("<I", header, 72)[0]
    exponent, mantissa = compact >> 24, compact & 0x007fffff
    if compact & 0x00800000 or not 3 <= exponent <= 32 or mantissa == 0:
        return False
    target = mantissa << (8 * (exponent - 3))
    mainnet_limit = 0x00ffff << (8 * (0x1d - 3))
    return target <= mainnet_limit and int.from_bytes(raw_hash, "little") <= target


def reject_bad_witness(package: Path, assignment: dict, work: Path, label: str) -> None:
    prover = package / "bin" / f"s31-{label}-prover"
    for kind in ("nonce", "compact"):
        changed = copy.deepcopy(assignment)
        changed["private_inputs"]["header"][39 if kind == "nonce" else 37] += 1
        if kind == "compact":
            changed["private_inputs"]["header"][37] = 0x1d80
        if independent_pow(changed["private_inputs"]["header"]):
            raise AssertionError(f"{kind}: negative fixture unexpectedly has valid PoW")
        path = work / f"{label}-{kind}.json"
        s31.write_json(path, changed)
        try:
            s31.invoke(str(prover), "prove", str(path), str(work / f"{label}-{kind}.proof"))
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"{label}: prover accepted {kind} mutation")


def main() -> None:
    assignment = json.loads(ASSIGNMENT.read_text())
    if not independent_pow(assignment["private_inputs"]["header"]):
        raise AssertionError("valid genesis fixture fails independent hashlib PoW")
    standard_relation, _ = compile_file(STANDARD)
    manual_relation, _ = compile_file(MANUAL)
    if structural_relation(standard_relation) != structural_relation(manual_relation):
        raise AssertionError("pow_valid adds or changes normalized relation operations")
    with tempfile.TemporaryDirectory(prefix="s31-pow-valid-") as temporary:
        work = Path(temporary)
        reports = {}
        for label, source in (("bitcoin_pow_valid_std", STANDARD), ("bitcoin_pow_valid_manual", MANUAL)):
            trial = s31.trial(source, ASSIGNMENT, work / label, "sparse-wide-gate")
            if trial["independent_value_oracle"] != {"status": "passed", "computed_public_outputs": {"valid": [1]}}:
                raise AssertionError(f"{label}: independent relation oracle differs")
            if trial["changed_public_statement_rejected"] != "public_outputs.valid[0]":
                raise AssertionError(f"{label}: changed public bit was accepted")
            reject_bad_witness(work / label / "package", assignment, work, label)
            reports[label] = trial
        std_report = reports["bitcoin_pow_valid_std"]
        manual_report = reports["bitcoin_pow_valid_manual"]
        for field in ("profile", "raw", "padded", "preprocessed_cells"):
            if std_report[field] != manual_report[field]:
                raise AssertionError(f"helper changed {field} cost")
        print(json.dumps({
            "schema": "s31-bitcoin-pow-valid-acceptance-v1",
            "native_verified": True,
            "independent_sha256d_and_compact_target": True,
            "structurally_equal_relation": True,
            "same_cost_geometry": True,
            "raw": std_report["raw"],
            "padded": std_report["padded"],
            "std_proof_bytes": std_report["proof_bytes"],
            "manual_proof_bytes": manual_report["proof_bytes"],
            "changed_public_claim_rejected": True,
            "invalid_compact_and_nonce_rejected": True,
        }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f"S31 Bitcoin PoW helper acceptance: {exc}", file=sys.stderr)
        raise SystemExit(1)
