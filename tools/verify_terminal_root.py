#!/usr/bin/env python3
"""Verify a production circuit-recursion root with StarkWare's pinned Cairo verifier.

The proof is a Cairo felt stream. It must never be passed to this repo's
``verify`` command, which expects the internal CircuitSerialize byte format.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path


PINNED_PROVING = "5a7c5ede4299c91a61df19a07cba4f7502c14230"
FRI_CONFIG = (26, 1, 0, 70, 4)
COMPONENT_LOGS = (20, 23, 20, 21, 23, 16, 20, 8, 14, 18, 16)
STARK_PRIME = 2**251 + 17 * 2**192 + 1


def words_hash(words):
    return list(struct.unpack("<8I", hashlib.blake2s(struct.pack("<%dI" % len(words), *words)).digest()))


def checked_words(value, length=8):
    if not isinstance(value, list) or len(value) != length:
        raise ValueError("expected an eight-word digest")
    words = [int(word, 16) if isinstance(word, str) and word.startswith("0x") else word for word in value]
    if any(type(word) is not int or word < 0 or word >= 2**32 for word in words):
        raise ValueError("digest word outside u32")
    return words


def felt_preimage_hash(preimage):
    if not isinstance(preimage, list):
        raise ValueError("invalid felt preimage")
    words = []
    for decimal in preimage:
        if not isinstance(decimal, str) or not re.fullmatch(r"0|[1-9][0-9]*", decimal):
            raise ValueError("invalid decimal felt")
        value = int(decimal)
        if value >= STARK_PRIME:
            raise ValueError("noncanonical decimal felt")
        if value < 2**63:
            words.extend((value >> 32, value & 0xffffffff))
        else:
            limbs = [(value >> (32 * i)) & 0xffffffff for i in range(7, -1, -1)]
            limbs[0] |= 0x80000000
            words.extend(limbs)
    return words_hash(words)


def packed_digest(node, leaf_hashes, depth=0):
    if depth > 64 or not isinstance(node, dict) or len(node) != 1:
        raise ValueError("invalid packed tree")
    if "Plain" in node:
        return None, felt_preimage_hash(node["Plain"]["output_preimage"])
    if "Composite" not in node:
        raise ValueError("unknown packed node")
    body = node["Composite"]
    circuit_hash = checked_words(body["circuit_hash"])
    children = body["subtasks"]
    if len(children) == 1 and "Plain" in children[0]:
        if tuple(circuit_hash) not in leaf_hashes:
            raise ValueError("leaf circuit hash absent from registry")
        return circuit_hash, packed_digest(children[0], leaf_hashes, depth + 1)[1]
    if len(children) != 2:
        raise ValueError("this verifier admits pairwise folds only")
    child_data = [packed_digest(child, leaf_hashes, depth + 1) for child in children]
    if any(child_hash is None for child_hash, _ in child_data):
        raise ValueError("fold child has no circuit hash")
    return circuit_hash, words_hash([word for child_hash, digest in child_data for word in child_hash + digest])


def proof_header(proof_path):
    raw = json.loads(proof_path.read_text())
    if not isinstance(raw, list) or len(raw) < 92:
        raise ValueError("invalid root felt stream")
    for felt in raw:
        if not isinstance(felt, str) or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", felt):
            raise ValueError("noncanonical root felt")
    felts = [int(felt, 16) for felt in raw]
    if any(felt >= 2**64 for felt in felts):
        raise ValueError("root felt exceeds u64")
    if felts[0] != 8:
        raise ValueError("root must expose eight output words")
    outputs = []
    for i in range(8):
        a, b, c, d = felts[1 + 4 * i : 5 + 4 * i]
        if a >= 2**16 or b >= 2**16 or c or d:
            raise ValueError("root output is not a packed u32")
        outputs.append(a | (b << 16))
    if tuple(felts[78:83]) != FRI_CONFIG or felts[83] != 4:
        raise ValueError("unexpected FRI security or commitment count")
    return outputs, checked_words(felts[84:92])


def verify(args):
    proving = args.pinned_proving.resolve()
    revision = subprocess.check_output(["git", "-C", str(proving), "rev-parse", "HEAD"], text=True).strip()
    if revision != PINNED_PROVING:
        raise ValueError("StarkWare prover revision is not pinned")
    subprocess.run(["git", "-C", str(proving), "diff", "--quiet", "HEAD"], check=True)
    if not subprocess.check_output(["scarb", "--version"], text=True).startswith("scarb 2.18.0 "):
        raise ValueError("Scarb 2.18.0 is required")
    workspace = proving / "stwo_cairo_verifier"
    if not (workspace / "crates/circuit_verifier/src/lib.cairo").is_file():
        raise ValueError("pinned Cairo verifier source is missing")

    registry = json.loads(args.registry.read_text())
    entries = registry["multiverifiers"]
    if len(entries) != 1:
        raise ValueError("registry must name one multiverifier")
    entry = entries[0]
    config = registry["circuit_proof_configs"][entry["config"]]["fri_config"]
    if tuple(config[key] for key in ("pow_bits", "log_blowup_factor", "log_last_layer_degree_bound", "n_queries", "fold_step")) != FRI_CONFIG:
        raise ValueError("registry is not the pinned production FRI profile")

    output_claim = checked_words(json.loads(args.outputs.read_text()))
    proof_outputs, preprocessed_root = proof_header(args.proof)
    if proof_outputs != output_claim or preprocessed_root != checked_words(entry["preprocessed_root"]):
        raise ValueError("proof outputs or preprocessed root differ from claims")
    sizes = registry["circuit_proof_configs"][entry["config"]]["component_log_sizes"]
    component_logs = [sizes[key] for key in ("eq", "qm31_ops", "triple_xor", "m31_to_u32", "blake_g_gate")]
    component_logs += [16, 20, 8, 14, 18, 16]
    if tuple(component_logs) != COMPONENT_LOGS:
        raise ValueError("registry geometry differs from the pinned Cairo verifier")
    config_bytes = bytes([FRI_CONFIG[1]] + component_logs)
    computed_hash = list(struct.unpack("<8I", hashlib.blake2s(config_bytes + struct.pack("<8I", *preprocessed_root)).digest()))
    if computed_hash != checked_words(entry["circuit_hash"]):
        raise ValueError("registry circuit hash does not match committed root and geometry")
    leaf_hashes = {tuple(checked_words(leaf["circuit_hash"])) for leaf in registry["leaf_verifiers"]}
    packed_hash, packed_output = packed_digest(json.loads(args.packed.read_text()), leaf_hashes)
    if packed_hash != checked_words(entry["circuit_hash"]) or packed_output != output_claim:
        raise ValueError("packed tree disagrees with registry or output claim")

    # Rebuild the pinned executable so --no-build cannot execute stale code.
    subprocess.run(["scarb", "--profile", "proving", "build", "-p", "stwo_circuit_verifier"], cwd=workspace, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = ["scarb", "--profile", "proving", "execute", "-p", "stwo_circuit_verifier", "--no-build", "--arguments-file", str(args.proof.resolve()), "--target", "standalone", "--print-program-output", "--output", "none"]
    result = subprocess.run(command, cwd=workspace, text=True, capture_output=True)
    if result.returncode:
        raise ValueError("pinned Cairo verifier rejected proof: " + (result.stderr.strip() or result.stdout.strip()))
    marker = "Program output:\n"
    if marker not in result.stdout:
        raise ValueError("Cairo verifier did not publish an output")
    published = checked_words([int(word) for word in result.stdout.split(marker, 1)[1].splitlines()[:8]])
    expected = words_hash(packed_hash + output_claim)
    if published != expected:
        raise ValueError("Cairo verifier output disagrees with root claim")
    return {"verified": True, "proving_revision": revision, "proof_sha256": hashlib.sha256(args.proof.read_bytes()).hexdigest(), "fri_config": dict(config), "preprocessed_root": preprocessed_root, "circuit_hash": packed_hash, "root_outputs": output_claim, "verifier_output": published}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("proof", "outputs", "packed", "registry", "pinned-proving"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args), sort_keys=True))
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print("root rejected: " + str(error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
