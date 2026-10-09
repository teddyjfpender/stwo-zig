#!/usr/bin/env python3
"""Two native-verified S31 hash payments and adversarial checks; synthetic use.

Retain source-bound packages, proofs, statements and diagnostic costs in zig-out.
This checks payment validity, not proof zero knowledge or Rust interoperability.
"""

from __future__ import annotations

import hashlib
import json
import platform
import secrets
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
PAYMENTS = S31 / "examples/payments"
sys.path.insert(0, str(PAYMENTS))
sys.path.insert(0, str(S31 / "python"))
sys.path.insert(0, str(S31 / "tests/python"))

import s31
from delivery import open_note, seal_note
from oracle import OracleError, evaluate_relation
from reference import (P, U64, Ledger, Note, PaymentError, assignment, context_for,
                       fixture, owner, random_words)
from test_tongo import invalid_witnesses
from text_frontend import compile_file
from acceptance_proof_privacy import commitments


def run(*args: object, accept: bool) -> subprocess.CompletedProcess:
    result = subprocess.run([str(x) for x in args], cwd=s31.ROOT, text=True,
                            capture_output=True, timeout=300)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit for {args}:\n{result.stdout}{result.stderr}")
    return result


def main() -> None:
    work = s31.ROOT / "zig-out/s31/tongo-acceptance"
    work.mkdir(parents=True, exist_ok=True)
    source = PAYMENTS / "tongo_transfer.s31"
    relation, _ = compile_file(source)
    package = s31.build(source, work / "blinded-package", "gate")
    s31.verify_package(package)
    prover = package / "bin/s31-tongo_transfer-prover"
    verifier = package / "bin/s31-tongo_transfer-native-verifier"
    key = package / "verification-key.json"
    proofs, rejected = [], []

    def verify(proof: bytes, receipt: tuple[int, ...]) -> bool:
        path, statement = work / "verify.proof", work / "verify.statement.json"
        path.write_bytes(proof)
        s31.write_json(statement, {"public_inputs": {}, "public_outputs": {"receipt": list(receipt)}})
        result = subprocess.run([str(verifier), str(path), str(statement), str(key)],
                                cwd=s31.ROOT, capture_output=True, timeout=300)
        return result.returncode == 0

    def prove(witness: dict, label: str) -> bytes:
        if evaluate_relation(relation, witness) != witness["public_outputs"]:
            raise AssertionError("independent payment oracle disagrees")
        path, proof_path = work / f"{label}.assignment.json", work / f"{label}.proof"
        s31.write_json(path, witness)  # Synthetic secrets only.
        started = time.perf_counter()
        result = run(prover, "prove", path, proof_path, accept=True)
        elapsed = time.perf_counter() - started
        proof = proof_path.read_bytes()
        started = time.perf_counter()
        if not verify(proof, tuple(witness["public_outputs"]["receipt"])):
            raise AssertionError("native verifier rejected valid payment")
        proofs.append({"label": label, "proof_bytes": len(proof), "prove_wall_s": elapsed,
                       "verify_wall_s": time.perf_counter() - started,
                       "prover_log": result.stdout + result.stderr,
                       "proof_sha256": hashlib.sha256(proof).hexdigest()})
        return proof

    ledger, _, _, recipient, _, alice, bob = fixture()
    # Establish this synthetic invoice key privately before sending. The
    # recipient receives the encrypted opening and can then spend its note.
    invoice_key = secrets.token_bytes(32)
    original = Note(1000, owner(alice), tuple(range(201, 209)))
    change = Note(620, owner(alice), tuple(range(401, 409)))
    memo = seal_note(recipient, invoice_key, ledger.context)
    first, good = assignment(ledger, 0, original, alice, recipient, change, 5, memo)
    proof = prove(good, "alice-to-bob")
    repeated = prove(good, "alice-to-bob-repeat")
    # Non-determinism is a regression check for fresh entropy, not a ZK proof.
    if commitments(proof)[0] != commitments(repeated)[0] or commitments(proof)[1] == commitments(repeated)[1]:
        raise AssertionError("repeated payment must have different trace commitments")

    for field in ("context", "anchor", "nullifier", "recipient", "change", "delivery", "fee"):
        value = getattr(first, field)
        mutated = first.fee + 1 if field == "fee" else ((value[0] + 1) % P, *value[1:])
        if verify(proof, replace(first, **{field: mutated}).receipt):
            raise AssertionError(f"native verifier accepted changed {field}")
        rejected.append(f"changed {field}")
    if verify(proof[:len(proof) // 2], first.receipt):
        raise AssertionError("native verifier accepted truncated proof")
    rejected.append("truncated proof")
    damaged = bytearray(proof)
    damaged[len(proof) // 2] ^= 1
    if verify(bytes(damaged), first.receipt):
        raise AssertionError("native verifier accepted damaged proof")
    rejected.append("damaged proof")

    for label, bad in invalid_witnesses(good).items():
        try:
            evaluate_relation(relation, bad)
        except OracleError:
            pass
        else:
            raise AssertionError(f"oracle accepted {label}")
        path = work / "invalid.assignment.json"
        s31.write_json(path, bad)
        run(prover, "prove", path, work / "invalid.proof", accept=False)
        rejected.append(label)

    ledger.submit(first, memo, proof, verify)
    received = open_note(memo, invoice_key, ledger.context, first.recipient)
    if received.owner != owner(bob):
        raise AssertionError("delivered note belongs to wrong receiver")
    back = Note(123, owner(alice), random_words())
    bob_change = Note(247, owner(bob), random_words())
    second_key = secrets.token_bytes(32)
    second_memo = seal_note(back, second_key, ledger.context)
    second, next_witness = assignment(ledger, 1, received, bob, back, bob_change, 5, second_memo)
    next_proof = prove(next_witness, "bob-to-alice")
    ledger.submit(second, second_memo, next_proof, verify)
    if open_note(second_memo, second_key, ledger.context, second.recipient) != back:
        raise AssertionError("return note delivery failed")
    try:
        ledger.submit(first, memo, proof, verify)
    except PaymentError as error:
        if str(error) != "note already spent":
            raise
    else:
        raise AssertionError("historical-root replay accepted")
    rejected.append("historical-root replay")

    # Prove integer boundaries as well as checking them in the value oracle.
    secret = random_words()
    context = context_for("boundary-chain", "ledger", "asset", hashlib.sha256(source.read_bytes()).hexdigest())
    large = Note(U64 - 1, owner(secret), random_words())
    boundary = Ledger(context, [large.commitment(context)])
    payment = Note(U64 - 2, owner(alice), random_words())
    zero_change = Note(0, owner(secret), random_words())
    _, large_witness = assignment(boundary, 0, large, secret, payment, zero_change, 1, b"boundary test memo")
    prove(large_witness, "u64-max-zero-change")

    report = {"schema": "s31-hash-payment-acceptance-v1", "lowering": "gate", "proof_mode": "blinded",
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "compiler_sha256": s31.verify_package(package)["compiler_sha256"],
              "host": {"platform": platform.platform(), "machine": platform.machine(),
                       "zig": run("zig", "version", accept=True).stdout.strip()},
              "proofs": proofs, "rejected": rejected,
              "ledger": {"notes": len(ledger.notes), "spent": len(ledger.spent), "fees": ledger.fees},
              "cost": json.loads((package / "cost-report.json").read_text()),
              "scope": "native-verified validity diagnostics; no zero-knowledge or Rust parity claim"}
    s31.write_json(work / "report.json", report)
    print(json.dumps({"accepted": len(proofs), "rejected": len(rejected),
                      "proof_bytes": [x["proof_bytes"] for x in proofs],
                      "ledger": report["ledger"], "report": str(work / "report.json")}, indent=2))


if __name__ == "__main__":
    main()
