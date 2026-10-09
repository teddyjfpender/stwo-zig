"""Hash-payment relation and transport tests, independent of the Zig prover."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
PAYMENTS = S31 / "examples/payments"
sys.path.insert(0, str(PAYMENTS))
sys.path.insert(0, str(S31 / "python"))

from delivery import BLOB_BYTES, open_note, seal_note
from oracle import OracleError, evaluate_relation
from reference import (P, U64, Envelope, Ledger, Note, PaymentError, assignment,
                       context_for, delivery_hash, fixture, limbs, nullifier, owner, random_words)
from text_frontend import compile_file


def invalid_witnesses(good: dict) -> dict[str, dict]:
    """Each mutation violates a distinct proof obligation or bound statement."""
    cases = {}
    for name, field, value in (
        ("inflation", "recipient_amount", limbs(376)),
        ("wrong secret", "secret", [11] * 8),
        ("wrong input opening", "input_salt", [12] * 8),
        ("wrong path", "sibling_1", [13] * 8),
        ("non-Boolean direction", "direction_0", [2]),
        ("out-of-range limb", "input_amount", [65536, 0, 0, 0]),
        ("noncanonical secret", "secret", [P] * 8),
        ("zero recipient", "recipient_amount", limbs(0)),
        ("integer overflow", "recipient_amount", limbs(U64 - 1)),
        ("field-wrap attempt", "input_amount", limbs(1000 + P)),
        ("wrong context", "context", [14] * 8),
        ("redirected recipient", "recipient_owner", [15] * 8),
        ("wrong delivery hash", "delivery", [16] * 8),
    ):
        bad = copy.deepcopy(good)
        bad["private_inputs"][field] = value
        if name == "zero recipient":
            bad["private_inputs"]["change_amount"] = limbs(995)
        # Bind the mutated transaction's own receipt wherever its wire values
        # remain canonical. Rejection must come from membership, conservation,
        # Boolean or range constraints, not just the original output mismatch.
        private = bad["private_inputs"]
        try:
            def decode(field: str) -> int:
                values = private[field]
                if any(type(x) is not int or not 0 <= x < 65536 for x in values):
                    raise PaymentError("noncanonical limb")
                return sum(x << (16 * i) for i, x in enumerate(values))
            context, secret = tuple(private["context"]), tuple(private["secret"])
            sender = owner(secret)
            old = Note(decode("input_amount"), sender, tuple(private["input_salt"]))
            recipient = Note(decode("recipient_amount"), tuple(private["recipient_owner"]),
                             tuple(private["recipient_salt"]))
            change = Note(decode("change_amount"), sender, tuple(private["change_salt"]))
            tx = Envelope(context, tuple(private["anchor"]), nullifier(context, old, secret),
                          recipient.commitment(context), change.commitment(context),
                          decode("fee"), tuple(private["delivery"]))
            bad["public_outputs"]["receipt"] = list(tx.receipt)
        except PaymentError:
            pass  # A noncanonical input is rejected before a receipt exists.
        if name in {"redirected recipient", "wrong delivery hash"}:
            # Those changes are valid different transactions. The original
            # receipt must reject them, binding recipient and delivery intent.
            bad["public_outputs"] = copy.deepcopy(good["public_outputs"])
        cases[name] = bad
    return cases


class PaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.relation, _ = compile_file(PAYMENTS / "tongo_transfer.s31")

    def test_pinned_fixture_and_only_receipt_is_public(self) -> None:
        witness = fixture()[2]
        self.assertEqual(self.relation, json.loads((PAYMENTS / "tongo_transfer.s31.json").read_text()))
        self.assertEqual(witness, json.loads((PAYMENTS / "tongo_transfer.valid.json").read_text()))
        self.assertEqual(evaluate_relation(self.relation, witness), witness["public_outputs"])
        self.assertTrue(all(x["visibility"] == "private" for x in self.relation["inputs"]))
        self.assertEqual(self.relation["proof_mode"], "blinded")
        self.assertEqual(self.relation["public_outputs"], ["receipt"])
        allowed = {"array_concat", "cast_m31", "constant", "hash_poseidon2_leaf",
                   "hash_poseidon2_pair", "int_add_checked", "int_view", "is_zero",
                   "select", "sum_lanes"}
        self.assertTrue({x["op"] for x in self.relation["nodes"]} <= allowed)

    def test_invalid_witnesses(self) -> None:
        for name, witness in invalid_witnesses(fixture()[2]).items():
            with self.subTest(name=name), self.assertRaises(OracleError):
                evaluate_relation(self.relation, witness)

    def test_large_amounts_and_zero_change(self) -> None:
        for value, payment, change_value, fee in ((U64 - 1, U64 - 2, 0, 1),
                                                  (P + 100, P + 50, 45, 5),
                                                  (1, 1, 0, 0)):
            with self.subTest(value=value):
                context = context_for("test-chain", "ledger", "token", "key")
                secret, receiver = random_words(), random_words()
                note = Note(value, owner(secret), random_words())
                ledger = Ledger(context, [note.commitment(context)])
                recipient = Note(payment, owner(receiver), random_words())
                change = Note(change_value, owner(secret), random_words())
                _, witness = assignment(ledger, 0, note, secret, recipient, change, fee, b"test memo")
                self.assertEqual(evaluate_relation(self.relation, witness), witness["public_outputs"])

    def test_each_envelope_field_is_bound(self) -> None:
        tx = fixture()[1]
        for field in ("context", "anchor", "nullifier", "recipient", "change", "delivery", "fee"):
            value = getattr(tx, field)
            changed = tx.fee + 1 if field == "fee" else ((value[0] + 1) % P, *value[1:])
            with self.subTest(field=field):
                self.assertNotEqual(tx.receipt, replace(tx, **{field: changed}).receipt)

    def test_ledger_failures_are_atomic_and_replay_is_global(self) -> None:
        ledger, tx, _, _, _, _, _ = fixture()
        memo = b"PUBLIC TEST MEMO; real delivery is exercised by acceptance"
        snapshot = (ledger.notes[:], ledger.anchors.copy(), ledger.spent.copy(), ledger.fees)
        for wrong in (replace(tx, context=(17,) * 8), replace(tx, anchor=(18,) * 8),
                      replace(tx, change=tx.recipient), replace(tx, recipient=ledger.notes[0]),
                      replace(tx, delivery=(19,) * 8)):
            with self.assertRaises(PaymentError):
                ledger.submit(wrong, memo, b"test", lambda *_: True)
            self.assertEqual(snapshot, (ledger.notes, ledger.anchors, ledger.spent, ledger.fees))
        with self.assertRaises(PaymentError):
            ledger.submit(tx, memo, b"test", lambda *_: False)
        with self.assertRaises(RuntimeError):
            ledger.submit(tx, memo, b"test", lambda *_: (_ for _ in ()).throw(RuntimeError("verifier failed")))
        self.assertEqual(snapshot, (ledger.notes, ledger.anchors, ledger.spent, ledger.fees))
        ledger.submit(tx, memo, b"unit-test mock proof", lambda _, receipt: receipt == tx.receipt)
        self.assertIn(tx.anchor, ledger.anchors)  # The old anchor is still accepted.
        with self.assertRaisesRegex(PaymentError, "already spent"):
            ledger.submit(tx, memo, b"test", lambda *_: True)
        self.assertEqual((len(ledger.notes), ledger.fees), (3, 5))

    def test_capacity_and_canonical_encodings(self) -> None:
        ledger, tx, *_ = fixture()
        full = Ledger(ledger.context, [tuple([i] * 8) for i in range(7)])
        wrong = replace(tx, anchor=full.root)
        with self.assertRaisesRegex(PaymentError, "tree is full"):
            full.submit(wrong, b"PUBLIC TEST MEMO; real delivery is exercised by acceptance",
                        b"test", lambda *_: True)
        for value in (-1, U64, True):
            with self.assertRaises(PaymentError):
                Note(value, (1,) * 8, (2,) * 8)
        with self.assertRaises(PaymentError):
            Envelope(tx.context, tx.anchor, (P,) * 8, tx.recipient, tx.change, tx.fee, tx.delivery)

    def test_context_identities_and_salt_change_commitments(self) -> None:
        _, tx, _, recipient, *_ = fixture()
        args = ["chain", "ledger", "asset", "verifier"]
        original = context_for(*args)
        for index in range(4):
            changed = args[:]
            changed[index] += "-other"
            self.assertNotEqual(original, context_for(*changed))
        self.assertNotEqual(recipient.commitment(tx.context),
                            replace(recipient, salt=(20,) * 8).commitment(tx.context))

    def test_authenticated_delivery(self) -> None:
        _, tx, _, recipient, *_ = fixture()
        key = bytes(range(32))  # Public test key.
        blob = seal_note(recipient, key, tx.context)
        self.assertEqual(len(blob), BLOB_BYTES)
        self.assertEqual(open_note(blob, key, tx.context, tx.recipient), recipient)
        self.assertNotEqual(blob, seal_note(recipient, key, tx.context))
        for index in (0, 5, 29, len(blob) - 1):
            damaged = bytearray(blob)
            damaged[index] ^= 1
            with self.subTest(index=index), self.assertRaises(PaymentError):
                open_note(bytes(damaged), key, tx.context, tx.recipient)
        for other_key, context, cm in ((b"z" * 32, tx.context, tx.recipient),
                                       (key, (21,) * 8, tx.recipient),
                                       (key, tx.context, tx.change)):
            with self.assertRaises(PaymentError):
                open_note(blob, other_key, context, cm)
        with self.assertRaises(PaymentError):
            open_note(blob[:-1], key, tx.context, tx.recipient)
        with self.assertRaises(PaymentError):
            seal_note(recipient, b"short", tx.context)
        self.assertNotEqual(delivery_hash(blob), delivery_hash(blob[:-1]))


if __name__ == "__main__":
    unittest.main()
