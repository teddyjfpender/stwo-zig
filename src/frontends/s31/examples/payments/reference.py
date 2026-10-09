"""Independent value model for the S31 hash-payment example; synthetic use only.

The bounded ledger stores public commitments and nullifiers, never note openings.
Its verifier callback must check the pinned native key against the supplied receipt.
Initial commitments stand for already authenticated, funded state.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))
import poseidon2_oracle as poseidon

P = (1 << 31) - 1
U64 = 1 << 64
DEPTH = 3
CAPACITY = 1 << DEPTH
Digest = tuple[int, ...]
TAGS = {"owner": 73101, "salt": 73102, "note": 73103, "nullifier": 73104,
        "fee": 73105, "empty": 73106, "transaction": 73107,
        "delivery": 73108, "context": 73109}


class PaymentError(ValueError):
    """An invalid note, envelope or state transition."""


def words(value: tuple[int, ...] | list[int]) -> Digest:
    if len(value) != 8 or any(type(x) is not int or not 0 <= x < P for x in value):
        raise PaymentError("expected eight canonical M31 words")
    return tuple(value)


def amount(value: int) -> int:
    if type(value) is not int or not 0 <= value < U64:
        raise PaymentError("expected an unsigned 64-bit amount")
    return value


def limbs(value: int) -> list[int]:
    return [(amount(value) >> (16 * i)) & 65535 for i in range(4)]


def leaf(value: list[int] | Digest) -> Digest:
    return tuple(poseidon.leaf(list(value)))


def pair(left: Digest, right: Digest) -> Digest:
    return tuple(poseidon.pair(list(words(left)), list(words(right))))


def tagged(role: str, value: list[int] | Digest = ()) -> Digest:
    return leaf([TAGS[role]] * 4 + list(value))


def random_words() -> Digest:
    return tuple(secrets.randbelow(P) for _ in range(8))


def context_for(chain: str, ledger: str, asset: str, verifier: str) -> Digest:
    if any(type(x) is not str or not x for x in (chain, ledger, asset, verifier)):
        raise PaymentError("context identities must be nonempty strings")
    data = json.dumps(["s31-hash-payments-v1", chain, ledger, asset, verifier],
                      ensure_ascii=True, separators=(",", ":")).encode()
    return tagged("context", [x % P for x in struct.unpack("<8I", hashlib.sha256(data).digest())])


def owner(secret: Digest) -> Digest:
    return tagged("owner", words(secret))


@dataclass(frozen=True)
class Note:
    value: int
    owner: Digest
    salt: Digest

    def __post_init__(self) -> None:
        amount(self.value)
        words(self.owner)
        words(self.salt)
        if type(self.owner) is not tuple or type(self.salt) is not tuple:
            raise PaymentError("note words must be immutable tuples")

    def commitment(self, context: Digest) -> Digest:
        metadata = pair(tagged("note", limbs(self.value)), words(context))
        return pair(metadata, pair(self.owner, tagged("salt", self.salt)))


def nullifier(context: Digest, note: Note, secret: Digest) -> Digest:
    if note.owner != owner(secret):
        raise PaymentError("spending secret does not own this note")
    return pair(tagged("nullifier", secret), note.commitment(context))


def delivery_hash(memo: bytes) -> Digest:
    if type(memo) is not bytes or not 1 <= len(memo) <= 4096:
        raise PaymentError("delivery must contain 1..4096 bytes")
    raw = hashlib.sha256(memo).digest()
    return tagged("delivery", [x % P for x in struct.unpack("<8I", raw)])


@dataclass(frozen=True)
class Envelope:
    context: Digest
    anchor: Digest
    nullifier: Digest
    recipient: Digest
    change: Digest
    fee: int
    delivery: Digest

    def __post_init__(self) -> None:
        for digest in (self.context, self.anchor, self.nullifier, self.recipient,
                       self.change, self.delivery):
            words(digest)
            if type(digest) is not tuple:
                raise PaymentError("envelope words must be immutable tuples")
        amount(self.fee)

    @property
    def receipt(self) -> Digest:
        scope = pair(tagged("transaction"), self.context)
        spent = pair(self.anchor, self.nullifier)
        created = pair(self.recipient, self.change)
        extras = pair(tagged("fee", limbs(self.fee)), self.delivery)
        return pair(pair(scope, spent), pair(created, extras))


def merkle_levels(commitments: list[Digest]) -> list[list[Digest]]:
    if len(commitments) > CAPACITY:
        raise PaymentError("note tree is full")
    levels = [[words(cm) for cm in commitments] + [tagged("empty")] * (CAPACITY - len(commitments))]
    for _ in range(DEPTH):
        old = levels[-1]
        levels.append([pair(old[i], old[i + 1]) for i in range(0, len(old), 2)])
    return levels


class Ledger:
    """Eight-leaf reference state machine. Not a vault or deployable contract."""

    def __init__(self, context: Digest, funded: list[Digest]) -> None:
        self.context = words(context)
        self.notes = [words(cm) for cm in funded]
        if len(set(self.notes)) != len(self.notes):
            raise PaymentError("duplicate funded commitment")
        self.anchors = {self.root}
        self.spent: set[Digest] = set()
        self.fees = 0

    @property
    def root(self) -> Digest:
        return merkle_levels(self.notes)[-1][0]

    def path(self, index: int) -> tuple[list[Digest], list[int]]:
        if type(index) is not int or not 0 <= index < len(self.notes):
            raise PaymentError("unknown note index")
        levels = merkle_levels(self.notes)
        siblings, directions = [], []
        for level in levels[:-1]:
            siblings.append(level[index ^ 1])
            directions.append(index & 1)
            index >>= 1
        return siblings, directions

    def submit(self, tx: Envelope, memo: bytes, proof: bytes,
               verify: Callable[[bytes, Digest], bool]) -> None:
        if tx.context != self.context or tx.anchor not in self.anchors:
            raise PaymentError("wrong context or unknown root")
        if tx.nullifier in self.spent:
            raise PaymentError("note already spent")
        outputs = [tx.recipient, tx.change]
        if len(set(outputs)) != 2 or any(cm in self.notes for cm in outputs):
            raise PaymentError("duplicate output commitment")
        if tx.delivery != delivery_hash(memo):
            raise PaymentError("delivery bytes do not match envelope")
        next_notes = self.notes + outputs
        next_root = merkle_levels(next_notes)[-1][0]  # Capacity check before verification.
        next_anchors = self.anchors | {next_root}
        next_spent = self.spent | {tx.nullifier}
        next_fees = self.fees + tx.fee
        if verify(proof, tx.receipt) is not True:
            raise PaymentError("proof rejected")
        # All potentially failing checks precede mutation; retained state is bounded.
        self.notes, self.anchors, self.spent, self.fees = next_notes, next_anchors, next_spent, next_fees


def assignment(ledger: Ledger, index: int, spent: Note, secret: Digest,
               recipient: Note, change: Note, fee: int, memo: bytes) -> tuple[Envelope, dict]:
    """Build the independent envelope and the private S31 assignment."""
    if spent.commitment(ledger.context) != ledger.notes[index]:
        raise PaymentError("note opening does not match leaf")
    if spent.value != recipient.value + change.value + amount(fee) or recipient.value == 0:
        raise PaymentError("value conservation or positive recipient failed")
    if change.owner != owner(secret):
        raise PaymentError("change must belong to sender")
    siblings, directions = ledger.path(index)
    tx = Envelope(ledger.context, ledger.root, nullifier(ledger.context, spent, secret),
                  recipient.commitment(ledger.context), change.commitment(ledger.context),
                  fee, delivery_hash(memo))
    private = {"context": list(tx.context), "anchor": list(tx.anchor),
               "delivery": list(tx.delivery), "secret": list(secret),
               "input_amount": limbs(spent.value), "input_salt": list(spent.salt),
               "recipient_owner": list(recipient.owner), "recipient_amount": limbs(recipient.value),
               "recipient_salt": list(recipient.salt), "change_amount": limbs(change.value),
               "change_salt": list(change.salt), "fee": limbs(fee)}
    for i, (sibling, direction) in enumerate(zip(siblings, directions, strict=True)):
        private[f"sibling_{i}"] = list(sibling)
        private[f"direction_{i}"] = [direction]
    return tx, {"public_inputs": {}, "private_inputs": private,
                "public_outputs": {"receipt": list(tx.receipt)}}


def fixture() -> tuple[Ledger, Envelope, dict, Note, Note, Digest, Digest]:
    """Deliberately public example secrets, not a wallet key-generation method."""
    source = Path(__file__).with_name("tongo_transfer.s31")
    context = context_for("SN_SEPOLIA", "example-ledger", "example-token",
                          hashlib.sha256(source.read_bytes()).hexdigest())
    alice, bob = tuple(range(1, 9)), tuple(range(101, 109))
    original = Note(1000, owner(alice), tuple(range(201, 209)))
    recipient = Note(375, owner(bob), tuple(range(301, 309)))
    change = Note(620, owner(alice), tuple(range(401, 409)))
    ledger = Ledger(context, [original.commitment(context)])
    tx, witness = assignment(ledger, 0, original, alice, recipient, change, 5,
                             b"PUBLIC TEST MEMO; real delivery is exercised by acceptance")
    return ledger, tx, witness, recipient, change, alice, bob
