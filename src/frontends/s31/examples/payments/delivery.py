"""Educational shared-invoice delivery using hashes only; not audited encryption.

Establish the 32-byte invoice key privately. This module cannot encrypt to a
public hash address. Fresh random nonces mask fixed-size note openings; HMAC
authenticates the entire ciphertext and its context/output commitment.
"""

from __future__ import annotations

import hmac
import secrets
import struct

from reference import Digest, Note, PaymentError, words

PREFIX = b"S31N\x01"
NONCE_BYTES = 24
PAYLOAD_BYTES = struct.calcsize("<Q16I")
BLOB_BYTES = len(PREFIX) + NONCE_BYTES + PAYLOAD_BYTES + 32
DOMAIN = b"s31-hash-payments/delivery/v1/"


def _keys(key: bytes) -> tuple[bytes, bytes]:
    if type(key) is not bytes or len(key) != 32:
        raise PaymentError("invoice key must contain 32 secret bytes")
    return (hmac.digest(key, DOMAIN + b"enc", "sha256"),
            hmac.digest(key, DOMAIN + b"mac", "sha256"))


def _associated(context: Digest, commitment: Digest) -> bytes:
    return struct.pack("<16I", *words(context), *words(commitment))


def _mask(payload: bytes, key: bytes, nonce: bytes) -> bytes:
    stream = b"".join(hmac.digest(key, DOMAIN + b"stream" + nonce + struct.pack("<I", i),
                                "sha256") for i in range((len(payload) + 31) // 32))
    return bytes(x ^ y for x, y in zip(payload, stream[:len(payload)], strict=True))


def seal_note(note: Note, key: bytes, context: Digest) -> bytes:
    enc, mac = _keys(key)
    nonce = secrets.token_bytes(NONCE_BYTES)
    payload = struct.pack("<Q16I", note.value, *note.owner, *note.salt)
    body = PREFIX + nonce + _mask(payload, enc, nonce)
    tag = hmac.digest(mac, DOMAIN + b"tag" + _associated(context, note.commitment(context)) + body,
                      "sha256")
    return body + tag


def open_note(blob: bytes, key: bytes, context: Digest, commitment: Digest) -> Note:
    enc, mac = _keys(key)
    if type(blob) is not bytes or len(blob) != BLOB_BYTES or not blob.startswith(PREFIX):
        raise PaymentError("invalid delivery format")
    body, tag = blob[:-32], blob[-32:]
    expected = hmac.digest(mac, DOMAIN + b"tag" + _associated(context, commitment) + body, "sha256")
    if not hmac.compare_digest(tag, expected):
        raise PaymentError("delivery authentication failed")
    nonce = body[len(PREFIX):len(PREFIX) + NONCE_BYTES]
    payload = _mask(body[len(PREFIX) + NONCE_BYTES:], enc, nonce)
    value, *decoded = struct.unpack("<Q16I", payload)
    note = Note(value, tuple(decoded[:8]), tuple(decoded[8:]))
    if note.commitment(context) != commitment:
        raise PaymentError("delivered opening does not match output commitment")
    return note
