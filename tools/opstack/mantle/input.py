"""Bounded, input-bound Mantle execution statement; no execution/proof authority."""

import hashlib
import json
from pathlib import Path
from opstack import transition_capture as C

MAX_INPUT = (16 << 20) - 4


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate Mantle JSON key")
        out[key] = value
    return out


def read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    return raw, statement(raw)


def _nonfinite(_):
    raise ValueError("nonfinite Mantle JSON")


def statement(raw):
    if len(raw) > MAX_INPUT:
        raise ValueError("Mantle guest input limit")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_nonfinite)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("Mantle JSON") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "fixture", "expected", "preimages"}
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        raise ValueError("Mantle input schema")
    fixture, expected = value["fixture"], value["expected"]
    if not isinstance(fixture, dict) or not isinstance(expected, dict):
        raise ValueError("Mantle input objects")
    if set(fixture) != {
        "rollup_config",
        "parent_header",
        "payload",
        "expected_parent_hash",
    } or set(expected) != {"config_sha256", "block_hash"}:
        raise ValueError("Mantle input fields")
    config = fixture["rollup_config"]
    parent = fixture["parent_header"]
    payload = fixture["payload"]
    if not all(isinstance(item, dict) for item in (config, parent, payload)):
        raise ValueError("Mantle execution objects")
    if any(
        type(config.get(key)) is not int or config[key] != pin
        for key, pin in (("l2_chain_id", 5000), ("l1_chain_id", 1), ("block_time", 2))
    ):
        raise ValueError("Mantle network")
    for name, pin in [
        ("mantle_skadi_time", 1756278000),
        ("mantle_limb_time", 1768374000),
        ("mantle_arsia_time", 1776841200),
    ]:
        if config.get(name) != pin:
            raise ValueError("Mantle fork schedule")
    canonical = json.dumps(
        config,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    if hashlib.sha256(canonical).digest() != C.unhex(expected["config_sha256"], 32):
        raise ValueError("Mantle config pin")
    header = C.header_rlp(parent)
    if C.keccak(header) != C.unhex(fixture["expected_parent_hash"], 32):
        raise ValueError("Mantle parent pin")
    timestamp = int.from_bytes(C.quantity(payload["timestamp"]), "big")
    if (
        timestamp != int.from_bytes(C.quantity(parent["timestamp"]), "big") + 2
        or timestamp < 1776841200
    ):
        raise ValueError("Mantle block adjacency")
    if int.from_bytes(C.quantity(parent["number"]), "big") >= (1 << 64) - 1:
        raise ValueError("Mantle block number")
    transactions = payload["transactions"]
    if (
        not isinstance(transactions, list)
        or not 1 <= len(transactions) <= 16384
        or sum(len(C.unhex(tx)) for tx in transactions) > 16 << 20
    ):
        raise ValueError("Mantle transaction bounds")
    records = value["preimages"]
    seen = set()
    total = 0
    if not isinstance(records, list) or len(records) > 131072:
        raise ValueError("Mantle preimage count")
    for record in records:
        if not isinstance(record, dict) or set(record) != {"hash", "data"}:
            raise ValueError("Mantle preimage fields")
        key = C.unhex(record["hash"], 32)
        data = C.unhex(record["data"])
        total += len(data)
        if key in seen or C.keccak(data) != key or total > 64 << 20:
            raise ValueError("Mantle preimage identity")
        seen.add(key)
    digest = hashlib.sha256(
        b"stwo/mantle/execution/v1\0"
        + hashlib.sha256(raw).digest()
        + C.unhex(expected["block_hash"], 32)
    ).digest()
    return digest + b"\x01" + (5000).to_bytes(8, "little") + b"ME"
