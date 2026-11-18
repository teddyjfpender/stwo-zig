"""Export Solidity FRI witnesses from a successful native receiver capture."""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


P = (1 << 31) - 1
RECORD = re.compile(r"^FRI_BEGIN ([a-f0-9]{64}) (\d+) (\d+)\nFRI_DEEP ([a-f0-9]*)\n"
                    r"((?:FRI_LAYER [a-f0-9]{64} \d+\nFRI_ROWS [a-f0-9]*\n"
                    r"FRI_SIBLINGS [a-f0-9]*\n)+)FRI_END$", re.MULTILINE)
LAYER = re.compile(r"FRI_LAYER ([a-f0-9]{64}) (\d+)\nFRI_ROWS ([a-f0-9]*)\nFRI_SIBLINGS ([a-f0-9]*)\n")


def blake(*parts):
    return hashlib.blake2s(b"".join(parts)).digest()


def unhex(value):
    return bytes.fromhex(value.removeprefix("0x"))


def ashex(value):
    return "0x" + value.hex()


def raw_positions(pre_pow, nonce, log):
    encoded_nonce = struct.pack("<Q", nonce)
    pow_prefix = blake(struct.pack("<I12x32sI", 0x12345678, pre_pow, 20))
    if struct.unpack_from("<I", blake(pow_prefix, encoded_nonce))[0] & ((1 << 20) - 1):
        raise ValueError("invalid native PoW")
    mixed = blake(pre_pow, encoded_nonce)
    words = [word for counter in range(14)
             for word in struct.unpack("<8I", blake(mixed, struct.pack("<IB", counter, 0)))]
    return [word & ((1 << log) - 1) for word in words[:108]]


def inverse_coordinate(position, log, circle):
    index = int(f"{position:0{log}b}"[::-1], 2)
    exponent = (1 + 4 * index) << ((30 if circle else 29) - log)
    x, y, a, b = 1, 0, 2, 1268011823
    while exponent:
        if exponent & 1:
            x, y = (x * a - y * b) % P, (x * b + y * a) % P
        a, b = (a * a - b * b) % P, 2 * a * b % P
        exponent >>= 1
    return pow(y if circle else x, -1, P)


def canonical_words(data):
    if len(data) % 32 or any(word >= P for (word,) in struct.iter_unpack("<I", data)):
        raise ValueError("malformed OM31 values")


def opening_root(leaves, siblings, depth):
    pending = {index: blake(b"leaf".ljust(64, b"\0"), value) for index, value in leaves.items()}
    remaining = iter(siblings)
    for _ in range(depth):
        parents = {}
        for index, value in pending.items():
            parent = index >> 1
            if parent in parents:
                continue
            sibling = pending.get(index ^ 1)
            if sibling is None:
                sibling = next(remaining, None)
                if sibling is None:
                    raise ValueError("missing Merkle sibling")
            left, right = (sibling, value) if index & 1 else (value, sibling)
            parents[parent] = blake(b"node".ljust(64, b"\0"), left, right)
        pending = parents
    if list(pending) != [0] or next(remaining, None) is not None:
        raise ValueError("surplus Merkle leaves or siblings")
    return pending[0]


def export_record(record, pcs, query):
    pre_pow_hex, log, nonce, deep_hex, layer_lines = record
    log, nonce = int(log), int(nonce)
    if not 5 <= log <= 30 or (log, nonce) != (pcs["domainLog"], int(query["nonce"])):
        raise ValueError("native query metadata mismatch")
    roots = [unhex(root) for root in pcs["friRoots"]]
    digest = blake(unhex(pcs["prefix"]), unhex(pcs["samples"]))
    for root in roots:
        digest = blake(digest, root)
    pre_pow = blake(digest, unhex(pcs["lastCoefficient"]))
    if pre_pow.hex() != pre_pow_hex or ashex(pre_pow) != pcs["prePowDigest"]:
        raise ValueError("native transcript mismatch")
    raw = raw_positions(pre_pow, nonce, log)
    unique = sorted(set(raw))
    deep = bytes.fromhex(deep_hex)
    canonical_words(deep)
    if len(deep) != 32 * len(unique):
        raise ValueError("unexpected DEEP value count")
    deep_values = [deep[i:i + 32] for i in range(0, len(deep), 32)]
    layers = []
    captured = LAYER.findall(layer_lines)
    if len(captured) != len(roots):
        raise ValueError("unexpected FRI layer count")
    for i, ((root_hex, step, raw_rows_hex, siblings_hex), root) in enumerate(zip(captured, roots)):
        step = int(step)
        if step != min(4, log - 1) or bytes.fromhex(root_hex) != root:
            raise ValueError("FRI layer metadata mismatch")
        width = 1 << step
        row_bytes = width * 32
        raw_rows = bytes.fromhex(raw_rows_hex)
        canonical_words(raw_rows)
        if len(raw_rows) != len(raw) * row_bytes:
            raise ValueError("unexpected FRI subgroup count")
        groups = {}
        for j, position in enumerate(raw):
            group = position >> step
            row = raw_rows[j * row_bytes:(j + 1) * row_bytes]
            if groups.setdefault(group, row) != row:
                raise ValueError("inconsistent repeated FRI subgroup")
        if i == 0:
            for position, value in zip(unique, deep_values):
                at = (position & (width - 1)) * 32
                if groups[position >> step][at:at + 32] != value:
                    raise ValueError("FRI input does not match captured DEEP value")
        leaf_log = 2 if step > 1 else 0
        leaf_bytes = 32 << leaf_log
        leaves = {}
        inverses = []
        for group, row in sorted(groups.items()):
            for j in range(0, row_bytes, leaf_bytes):
                leaves[(group << (step - leaf_log)) + j // leaf_bytes] = row[j:j + leaf_bytes]
            for round_index in range(step):
                fold_width = width >> round_index
                for offset in range(0, fold_width, 2):
                    inverses.append(inverse_coordinate(group * fold_width + offset, log - round_index,
                                                       i == 0 and round_index == 0))
        witness = bytes.fromhex(siblings_hex)
        if len(witness) % 32:
            raise ValueError("malformed Merkle witness")
        siblings = [witness[j:j + 32] for j in range(0, len(witness), 32)]
        if opening_root(leaves, siblings, log - leaf_log) != root:
            raise ValueError("FRI Merkle witness does not authenticate captured rows")
        layers.append({"rows": ashex(b"".join(leaves.values())), "siblings": list(map(ashex, siblings)),
                       "inverses": inverses})
        raw = [position >> step for position in raw]
        log -= step
    if log != 1:
        raise ValueError("FRI schedule did not reach its terminal domain")
    return {"worker": pcs["worker"], "workerSha256": pcs["workerSha256"],
            "deepValues": list(map(ashex, deep_values)), "layers": layers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("diagnostics", "receipt", "queries", "pcs", "output"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    if not receipt["accepted"] or not receipt["completed_ethereum_block"]:
        raise ValueError("capture requires accepted complete native reception")
    pcs = json.loads(args.pcs.read_text())
    query = json.loads(args.queries.read_text())[pcs["worker"]]
    if (pcs["workerSha256"], pcs["prePowDigest"], pcs["domainLog"]) != (
            query["workerSha256"], query["prePowDigest"], query["domainLog"]):
        raise ValueError("PCS and query fixtures disagree")
    records = [record for record in RECORD.findall(args.diagnostics.read_text())
               if ashex(bytes.fromhex(record[0])) == query["prePowDigest"]]
    if len(records) != 1:
        raise ValueError(f"expected one intact matching capture, found {len(records)}")
    args.output.write_text(json.dumps(export_record(records[0], pcs, query), indent=2) + "\n")


if __name__ == "__main__":
    main()
