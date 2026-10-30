#!/usr/bin/env python3
"""Count OODS values in an already verified B7UF postcard (not a verifier).

The family map is the finite 15-tree B7UF protocol. This deliberately rejects
other tree counts; it does not infer a statement or accept proof authority.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

ROLES = (
    "all fixed", "native main", "native access", "caller main", "caller access",
    "program main", "lookup main", "RAM main", "native interaction",
    "caller arithmetic interaction", "caller relation interaction",
    "program interaction", "lookup interaction", "RAM interaction", "composition",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.proof.stat().st_size > 64 << 20:
        parser.error("proof exceeds this diagnostic's 64 MiB limit")
    raw = args.proof.read_bytes()
    pos = 0

    def uint():
        nonlocal pos
        value = 0
        for shift in range(0, 70, 7):
            if pos >= len(raw):
                raise ValueError("truncated postcard prefix")
            byte = raw[pos]
            pos += 1
            if shift == 63 and byte > 1:
                raise ValueError("overflowing varint")
            value |= (byte & 127) << shift
            if byte < 128:
                if shift and byte == 0:
                    raise ValueError("noncanonical varint")
                return value
        raise ValueError("overflowing varint")

    config = [uint() for _ in range(5)]
    tag = uint()
    if tag not in (0, 1):
        raise ValueError("invalid lifting option")
    lifting = uint() if tag else None
    if uint() != len(ROLES):
        raise ValueError("expected the B7UF 15-tree protocol")
    pos += 32 * len(ROLES)
    if uint() != len(ROLES):
        raise ValueError("unexpected sampled tree count")
    rows = []
    for tree, role in enumerate(ROLES):
        columns = uint()
        if columns > 1 << 20:
            raise ValueError("column count exceeds diagnostic limit")
        samples = 0
        for _ in range(columns):
            width = uint()
            if width > 16:
                raise ValueError("sample width exceeds diagnostic limit")
            samples += width
            for _ in range(width * 4):
                if uint() >= 0x7fffffff:
                    raise ValueError("noncanonical field limb")
        rows.append((tree, role, columns, samples))
    with args.output.open("w", newline="") as output:
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        writer.writerow(("tree", "family", "columns", "oods_qm31_values"))
        writer.writerows(rows)
    total = sum(row[3] for row in rows)
    caller = sum(rows[tree][3] for tree in (3, 4, 9, 10))
    print(json.dumps({"proof_sha256": hashlib.sha256(raw).hexdigest(),
                      "pcs_config_fields": config, "lifting": lifting,
                      "oods_values": total, "caller_oods_values": caller,
                      "caller_share": caller / total if total else None,
                      "proof_verification_performed": False}))


if __name__ == "__main__":
    main()
