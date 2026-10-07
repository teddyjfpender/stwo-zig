#!/usr/bin/env python3
"""Check completeness of the blocking V6 fixed-key source inventory.

This checks the inventory, not AIR soundness. A successful run never admits a
proof or a key; `--require-admitted` deliberately fails until a separate proof
qualification replaces this planning artifact.
"""

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "design/riscv-proving-stack/fixed-key-v6-audit.tsv"
FIELDS = (
    "row",
    "component",
    "classification",
    "preprocessed_surface",
    "v6_owner_or_move",
    "proof_obligation",
)
KNOWN_VALUE_MOVES = {5, 42}
CLASSIFICATIONS = {"template_rebuild", "move_leaf_values", "fixed", "inert"}


def check_inventory() -> list[dict[str, str]]:
    with AUDIT.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("V6 audit schema changed")
        rows = list(reader)
    if len(rows) != 50:
        raise ValueError(f"V6 audit must cover all 50 rows, found {len(rows)}")
    for index, row in enumerate(rows):
        if row["row"] != str(index):
            raise ValueError(f"missing, duplicated, or reordered row {index}")
        if row["classification"] not in CLASSIFICATIONS:
            raise ValueError(f"unknown classification at row {index}")
        if any(not row[field].strip() for field in FIELDS):
            raise ValueError(f"incomplete inventory at row {index}")
        if row["classification"] == "fixed" and index != 35:
            raise ValueError(f"unexpected fixed-key clearance at row {index}")
    for index in KNOWN_VALUE_MOVES:
        if rows[index]["classification"] != "move_leaf_values":
            raise ValueError(f"known leaf-dependent row {index} lost its move gate")
    if rows[4]["classification"] != "template_rebuild":
        raise ValueError("row 4 must retain its independently rebuilt fixed schedule")
    if rows[34]["component"] != "poseidon2" or rows[49]["component"] != "local_receipt_hash":
        raise ValueError("V6 roster boundary changed")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-admitted", action="store_true")
    args = parser.parse_args()
    rows = check_inventory()
    if args.require_admitted:
        pending = [int(row["row"]) for row in rows if row["classification"] != "fixed"]
        raise SystemExit(f"V6 fixed-key admission blocked; {len(pending)} rows require proof: {pending}")
    print("V6 fixed-key audit: 50 rows covered; key admission remains blocked")


if __name__ == "__main__":
    main()
