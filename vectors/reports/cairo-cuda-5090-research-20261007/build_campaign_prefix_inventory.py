#!/usr/bin/env python3
"""Pin the exact ordered 64/128/512 prefixes of a saved proving-service run."""

import argparse
import csv
import json
from pathlib import Path


def read_csv(path: Path, key: str) -> dict[str, dict[str, str]]:
    with path.open(newline="") as source:
        return {row[key]: row for row in csv.DictReader(source)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True,
                        help="directory containing preparation.json, metadata and saved 128/512 receipts")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    base = args.campaign_dir
    with (base / "h200-api-512-001" / "pie_analysis.csv").open(newline="") as source:
        analysis = list(csv.DictReader(source))
    with (base / "h200-api-128-001" / "pie_analysis.csv").open(newline="") as source:
        first_128 = list(csv.DictReader(source))
    prepared = {row["name"]: row for row in json.loads((base / "preparation.json").read_text())}
    metadata = read_csv(base / "pie_metadata.csv", "pie")
    assert len(analysis) == 512 and len(first_128) == 128
    assert [row["pie_name"] for row in analysis[:128]] == [row["pie_name"] for row in first_128]
    rows = []
    for position, row in enumerate(analysis, 1):
        name = row["pie_name"]
        prep = prepared[name]
        meta = metadata[name]
        if position > 1:
            assert int(rows[-1]["last_block"]) + 1 == int(row["first_block"])
        assert int(row["steps"]) == int(meta["os_steps"])
        assert row["archive_sha256"] == prep["archive_sha256"]
        assert int(row["adapted_bytes"]) == int(prep["adapted_bytes"])
        rows.append({
            "position": position,
            "pie": name,
            "first_block": row["first_block"],
            "last_block": row["last_block"],
            "blocks": meta["n_blocks"],
            "transactions": meta["txs"],
            "steps": row["steps"],
            "ec_ops": meta["builtin_ec_op"],
            "pedersen_ops": meta["builtin_pedersen"],
            "keccak_ops": meta["builtin_keccak"],
            "archive_sha256": prep["archive_sha256"],
            "adapted_sha256": prep["adapted_sha256"],
            "adapted_bytes": prep["adapted_bytes"],
            "preimage_sha256": prep["preimage_sha256"],
            "preimage_bytes": prep["preimage_bytes"],
        })
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "h200-campaign-prefix-inventory.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    targets = {}
    for count in (64, 128, 512):
        subset = rows[:count]
        reference = None
        if count in (128, 512):
            name = f"h200-api-{count}-001"
            summary = json.loads((base / name / "summary.json").read_text())
            receipt = json.loads((base / name / "receipt.json").read_text())
            assert receipt["leaf_count"] == count
            reference = {
                "attempt": name,
                "root_proof_sha256": summary["root_proof_sha256"],
                "final_root": receipt["final_root"],
                "accepted_to_publication_wall_s": summary["accepted_to_publication_wall_s"],
            }
        targets[str(count)] = {
            "first_pie": subset[0]["pie"],
            "last_pie": subset[-1]["pie"],
            "first_block": int(subset[0]["first_block"]),
            "last_block": int(subset[-1]["last_block"]),
            "total_steps": sum(int(item["steps"]) for item in subset),
            "total_adapted_bytes": sum(int(item["adapted_bytes"]) for item in subset),
            "reference": reference,
        }
    (args.out / "h200-campaign-prefix-targets.json").write_text(
        json.dumps(targets, indent=2, sort_keys=True) + "\n")
    for count, target in targets.items():
        print(count, target["first_pie"], target["last_pie"], target["total_steps"])


if __name__ == "__main__":
    main()
