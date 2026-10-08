#!/usr/bin/env python3
"""Pin a broader, position-stratified subset of the exact H200 512-PIE run."""

import argparse
import csv
import json
from pathlib import Path


# The original 15 over-sampled expensive EC/Pedersen cases. These additions
# provide coverage throughout the 64/128 prefixes and later 512 campaign.
ADDITIONAL_POSITIONS = (2, 8, 16, 24, 32, 40, 48, 56, 64,
                        72, 88, 104, 120, 128, 192, 320, 448, 480)


def read_csv(path: Path, key: str) -> dict:
    with path.open(newline="") as source:
        return {row[key]: row for row in csv.DictReader(source)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--h200-dir", type=Path, required=True)
    args = parser.parse_args()
    inventory_path = args.report_dir / "h200-campaign-prefix-inventory.csv"
    with inventory_path.open(newline="") as source:
        inventory = list(csv.DictReader(source))
    if len(inventory) != 512 or [int(row["position"]) for row in inventory] != list(range(1, 513)):
        raise ValueError("expected the exact, ordered 512-PIE inventory")
    baseline = json.loads((args.report_dir / "h200-512-stratified-sample.json").read_text())
    by_name = {row["pie"]: row for row in baseline}
    archive_bytes = read_csv(args.h200_dir / "archive_sizes.csv", "pie_name")
    analysis = read_csv(args.h200_dir / "h200-api-512-001/pie_analysis.csv", "pie_name")
    for position in ADDITIONAL_POSITIONS:
        row = inventory[position - 1]
        name = row["pie"]
        if name in by_name:
            raise ValueError(f"additional position duplicates original sample: {position}")
        source = analysis[name]
        # The service leaf input includes its request envelope, so its digest
        # is distinct from the adapted CPI object recorded by preparation.
        if row["archive_sha256"] != source["archive_sha256"]:
            raise ValueError(f"source receipts differ for {name}")
        by_name[name] = {
            "pie": name,
            "campaign_position": position,
            "steps": int(row["steps"]),
            "blocks": int(row["blocks"]),
            "transactions": int(row["transactions"]),
            "ec_ops": int(row["ec_ops"]),
            "pedersen_ops": int(row["pedersen_ops"]),
            "keccak_ops": int(row["keccak_ops"] or 0),
            "archive_sha256": row["archive_sha256"],
            "archive_bytes": int(archive_bytes[name]["archive_bytes"]),
            "input_sha256": row["adapted_sha256"],
            "input_bytes": int(row["adapted_bytes"]),
            "preimage_sha256": row["preimage_sha256"],
            "preimage_bytes": int(row["preimage_bytes"]),
            "h200_ingress_s": float(source["ingress_s"]),
            "h200_cairo_prove_s": float(source["cairo_prove_s"]),
            "h200_wrap_s": float(source["circuit_wrap_s"]),
            "h200_source": "proving-service/h200-api-512-001",
        }
    position_by_name = {row["pie"]: int(row["position"]) for row in inventory}
    result = sorted(by_name.values(), key=lambda row: position_by_name[row["pie"]])
    for row in result:
        source = inventory[position_by_name[row["pie"]] - 1]
        row["campaign_position"] = position_by_name[row["pie"]]
        row["preimage_sha256"] = source["preimage_sha256"]
        row["preimage_bytes"] = int(source["preimage_bytes"])
    if len(result) != 33 or len({row["pie"] for row in result}) != 33:
        raise ValueError("expected 33 unique sample PIEs")
    output = args.report_dir / "h200-512-extended-sample.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(result)} PIEs; {sum(row['campaign_position'] <= 64 for row in result)} first64; "
          f"{sum(row['campaign_position'] <= 128 for row in result)} first128; "
          f"{sum(row['steps'] for row in result):,} steps; {sum(row['input_bytes'] for row in result):,} CPI bytes")


if __name__ == "__main__":
    main()
