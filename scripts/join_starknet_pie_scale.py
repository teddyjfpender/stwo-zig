#!/usr/bin/env python3
"""Join the full PIE catalogue with measured adaptation and proving receipts."""

import argparse
import csv
from pathlib import Path


ADAPT = {
    "status": "adapt_status", "adapt_wall_s": "adapt_wall_s",
    "adapt_peak_rss_bytes": "adapt_peak_rss_bytes", "cpi_bytes": "cpi_bytes",
    "cpi_sha256": "cpi_sha256", "error": "adapt_error",
}
PROOF = {
    "status": "proof_status", "ingress_s": "proof_ingress_s",
    "proof_execute_finish_s": "proof_execute_finish_s",
    "adapted_to_publication_s": "proof_publication_s",
    "fixed_initial_upload_s": "proof_fixed_initial_upload_s",
    "fixed_preprocessed_load_s": "proof_fixed_preprocessed_load_s",
    "fixed_materialize_s": "proof_fixed_materialize_s",
    "ingress_other_s": "proof_ingress_other_s",
    "ingress_preparation_other_s": "proof_ingress_preparation_other_s",
    "publication_other_s": "proof_publication_other_s",
    "process_overhead_s": "proof_process_overhead_s",
    "rust_verify_s": "proof_rust_verify_s",
    "rust_verify_inner_s": "proof_rust_verify_inner_s",
    "rust_verify_peak_rss_bytes": "proof_rust_verify_peak_rss_bytes",
    **{f"ingress_{phase}_s": f"proof_ingress_{phase}_s" for phase in (
        "paths", "runtime", "source", "controllers", "twiddles", "allocation",
        "binding", "static", "writers", "statement_and_session")},
    "process_wall_s": "proof_process_wall_s", "host_peak_rss_bytes": "proof_host_peak_rss_bytes",
    "gpu_peak_used_bytes": "proof_gpu_peak_used_bytes",
    "planned_arena_bytes": "proof_planned_arena_bytes",
    "peak_live_bytes": "proof_peak_live_bytes", "proof_bytes": "proof_bytes",
    "proof_sha256": "proof_sha256", "error": "proof_error",
}


def keyed(paths: list[Path] | None) -> dict[str, dict]:
    result = {}
    for path in paths or []:
        with path.open(newline="") as source:
            rows = list(csv.DictReader(source))
        for row in rows:
            name = row["pie"]
            if name in result:
                raise ValueError(f"duplicate PIE name {name} in {path}")
            row["_receipt_file"] = path.name
            result[name] = row
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--adaptation", type=Path, action="append")
    parser.add_argument("--proving", type=Path, action="append")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.catalog.open(newline="") as source:
        reader = csv.DictReader(source)
        catalog_fields = reader.fieldnames
        catalog = list(reader)
    if catalog_fields is None or len({row["pie"] for row in catalog}) != len(catalog):
        raise ValueError("catalogue has no header or duplicate PIE names")
    adaptation, proving = keyed(args.adaptation), keyed(args.proving)
    names = {row["pie"] for row in catalog}
    if set(adaptation) - names or set(proving) - names:
        raise ValueError("measurement names are absent from the catalogue")
    fields = catalog_fields + ["adapt_receipt_file"] + list(ADAPT.values()) + ["proof_receipt_file"] + list(PROOF.values())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in catalog:
            name = row["pie"]
            row["adapt_receipt_file"] = adaptation.get(name, {}).get("_receipt_file", "")
            row.update({target: adaptation.get(name, {}).get(source, "")
                        for source, target in ADAPT.items()})
            row["proof_receipt_file"] = proving.get(name, {}).get("_receipt_file", "")
            row.update({target: proving.get(name, {}).get(source, "")
                        for source, target in PROOF.items()})
            writer.writerow(row)
    print(f"joined {len(catalog)} PIEs; {len(adaptation)} adaptations; {len(proving)} proof trials")


if __name__ == "__main__":
    main()
