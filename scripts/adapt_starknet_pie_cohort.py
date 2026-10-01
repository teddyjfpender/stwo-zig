#!/usr/bin/env python3
"""Adapt downloaded Starknet OS PIEs into canonical compact Cairo inputs.

The Rust oracle runs the pinned leaf bootloader. This is a separate timing
stage from GPU proving; its memory and wall time must never be called proof
generation. Output artifacts and logs belong outside the repository.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time


LEAF_PROGRAM = "crates/cairo-program-runner-lib/resources/compiled_programs/bootloaders/leaf_simple_bootloader_compiled.json"
RSS_MAC = re.compile(r"(\d+)\s+maximum resident set size")
RSS_LINUX = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")
FIELDS = ("pie", "os_steps", "archive_bytes", "archive_sha256", "status", "adapt_wall_s",
          "adapt_peak_rss_bytes", "cpi_bytes", "cpi_sha256", "error")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--proving-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text())
    prior = {}
    csv_path = args.out / "adaptation.csv"
    if csv_path.exists():
        with csv_path.open(newline="") as source:
            prior = {row["pie"]: row for row in csv.DictReader(source)}
    rows = []
    for item in manifest["rows"]:
        name, meta = item["pie"], item["meta"]
        archive = Path(item["zip"]["path"])
        if args.max_steps and meta["os_steps"] > args.max_steps:
            continue
        adapted = args.out / f"{name}.cpi"
        if name in prior and prior[name]["status"] == "adapted" and adapted.is_file() \
                and sha(adapted) == prior[name]["cpi_sha256"]:
            rows.append(prior[name])
            continue
        row = {"pie": name, "os_steps": meta["os_steps"],
               "archive_bytes": archive.stat().st_size,
               "archive_sha256": item["zip"]["sha256"], "status": "failed"}
        if sha(archive) != row["archive_sha256"]:
            raise ValueError(f"archive digest mismatch: {archive}")
        preimage = args.out / f"{name}.preimage.hex.json"
        request = args.out / f"{name}.bootloader_input.json"
        request.write_text(json.dumps({
            "tasks": [{"type": "CairoPiePath", "path": str(archive), "program_hash_function": "blake"}],
            "fact_topologies_path": None, "single_page": True,
            "output_preimage_dump_path": str(preimage),
        }, indent=2) + "\n")
        command = [str(args.oracle), "adapt-program", "--proving-root", str(args.proving_root),
                   "--program", LEAF_PROGRAM, "--program-input", str(request),
                   "--input-format", "compact", "--output", str(adapted)]
        flags = ["-l"] if sys.platform == "darwin" else ["-v"]
        started = time.perf_counter()
        try:
            with (args.out / f"{name}.adapt.log").open("w") as log:
                result = subprocess.run(["/usr/bin/time", *flags, *command], stdout=log,
                                        stderr=subprocess.STDOUT, timeout=args.timeout)
            row["adapt_wall_s"] = round(time.perf_counter() - started, 3)
            content = (args.out / f"{name}.adapt.log").read_text(errors="replace")
            mac = RSS_MAC.search(content)
            linux = RSS_LINUX.search(content)
            row["adapt_peak_rss_bytes"] = (int(mac.group(1)) if mac else
                                            int(linux.group(1)) * 1024 if linux else None)
            if result.returncode != 0 or not adapted.is_file():
                row["error"] = content[-500:]
            else:
                row.update(status="adapted", cpi_bytes=adapted.stat().st_size,
                           cpi_sha256=sha(adapted))
        except subprocess.TimeoutExpired:
            row["adapt_wall_s"] = round(time.perf_counter() - started, 3)
            row["error"] = "adaptation timed out"
        rows.append(row)
        write_rows(csv_path, rows)
        print(f"{name}: {row['status']} in {row.get('adapt_wall_s')} s, "
              f"CPI {row.get('cpi_bytes', 0)} bytes", flush=True)
    write_rows(csv_path, rows)


if __name__ == "__main__":
    main()
