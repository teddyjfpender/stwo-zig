#!/usr/bin/env python3
"""Fetch and adapt authenticated PIEs for a pinned campaign sample."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request


PROGRAM = "crates/cairo-program-runner-lib/resources/compiled_programs/bootloaders/leaf_simple_bootloader_compiled.json"


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        followup = super().redirect_request(request, fp, code, msg, headers, new_url)
        if followup and urllib.parse.urlparse(new_url).netloc != urllib.parse.urlparse(request.full_url).netloc:
            followup.remove_header("Authorization")
        return followup


def digest(path: Path) -> str:
    hash_state = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            hash_state.update(block)
    return hash_state.hexdigest()


def check(path: Path, expected_sha: str, expected_bytes: int) -> bool:
    return path.is_file() and path.stat().st_size == expected_bytes and digest(path) == expected_sha


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--proving-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--api-origin", default="https://15-237-92-219.sslip.io")
    args = parser.parse_args()
    token = os.getenv("LOTP_API_KEY")
    args.output.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(SafeRedirect)
    receipt_rows = []
    for row in json.loads(args.manifest.read_text()):
        name = row["pie"]
        archive = args.output / (name + ".zip")
        adapted = args.output / (name + ".cpi")
        preimage = args.output / (name + ".preimage.json")
        downloaded = False
        adapted_now = False
        if not check(archive, row["archive_sha256"], row["archive_bytes"]):
            if not token:
                parser.error("LOTP_API_KEY is required to download missing archives")
            request = urllib.request.Request(
                args.api_origin.rstrip("/") + "/v1/pies/" + name,
                headers={"Authorization": "Bearer " + token},
            )
            temporary = archive.with_suffix(".partial")
            with opener.open(request, timeout=180) as source, temporary.open("wb") as output:
                while block := source.read(1 << 20):
                    output.write(block)
            if not check(temporary, row["archive_sha256"], row["archive_bytes"]):
                temporary.unlink(missing_ok=True)
                raise ValueError(f"{name}: downloaded archive differs from H200 receipt")
            temporary.replace(archive)
            downloaded = True
        if not (check(adapted, row["input_sha256"], row["input_bytes"]) and check(
            preimage, row["preimage_sha256"], row["preimage_bytes"]
        )):
            bootloader = args.output / (name + ".bootloader.json")
            bootloader.write_text(json.dumps({
                "tasks": [{"type": "CairoPiePath", "path": str(archive), "program_hash_function": "blake"}],
                "fact_topologies_path": None,
                "single_page": True,
                "output_preimage_dump_path": str(preimage),
            }))
            with (args.output / (name + ".adapt.log")).open("w") as log:
                subprocess.run([
                    str(args.oracle), "adapt-program", "--proving-root", str(args.proving_root),
                    "--program", PROGRAM, "--program-input", str(bootloader),
                    "--input-format", "compact", "--output", str(adapted),
                ], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
            adapted_now = True
        if not check(adapted, row["input_sha256"], row["input_bytes"]):
            raise ValueError(f"{name}: adapted CPI differs from H200 receipt")
        if not check(preimage, row["preimage_sha256"], row["preimage_bytes"]):
            raise ValueError(f"{name}: public preimage differs from H200 receipt")
        receipt_rows.append({
            "pie": name,
            "campaign_position": row["campaign_position"],
            "archive_sha256": row["archive_sha256"],
            "archive_bytes": archive.stat().st_size,
            "adapted_sha256": row["input_sha256"],
            "adapted_bytes": adapted.stat().st_size,
            "preimage_sha256": row["preimage_sha256"],
            "preimage_bytes": preimage.stat().st_size,
            "downloaded_this_run": downloaded,
            "adapted_this_run": adapted_now,
        })
        print(name, "adapted and authenticated" if adapted_now else "already authenticated", flush=True)
    if args.receipt:
        program = args.proving_root / PROGRAM
        proving_commit = subprocess.run(
            ["git", "-C", str(args.proving_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps({
            "schema": "stwo.cairo-cuda-campaign-sample-preparation.v1",
            "manifest_sha256": digest(args.manifest),
            "oracle_sha256": digest(args.oracle),
            "proving_commit": proving_commit,
            "program_sha256": digest(program),
            "pies": receipt_rows,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()
