#!/usr/bin/env python3
"""Build the legacy Rust CUDA qualifier against materialized authority."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from cuda_external_authority import AuthorityError, verify_projection


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tools/stwo-cuda-adapter-rs"
DEPENDENCIES = {
    ".authority/crates/stwo": "crates/stwo",
    ".authority/crates/backend-cuda": (
        "crates/backend-cuda"
    ),
    ".authority/crates/backend-cuda-kernels": (
        "crates/backend-cuda-kernels"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("test", "build", "run"))
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--adapter-root", type=Path, default=ADAPTER)
    parser.add_argument("--output", type=Path, required=True)
    args, adapter_args = parser.parse_known_args()
    authority = args.authority_root.resolve()
    adapter = args.adapter_root.resolve()
    if not (authority / "crates/backend-cuda/Cargo.toml").is_file():
        raise SystemExit("materialized CUDA host authority is incomplete")
    try:
        authority_receipt = verify_projection(authority)
    except AuthorityError as error:
        raise SystemExit(f"materialized CUDA host authority is invalid: {error}") from error
    if not (adapter / "Cargo.toml").is_file() or not (adapter / "Cargo.lock").is_file():
        raise SystemExit("CUDA adapter source closure is incomplete")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stwo-cuda-adapter-") as temporary:
        staging = Path(temporary) / "adapter"
        shutil.copytree(adapter, staging, ignore=shutil.ignore_patterns("target"))
        manifest_path = staging / "Cargo.toml"
        manifest = manifest_path.read_text(encoding="utf-8")
        for old, relative in sorted(
            DEPENDENCIES.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            replacement = (authority / relative).as_posix()
            if old not in manifest:
                raise SystemExit(f"CUDA adapter dependency pin is absent: {old}")
            manifest = manifest.replace(old, replacement)
        manifest_path.write_text(manifest, encoding="utf-8")
        environment = dict(os.environ)
        environment["CARGO_TARGET_DIR"] = str(args.output / "target")
        cargo_command = "run" if args.command == "run" else args.command
        command = [
            "cargo",
            "+nightly-2025-07-14",
            cargo_command,
            "--locked",
            "--manifest-path",
            str(manifest_path),
        ]
        if args.command in {"build", "run"}:
            command.append("--release")
        adapter_args = list(adapter_args)
        if adapter_args[:1] == ["--"]:
            adapter_args = adapter_args[1:]
        if args.command != "run" and adapter_args:
            raise SystemExit("adapter arguments are accepted only by the run command")
        if adapter_args:
            command.append("--")
            command.extend(adapter_args)
        completed = subprocess.run(command, env=environment, check=False)
        if completed.returncode != 0:
            return completed.returncode
    receipt = {
        "schema": "stwo-zig-cuda-external-adapter-receipt-v1",
        "command": args.command,
        "authority": authority_receipt,
    }
    (args.output / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
