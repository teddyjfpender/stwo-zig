#!/usr/bin/env python3
"""Compile official Stwo-Cairo AIR through an authenticated Stwo source overlay."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(__file__).resolve().parent
OVERLAY = ROOT / "target" / "cairo-air-official-stwo"
RECEIPT = OVERLAY / ".stwo-zig-air-overlay.json"
OFFICIAL_REVISION = "7b211edde786775016ef3eecb837a6240d8fe792"
OFFICIAL_TREE = "8ee4fc2b8c8a819e85308c494e7114ab7ab4936b"
COMPONENT = Path("crates/constraint-framework/src/component.rs")
ACCESSOR_NEEDLE = """\
        Self { eval, trace_locations, info, preprocessed_column_indices, claimed_sum }
    }

    pub fn trace_locations(&self) -> &[TreeSubspan] {
"""
ACCESSOR_REPLACEMENT = """\
        Self { eval, trace_locations, info, preprocessed_column_indices, claimed_sum }
    }

    /// Returns the evaluator for backend-neutral AIR recording.
    pub fn evaluator(&self) -> &E {
        &self.eval
    }

    pub fn trace_locations(&self) -> &[TreeSubspan] {
"""


def run(command: list[str], cwd: Path, *, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def source_identity(source: Path) -> dict[str, str]:
    revision = run(["git", "rev-parse", "HEAD"], source, capture=True)
    tree = run(["git", "rev-parse", "HEAD^{tree}"], source, capture=True)
    if revision != OFFICIAL_REVISION or tree != OFFICIAL_TREE:
        raise ValueError(
            f"official Stwo source is {revision}/{tree}, "
            f"expected {OFFICIAL_REVISION}/{OFFICIAL_TREE}"
        )
    subprocess.run(
        ["git", "diff-index", "--quiet", "HEAD", "--"],
        cwd=source,
        check=True,
    )
    return {"revision": revision, "tree": tree}


def patch_identity() -> dict[str, str]:
    patch = {
        "path": COMPONENT.as_posix(),
        "before_sha256": hashlib.sha256(ACCESSOR_NEEDLE.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(ACCESSOR_REPLACEMENT.encode()).hexdigest(),
    }
    canonical = json.dumps(patch, sort_keys=True, separators=(",", ":")).encode()
    patch["sha256"] = hashlib.sha256(canonical).hexdigest()
    return patch


def wanted_receipt(source: Path) -> dict[str, object]:
    return {
        "schema": "stwo-zig-official-air-overlay-v1",
        "source": source_identity(source),
        "patch": patch_identity(),
    }


def current_receipt() -> dict[str, object] | None:
    try:
        return json.loads(RECEIPT.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def create_overlay(source: Path, receipt: dict[str, object]) -> None:
    if OVERLAY.exists():
        shutil.rmtree(OVERLAY)
    archive = subprocess.run(
        ["git", "archive", "--format=tar", OFFICIAL_REVISION],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    OVERLAY.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(OVERLAY, filter="data")
    path = OVERLAY / COMPONENT
    source_text = path.read_text()
    if source_text.count(ACCESSOR_NEEDLE) != 1:
        raise ValueError("official FrameworkComponent accessor patch context drifted")
    path.write_text(source_text.replace(ACCESSOR_NEEDLE, ACCESSOR_REPLACEMENT, 1))
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def ensure_overlay(source: Path) -> dict[str, object]:
    receipt = wanted_receipt(source)
    component = OVERLAY / COMPONENT
    if current_receipt() != receipt or not component.is_file():
        create_overlay(source, receipt)
    if ACCESSOR_REPLACEMENT not in component.read_text():
        raise ValueError("cached official Stwo AIR overlay is not patched as recorded")
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stwo-source", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    receipt = ensure_overlay(args.stwo_source.resolve())
    if args.output.exists():
        raise FileExistsError(f"refusing to replace {args.output}")
    run(
        [
            "cargo",
            "+nightly-2026-01-15",
            "run",
            "--locked",
            "--manifest-path",
            str(TOOL / "Cargo.toml"),
            "--",
            str(args.proof.resolve()),
            str(args.output.resolve()),
        ],
        TOOL,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
