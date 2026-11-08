#!/usr/bin/env python3
"""Materialize and authenticate the audit-only upstream CUDA workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA_ROOT = ROOT / "src/backends/cuda"
DEFAULT_OUTPUT = CUDA_ROOT / "vendor/host_authority"
HOST_MANIFEST = CUDA_ROOT / "host_source_manifest.json"
KERNEL_MANIFEST = CUDA_ROOT / "source_manifest.json"
HOST_MANIFEST_SHA256 = (
    "0454c14abb003ad57ec17c68fb0e2d5b5d3359c6f680ae4a64743a8bf02b4017"
)
KERNEL_MANIFEST_SHA256 = (
    "6badbe13d6b040cd823ee8fd74da753d8f5354d7924fba7a51512c28262139b4"
)
REPOSITORY = "https://github.com/teddyjfpender/stwo"
COMMIT = "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035"
REPOSITORY_TREE = "55cbec6c408dfc4e81c722deca9f5526d3785536"
KERNEL_SUBTREE = Path("crates/backend-cuda-kernels/cuda")
HOST_PIN = {
    "authority": "host",
    "file_count": 1003,
    "byte_count": 44877364,
    "closure_sha256": "8592124d6ad17610e23171fa7160030f8f76e21f4deff35e76699de8ad515341",
    "upstream": {
        "repository": REPOSITORY,
        "branch": "perf-optimizations",
        "commit": COMMIT,
        "repository_tree": REPOSITORY_TREE,
        "paths": [
            "Cargo.lock",
            "Cargo.toml",
            "LICENSE",
            "rust-toolchain.toml",
            "rustfmt.toml",
            "crates/*",
        ],
    },
}
KERNEL_PIN = {
    "authority": "kernels",
    "file_count": 458,
    "byte_count": 33508731,
    "closure_sha256": "63c7503f83ed467fdcf010be867b0f395ace8a4a0d1d11572112ce7405cbbe2b",
    "upstream": {
        "repository": REPOSITORY,
        "branch": "perf-optimizations",
        "commit": COMMIT,
        "tree": "044f995e98ba6f2fdb5a1634a99c14927d7a93c0",
        "path": KERNEL_SUBTREE.as_posix(),
    },
}


class AuthorityError(RuntimeError):
    pass


def load_manifest(path: Path, expected_sha256: str) -> dict[str, object]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuthorityError(f"cannot read authority manifest {path}: {error}") from error
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise AuthorityError(f"external CUDA authority manifest drifted: {path}")
    if value.get("schema") != "stwo-zig-cuda-source-closure-v1":
        raise AuthorityError(f"unsupported authority manifest: {path}")
    return value


def validate_manifest_pin(
    manifest: dict[str, object],
    pin: dict[str, object],
) -> None:
    observed = {key: manifest.get(key) for key in pin}
    if observed != pin:
        raise AuthorityError("external CUDA authority manifest pin drifted")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != pin["file_count"]:
        raise AuthorityError("external CUDA authority file inventory is malformed")


def closure(root: Path) -> dict[str, object]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files or any(path.is_symlink() for path in root.rglob("*")):
        raise AuthorityError(f"authority projection is empty or contains symlinks: {root}")
    digest = hashlib.sha256()
    entries: list[dict[str, object]] = []
    byte_count = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
        byte_count += len(payload)
        entries.append(
            {
                "bytes": len(payload),
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "file_count": len(entries),
        "byte_count": byte_count,
        "closure_sha256": digest.hexdigest(),
        "files": entries,
    }


def verify_projection(root: Path) -> dict[str, object]:
    expected_host = load_manifest(HOST_MANIFEST, HOST_MANIFEST_SHA256)
    expected_kernel = load_manifest(KERNEL_MANIFEST, KERNEL_MANIFEST_SHA256)
    validate_manifest_pin(expected_host, HOST_PIN)
    validate_manifest_pin(expected_kernel, KERNEL_PIN)
    actual_host = closure(root)
    actual_kernel = closure(root / KERNEL_SUBTREE)
    for label, expected, actual in (
        ("host", expected_host, actual_host),
        ("kernel", expected_kernel, actual_kernel),
    ):
        pinned = {
            key: expected[key]
            for key in ("file_count", "byte_count", "closure_sha256", "files")
        }
        if actual != pinned:
            raise AuthorityError(f"materialized CUDA {label} authority differs from its pin")
    return {
        "schema": "stwo-zig-cuda-external-authority-receipt-v1",
        "repository": REPOSITORY,
        "commit": COMMIT,
        "repository_tree": REPOSITORY_TREE,
        "host_manifest_sha256": HOST_MANIFEST_SHA256,
        "kernel_manifest_sha256": KERNEL_MANIFEST_SHA256,
        "host_closure_sha256": actual_host["closure_sha256"],
        "kernel_closure_sha256": actual_kernel["closure_sha256"],
        "host_file_count": actual_host["file_count"],
        "kernel_file_count": actual_kernel["file_count"],
    }


def run(*arguments: str, cwd: Path | None = None) -> str:
    process = subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise AuthorityError(f"command failed ({' '.join(arguments)}): {detail}")
    return process.stdout.strip()


def project(checkout: Path, destination: Path) -> None:
    manifest = load_manifest(HOST_MANIFEST, HOST_MANIFEST_SHA256)
    validate_manifest_pin(manifest, HOST_PIN)
    for entry in manifest["files"]:
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise AuthorityError("authority manifest path escapes its projection")
        source = checkout / relative
        target = destination / relative
        if not source.is_file() or source.is_symlink():
            raise AuthorityError(f"upstream authority input is absent: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def materialize(output: Path) -> dict[str, object]:
    output = output.resolve()
    if output in {Path("/"), Path.home().resolve(), ROOT, ROOT.parent}:
        raise AuthorityError("refusing broad CUDA authority destination")
    if output.exists():
        if any(path.is_file() or path.is_symlink() for path in output.rglob("*")):
            return verify_projection(output)
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stwo-cuda-authority-") as temporary:
        temporary_root = Path(temporary)
        checkout = temporary_root / "checkout"
        staging = output.parent / f".{output.name}.staging-{os.getpid()}"
        if staging.exists():
            raise AuthorityError(f"stale authority staging path exists: {staging}")
        run("git", "init", "--quiet", str(checkout))
        run("git", "remote", "add", "origin", REPOSITORY, cwd=checkout)
        run("git", "fetch", "--quiet", "--depth", "1", "origin", COMMIT, cwd=checkout)
        run("git", "checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=checkout)
        if run("git", "rev-parse", "HEAD", cwd=checkout) != COMMIT:
            raise AuthorityError("fetched CUDA authority commit drifted")
        if run("git", "rev-parse", "HEAD^{tree}", cwd=checkout) != REPOSITORY_TREE:
            raise AuthorityError("fetched CUDA authority tree drifted")
        staging.mkdir()
        try:
            project(checkout, staging)
            receipt = verify_projection(staging)
            os.replace(staging, output)
            return receipt
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("materialize", "verify"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    receipt = (
        materialize(args.output)
        if args.command == "materialize"
        else verify_projection(args.output.resolve())
    )
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.receipt is not None:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuthorityError as error:
        raise SystemExit(f"CUDA external authority rejected: {error}") from error
