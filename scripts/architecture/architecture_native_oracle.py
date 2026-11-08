#!/usr/bin/env python3
"""Create or verify a content-addressed pinned Native Rust oracle bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "build-architecture-native-oracle-bundle-v1"
UPSTREAM = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
TOOLCHAIN = "nightly-2025-07-14"
RUSTC_RELEASE = "1.90.0-nightly"
RUSTC_COMMIT = "e9182f195b8505c87c4bd055b9f6e114ccda0981"
CARGO_RELEASE = "1.90.0-nightly"
CARGO_COMMIT = "eabb4cd923deb73e714f7ad3f5234d68ca284dbe"
PACKAGE = Path("tools/stwo-interop-rs")
BINARY_NAME = "stwo-interop-rs"
MANIFEST_NAME = "manifest.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
MANIFEST_FIELDS = {
    "schema",
    "content_sha256",
    "host_role",
    "platform",
    "rust_toolchain",
    "upstream_commit",
    "sources",
    "binary",
    "producer",
}
PRODUCER_FIELDS = {
    "repository",
    "repository_id",
    "candidate",
    "tree",
    "workflow_sha",
    "workflow_path",
    "workflow_definition_sha256",
    "producer_job",
    "run_id",
    "run_attempt",
}


class OracleBundleError(ValueError):
    """The Native Rust oracle bundle is malformed or unauthenticated."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strict_json_bytes(raw: bytes, description: str) -> object:
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise OracleBundleError(f"{description} size is invalid")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise OracleBundleError(f"duplicate JSON key in {description}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise OracleBundleError(f"non-finite JSON value in {description}: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise OracleBundleError(f"{description} is not canonical JSON: {error}") from error


def _strict_json_file(path: Path, description: str) -> object:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_MANIFEST_BYTES
    ):
        raise OracleBundleError(f"{description} is not a regular file")
    return _strict_json_bytes(path.read_bytes(), description)


def _current_platform() -> tuple[str, dict[str, str]]:
    system = platform.system()
    roles = {"Darwin": "macos", "Linux": "linux"}
    if system not in roles:
        raise OracleBundleError(f"unsupported Native oracle platform: {system}")
    machine = platform.machine()
    if not machine:
        raise OracleBundleError("Native oracle architecture is empty")
    return roles[system], {"system": system, "machine": machine}


def _tool_output(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv,
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise OracleBundleError(f"failed to identify pinned toolchain: {error}") from error
    output = result.stdout.strip()
    if not output or len(output) > 4096 or not output.isascii():
        raise OracleBundleError("pinned toolchain identity output is invalid")
    return output


def _version_fields(output: str, tool: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value
    required = {"release", "commit-hash", "host"}
    if not required <= values.keys():
        raise OracleBundleError(f"{tool} verbose version output is incomplete")
    return {
        "release": values["release"],
        "commit": values["commit-hash"],
        "target_triple": values["host"],
    }


def _toolchain_identity() -> dict[str, object]:
    rustc = _version_fields(
        _tool_output(["rustc", f"+{TOOLCHAIN}", "--version", "--verbose"]),
        "rustc",
    )
    cargo = _version_fields(
        _tool_output(["cargo", f"+{TOOLCHAIN}", "--version", "--verbose"]),
        "cargo",
    )
    if (
        rustc["release"] != RUSTC_RELEASE
        or rustc["commit"] != RUSTC_COMMIT
        or cargo["release"] != CARGO_RELEASE
        or cargo["commit"] != CARGO_COMMIT
        or cargo["target_triple"] != rustc["target_triple"]
    ):
        raise OracleBundleError("installed compiler differs from the pinned toolchain")
    return {"channel": TOOLCHAIN, "rustc": rustc, "cargo": cargo}


def _validate_toolchain(value: object, role: str, machine: str) -> None:
    if not isinstance(value, dict) or set(value) != {"channel", "rustc", "cargo"}:
        raise OracleBundleError("Native oracle toolchain identity is malformed")
    if value["channel"] != TOOLCHAIN:
        raise OracleBundleError("Native oracle toolchain channel drifted")
    expected = (
        ("rustc", RUSTC_RELEASE, RUSTC_COMMIT),
        ("cargo", CARGO_RELEASE, CARGO_COMMIT),
    )
    triples: list[str] = []
    for key, release, commit in expected:
        record = value[key]
        if not isinstance(record, dict) or set(record) != {"release", "commit", "target_triple"}:
            raise OracleBundleError(f"Native oracle {key} identity is malformed")
        if (
            record["release"] != release
            or record["commit"] != commit
            or not isinstance(record["target_triple"], str)
            or len(record["target_triple"]) > 96
            or not record["target_triple"].isascii()
        ):
            raise OracleBundleError(f"Native oracle {key} identity drifted")
        triples.append(record["target_triple"])
    architecture = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(machine)
    suffix = {"macos": "-apple-darwin", "linux": "-unknown-linux-gnu"}[role]
    if architecture is None or len(set(triples)) != 1 or triples[0] != architecture + suffix:
        raise OracleBundleError("Native oracle compiler target does not match its host")


def _source_paths(root: Path) -> tuple[str, ...]:
    package = root / PACKAGE
    package_metadata = package.lstat()
    if not stat.S_ISDIR(package_metadata.st_mode) or package.is_symlink():
        raise OracleBundleError("Native oracle package path is unsafe")
    required = (package / "Cargo.toml", package / "Cargo.lock", package / "src")
    if not all(path.exists() for path in required):
        raise OracleBundleError("Native oracle source closure is incomplete")
    src_metadata = (package / "src").lstat()
    if not stat.S_ISDIR(src_metadata.st_mode) or (package / "src").is_symlink():
        raise OracleBundleError("Native oracle source directory is unsafe")
    discovered: list[str] = []
    for path in (package / "Cargo.toml", package / "Cargo.lock"):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise OracleBundleError(f"Native oracle source is unsafe: {path}")
        discovered.append(path.relative_to(root).as_posix())
    for path in sorted((package / "src").rglob("*")):
        metadata = path.lstat()
        if path.is_symlink():
            raise OracleBundleError(f"Native oracle source is unsafe: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise OracleBundleError(f"Native oracle source is unsafe: {path}")
        discovered.append(path.relative_to(root).as_posix())
    if len(discovered) == 2:
        raise OracleBundleError("Native oracle Rust source set is empty")
    return tuple(discovered)


def _sources(root: Path) -> dict[str, str]:
    return {relative: _sha256(root / relative) for relative in _source_paths(root)}


def _bounded_positive_int(value: object, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= maximum
    )


def _workflow_path(authority_root: Path, value: object) -> Path:
    if (
        not isinstance(value, str)
        or not value.startswith(".github/workflows/")
        or not value.endswith((".yml", ".yaml"))
        or len(value) > 160
        or Path(value).is_absolute()
        or ".." in Path(value).parts
    ):
        raise OracleBundleError("Native oracle producer workflow path is unsafe")
    workflow = authority_root / value
    try:
        metadata = workflow.lstat()
    except FileNotFoundError as error:
        raise OracleBundleError("Native oracle producer workflow is absent from authority") from error
    if not stat.S_ISREG(metadata.st_mode) or workflow.is_symlink():
        raise OracleBundleError("Native oracle producer workflow is unsafe")
    return workflow


def _validate_producer(value: object, authority_root: Path) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != PRODUCER_FIELDS:
        raise OracleBundleError("Native oracle producer identity is malformed")
    workflow = _workflow_path(authority_root, value["workflow_path"])
    if (
        value["repository"] != "teddyjfpender/stwo-zig"
        or value["repository_id"] != 1152389958
        or not isinstance(value["candidate"], str)
        or HEX40.fullmatch(value["candidate"]) is None
        or not isinstance(value["tree"], str)
        or HEX40.fullmatch(value["tree"]) is None
        or not isinstance(value["workflow_sha"], str)
        or HEX40.fullmatch(value["workflow_sha"]) is None
        or not isinstance(value["workflow_definition_sha256"], str)
        or HEX64.fullmatch(value["workflow_definition_sha256"]) is None
        or value["workflow_definition_sha256"] != _sha256(workflow)
        or not isinstance(value["producer_job"], str)
        or value["producer_job"] not in {
            "native-oracle-producer-linux",
            "native-oracle-producer-macos",
        }
        or not _bounded_positive_int(value["run_id"], 2**63 - 1)
        or not _bounded_positive_int(value["run_attempt"], 1000)
    ):
        raise OracleBundleError("Native oracle producer trust fields are invalid")
    return value


def _content_address(manifest: dict[str, object]) -> str:
    identity = {key: value for key, value in manifest.items() if key != "content_sha256"}
    return hashlib.sha256(_canonical(identity)).hexdigest()


def _regular_executable(path: Path) -> Path:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_BINARY_BYTES
        or metadata.st_mode & 0o111 == 0
    ):
        raise OracleBundleError("Native Rust oracle is not a bounded executable regular file")
    return path.resolve(strict=True)


def build(
    binary: Path,
    root: Path,
    output: Path,
    producer: dict[str, object],
    authority_root: Path | None = None,
) -> Path:
    binary = _regular_executable(binary)
    root = root.resolve(strict=True)
    authority_root = (authority_root or ROOT).resolve(strict=True)
    producer = _validate_producer(producer, authority_root)
    role, host_platform = _current_platform()
    if producer["producer_job"] != f"native-oracle-producer-{role}":
        raise OracleBundleError("Native oracle producer job does not match its host")
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise OracleBundleError("refusing to replace an existing Native oracle bundle")

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        destination = staging / BINARY_NAME
        shutil.copyfile(binary, destination)
        destination.chmod(0o555)
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "content_sha256": "",
            "host_role": role,
            "platform": host_platform,
            "rust_toolchain": _toolchain_identity(),
            "upstream_commit": UPSTREAM,
            "sources": _sources(root),
            "binary": {
                "path": BINARY_NAME,
                "sha256": _sha256(destination),
                "size": destination.stat().st_size,
                "mode": 0o555,
            },
            "producer": producer,
        }
        manifest["content_sha256"] = _content_address(manifest)
        (staging / MANIFEST_NAME).write_bytes(_canonical(manifest) + b"\n")
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output / BINARY_NAME


def verify(
    bundle: Path,
    root: Path,
    role: str,
    expected_producer: dict[str, object] | None = None,
    authority_root: Path | None = None,
    protected: bool = False,
) -> Path:
    if protected and (expected_producer is None or authority_root is None):
        raise OracleBundleError(
            "protected verification requires authenticated producer metadata and authority root"
        )
    bundle_metadata = bundle.lstat()
    if not stat.S_ISDIR(bundle_metadata.st_mode) or bundle.is_symlink():
        raise OracleBundleError("Native oracle bundle is not a regular directory")
    bundle = bundle.resolve(strict=True)
    if {path.name for path in bundle.iterdir()} != {MANIFEST_NAME, BINARY_NAME}:
        raise OracleBundleError("Native oracle bundle path set drifted")

    manifest_path = bundle / MANIFEST_NAME
    manifest = _strict_json_file(manifest_path, "Native oracle manifest")
    raw_manifest = manifest_path.read_bytes()
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise OracleBundleError("Native oracle manifest fields drifted")
    if raw_manifest != _canonical(manifest) + b"\n":
        raise OracleBundleError("Native oracle manifest encoding is not canonical")
    current_role, current_platform = _current_platform()
    if role not in {"linux", "macos"} or role != current_role:
        raise OracleBundleError("Native oracle requested role does not match this host")
    if (
        manifest["schema"] != SCHEMA
        or manifest["host_role"] != role
        or manifest["platform"] != current_platform
        or manifest["upstream_commit"] != UPSTREAM
        or manifest["sources"] != _sources(root.resolve(strict=True))
    ):
        raise OracleBundleError("Native oracle source/toolchain/platform identity drifted")
    _validate_toolchain(manifest["rust_toolchain"], role, current_platform["machine"])
    content_sha256 = manifest["content_sha256"]
    if (
        not isinstance(content_sha256, str)
        or HEX64.fullmatch(content_sha256) is None
        or content_sha256 != _content_address(manifest)
    ):
        raise OracleBundleError("Native oracle content address mismatch")

    binary_record = manifest["binary"]
    if not isinstance(binary_record, dict) or set(binary_record) != {"path", "sha256", "size", "mode"}:
        raise OracleBundleError("Native oracle binary record is malformed")
    if (
        binary_record["path"] != BINARY_NAME
        or not isinstance(binary_record["sha256"], str)
        or HEX64.fullmatch(binary_record["sha256"]) is None
        or not _bounded_positive_int(binary_record["size"], MAX_BINARY_BYTES)
        or binary_record["mode"] != 0o555
    ):
        raise OracleBundleError("Native oracle binary record fields are invalid")
    binary = bundle / BINARY_NAME
    metadata = binary.lstat()
    if not stat.S_ISREG(metadata.st_mode) or binary.is_symlink():
        raise OracleBundleError("Native oracle binary path is unsafe")
    if (
        metadata.st_size != binary_record["size"]
        or stat.S_IMODE(metadata.st_mode) != binary_record["mode"]
        or _sha256(binary) != binary_record["sha256"]
    ):
        raise OracleBundleError("Native oracle binary content digest mismatch")

    authority_root = (authority_root or ROOT).resolve(strict=True)
    producer = _validate_producer(manifest["producer"], authority_root)
    if (
        expected_producer is not None
        and producer != _validate_producer(expected_producer, authority_root)
    ):
        raise OracleBundleError("Native oracle producer differs from trusted metadata")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    create = phases.add_parser("build")
    create.add_argument("--binary", type=Path, required=True)
    create.add_argument("--root", type=Path, default=ROOT)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--producer", type=Path, required=True)
    create.add_argument("--authority-root", type=Path, default=ROOT)
    check = phases.add_parser("verify")
    check.add_argument("--bundle", type=Path, required=True)
    check.add_argument("--root", type=Path, default=ROOT)
    check.add_argument("--role", choices=("linux", "macos"), required=True)
    check.add_argument("--expected-producer", type=Path)
    check.add_argument("--authority-root", type=Path)
    check.add_argument("--protected", action="store_true")
    args = parser.parse_args()
    try:
        if args.phase == "build":
            producer = _strict_json_file(args.producer, "Native oracle producer")
            build(args.binary, args.root, args.output, producer, args.authority_root)
        else:
            expected = (
                _strict_json_file(args.expected_producer, "expected Native oracle producer")
                if args.expected_producer else None
            )
            verify(
                args.bundle,
                args.root,
                args.role,
                expected,
                args.authority_root,
                args.protected,
            )
    except (OSError, OracleBundleError) as error:
        print(f"architecture Native oracle bundle: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"architecture Native oracle bundle: PASS ({args.phase})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
