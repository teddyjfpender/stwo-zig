#!/usr/bin/env python3
"""Validate every live Rust-oracle pin carrier against the upstream ledger."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from upstream_pins_lib.official_cairo_vectors import check as check_official_cairo_vectors


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "conformance" / "upstream.md"
REVISION_RE = r"[0-9a-f]{40}"


class PinLedgerError(ValueError):
    """The checked-in upstream ledger is missing or ambiguous."""


@dataclasses.dataclass(frozen=True)
class PinLedger:
    native_repository: str
    native_revision: str
    riscv_repository: str
    riscv_revision: str
    official_cairo_repository: str
    official_cairo_revision: str
    official_cairo_stwo_repository: str
    official_cairo_stwo_revision: str
    cairo_repository: str
    cairo_revision: str
    cairo_stwo_repository: str
    cairo_stwo_revision: str
    cairo_prover_stwo_revision: str


@dataclasses.dataclass(frozen=True)
class TextPin:
    path: str
    label: str
    pattern: str
    expected: str


def _single_field(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise PinLedgerError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def parse_ledger(path: Path = DEFAULT_LEDGER) -> PinLedger:
    text = path.read_text(encoding="utf-8")
    return PinLedger(
        native_repository=_single_field(
            text, r"^- Upstream repository: `([^`]+)`$", "Native Stwo repository"
        ),
        native_revision=_single_field(
            text, rf"^- Pinned commit: `({REVISION_RE})`$", "Native Stwo revision"
        ),
        riscv_repository=_single_field(
            text, r"^- Stark-V repository: `([^`]+)`$", "Stark-V repository"
        ),
        riscv_revision=_single_field(
            text,
            rf"^- Pinned Stark-V commit: `({REVISION_RE})`$",
            "Stark-V revision",
        ),
        official_cairo_repository=_single_field(
            text,
            r"^- Official Stwo-Cairo repository: `([^`]+)`$",
            "official Stwo-Cairo repository",
        ),
        official_cairo_revision=_single_field(
            text,
            rf"^- Pinned official Stwo-Cairo commit: `({REVISION_RE})`$",
            "official Stwo-Cairo revision",
        ),
        official_cairo_stwo_repository=_single_field(
            text,
            r"^- Official Cairo Stwo repository: `([^`]+)`$",
            "official Cairo Stwo repository",
        ),
        official_cairo_stwo_revision=_single_field(
            text,
            rf"^- Pinned official Cairo Stwo commit: `({REVISION_RE})`$",
            "official Cairo Stwo revision",
        ),
        cairo_repository=_single_field(
            text, r"^- Stwo-Cairo repository: `([^`]+)`$", "Cairo Stwo-Cairo repository"
        ),
        cairo_revision=_single_field(
            text,
            rf"^- Pinned Stwo-Cairo commit: `({REVISION_RE})`$",
            "Cairo Stwo-Cairo revision",
        ),
        cairo_stwo_repository=_single_field(
            text, r"^- Stwo repository: `([^`]+)`$", "Cairo Stwo repository"
        ),
        cairo_stwo_revision=_single_field(
            text,
            rf"^- Pinned Cairo verifier Stwo commit: `({REVISION_RE})`$",
            "Cairo verifier Stwo revision",
        ),
        cairo_prover_stwo_revision=_single_field(
            text,
            rf"^- Pinned Cairo prover Stwo commit: `({REVISION_RE})`$",
            "Cairo prover Stwo revision",
        ),
    )


def _check_text_pin(root: Path, pin: TextPin) -> list[str]:
    path = root / pin.path
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"{pin.path}: unable to read {pin.label}: {error}"]
    matches = re.findall(pin.pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        return [f"{pin.path}: expected exactly one {pin.label}, found {len(matches)}"]
    if matches[0] != pin.expected:
        return [f"{pin.path}: {pin.label} is {matches[0]!r}, expected {pin.expected!r}"]
    return []


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _check_manifest_dependency(
    root: Path,
    relative_path: str,
    dependency: str,
    repository: str,
    revision: str,
) -> list[str]:
    try:
        manifest = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse manifest: {error}"]
    value = manifest.get("dependencies", {}).get(dependency)
    if not isinstance(value, dict):
        return [f"{relative_path}: missing table dependency {dependency!r}"]
    errors: list[str] = []
    for field, expected in (("git", repository), ("rev", revision)):
        if value.get(field) != expected:
            errors.append(
                f"{relative_path}: dependency {dependency!r} {field} is "
                f"{value.get(field)!r}, expected {expected!r}"
            )
    return errors


def _check_cairo_manifest(root: Path, ledger: PinLedger) -> list[str]:
    relative_path = "tools/stwo-cairo-verifier-rs/Cargo.toml"
    try:
        manifest = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse manifest: {error}"]

    metadata = manifest.get("package", {}).get("metadata", {}).get("canonical-verifier", {})
    expected_metadata = {
        "stwo-cairo-repository": ledger.cairo_repository,
        "stwo-cairo-revision": ledger.cairo_revision,
        "stwo-repository": ledger.cairo_stwo_repository,
        "stwo-revision": ledger.cairo_stwo_revision,
    }
    errors = [
        f"{relative_path}: metadata {key!r} is {metadata.get(key)!r}, expected {expected!r}"
        for key, expected in expected_metadata.items()
        if metadata.get(key) != expected
    ]
    for dependency in ("cairo-air", "stwo-cairo-common"):
        errors.extend(
            _check_manifest_dependency(
                root,
                relative_path,
                dependency,
                ledger.cairo_repository,
                ledger.cairo_revision,
            )
        )
    errors.extend(
        _check_manifest_dependency(
            root,
            relative_path,
            "stwo",
            ledger.cairo_stwo_repository,
            ledger.cairo_stwo_revision,
        )
    )
    return errors


def _check_official_cairo_manifest(root: Path, ledger: PinLedger) -> list[str]:
    relative_path = "tools/stwo-cairo-official-verifier-rs/Cargo.toml"
    try:
        manifest = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse manifest: {error}"]

    metadata = manifest.get("package", {}).get("metadata", {}).get("official-verifier", {})
    expected_metadata = {
        "stwo-cairo-repository": ledger.official_cairo_repository,
        "stwo-cairo-revision": ledger.official_cairo_revision,
        "stwo-repository": ledger.official_cairo_stwo_repository,
        "stwo-revision": ledger.official_cairo_stwo_revision,
    }
    errors = [
        f"{relative_path}: metadata {key!r} is {metadata.get(key)!r}, expected {expected!r}"
        for key, expected in expected_metadata.items()
        if metadata.get(key) != expected
    ]
    dependencies = manifest.get("dependencies", {})
    expected_dependencies = {
        "cairo-air": (
            ledger.official_cairo_repository,
            ledger.official_cairo_revision,
        ),
        "stwo-cairo-adapter": (
            ledger.official_cairo_repository,
            ledger.official_cairo_revision,
        ),
        "stwo-cairo-common": (
            ledger.official_cairo_repository,
            ledger.official_cairo_revision,
        ),
        # Stwo-Cairo uses this short rev spelling. Matching it prevents Cargo
        # from creating two incompatible identities for the same Stwo commit.
        "stwo": (
            ledger.official_cairo_stwo_repository,
            ledger.official_cairo_stwo_revision[:8],
        ),
    }
    for dependency, (repository, revision) in expected_dependencies.items():
        value = dependencies.get(dependency)
        if not isinstance(value, dict):
            errors.append(f"{relative_path}: missing table dependency {dependency!r}")
            continue
        if value.get("git") != repository or value.get("rev") != revision:
            errors.append(
                f"{relative_path}: dependency {dependency!r} is "
                f"{value.get('git')!r}@{value.get('rev')!r}, "
                f"expected {repository!r}@{revision!r}"
            )
    for name, value in dependencies.items():
        if isinstance(value, dict) and "path" in value:
            errors.append(f"{relative_path}: path dependency {name!r} is forbidden")
    for key in ("patch", "replace"):
        if key in manifest:
            errors.append(f"{relative_path}: [{key}] is forbidden in the official oracle")
    return errors


def _check_cairo_trace_oracle_manifest(root: Path, ledger: PinLedger) -> list[str]:
    relative_path = "tools/stwo-cairo-trace-oracle/Cargo.toml"
    try:
        manifest = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse manifest: {error}"]

    metadata = manifest.get("package", {}).get("metadata", {}).get("canonical-oracle", {})
    expected_metadata = {
        "stwo-cairo-repository": ledger.cairo_repository,
        "stwo-cairo-revision": ledger.cairo_revision,
        "stwo-repository": ledger.cairo_stwo_repository,
        "stwo-revision": ledger.cairo_prover_stwo_revision,
    }
    errors = [
        f"{relative_path}: metadata {key!r} is {metadata.get(key)!r}, expected {expected!r}"
        for key, expected in expected_metadata.items()
        if metadata.get(key) != expected
    ]
    for dependency in (
        "cairo-air",
        "stwo-cairo-adapter",
        "stwo-cairo-common",
        "stwo-cairo-prover",
    ):
        errors.extend(
            _check_manifest_dependency(
                root,
                relative_path,
                dependency,
                ledger.cairo_repository,
                ledger.cairo_revision,
            )
        )

    # The pinned Stwo-Cairo manifest names the verifier revision. Source-qualified
    # replacements are required to substitute its complete prover dependency graph.
    errors.extend(
        _check_manifest_dependency(
            root,
            relative_path,
            "stwo",
            ledger.cairo_stwo_repository,
            ledger.cairo_stwo_revision,
        )
    )
    replacements = manifest.get("replace", {})
    required_packages = {
        "stwo@2.2.0",
        "stwo-backend-cuda@2.2.0",
        "stwo-backend-cuda-kernels@0.1.0",
        "stwo-constraint-framework@2.2.0",
        "stwo-air-utils@2.2.0",
        "stwo-air-utils-derive@2.2.0",
    }
    found_packages: set[str] = set()
    for source_id, replacement in replacements.items():
        package = source_id.rsplit("#", 1)[-1]
        if package not in required_packages:
            errors.append(f"{relative_path}: unexpected Stwo replacement {source_id!r}")
            continue
        found_packages.add(package)
        if not isinstance(replacement, dict) or replacement.get("git") != ledger.cairo_stwo_repository or replacement.get("rev") != ledger.cairo_prover_stwo_revision:
            errors.append(
                f"{relative_path}: replacement {source_id!r} must target "
                f"{ledger.cairo_stwo_repository}@{ledger.cairo_prover_stwo_revision}"
            )
    missing = sorted(required_packages - found_packages)
    if missing:
        errors.append(f"{relative_path}: missing Stwo replacements {missing!r}")
    return errors


def _check_replaced_lock_sources(root: Path, relative_path: str, ledger: PinLedger) -> list[str]:
    try:
        lock = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse lockfile: {error}"]
    old_source = (
        f"git+{ledger.cairo_stwo_repository}?rev={ledger.cairo_stwo_revision}"
        f"#{ledger.cairo_stwo_revision}"
    )
    new_source = (
        f"git+{ledger.cairo_stwo_repository}?rev={ledger.cairo_prover_stwo_revision}"
        f"#{ledger.cairo_prover_stwo_revision}"
    )
    packages = [
        package
        for package in lock.get("package", [])
        if isinstance(package, dict)
        and isinstance(package.get("source"), str)
        and package["source"].startswith(f"git+{ledger.cairo_stwo_repository}?")
    ]
    sources = {package["source"] for package in packages}
    errors: list[str] = []
    if sources != {old_source, new_source}:
        errors.append(
            f"{relative_path}: Cairo prover Stwo sources are {sorted(sources)!r}, "
            f"expected only declared {old_source!r} and replacement {new_source!r}"
        )
    old_packages = {package["name"] for package in packages if package["source"] == old_source}
    new_packages = {package["name"] for package in packages if package["source"] == new_source}
    if old_packages != new_packages:
        errors.append(
            f"{relative_path}: replacement package names differ: "
            f"declared={sorted(old_packages)!r}, replacements={sorted(new_packages)!r}"
        )
    for package in packages:
        if package["source"] != old_source:
            continue
        replace = package.get("replace")
        if not isinstance(replace, str) or ledger.cairo_prover_stwo_revision not in replace:
            errors.append(
                f"{relative_path}: {package['name']}@{package['version']} is not locked to "
                f"the prover replacement {ledger.cairo_prover_stwo_revision}"
            )
    return errors


def _check_lock_sources(
    root: Path, relative_path: str, repository: str, revision: str
) -> list[str]:
    try:
        lock = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse lockfile: {error}"]
    prefix = f"git+{repository}?"
    sources = {
        package.get("source")
        for package in lock.get("package", [])
        if isinstance(package, dict)
        and isinstance(package.get("source"), str)
        and package["source"].startswith(prefix)
    }
    expected = f"git+{repository}?rev={revision}#{revision}"
    if not sources:
        return [f"{relative_path}: no locked package found for {repository}"]
    if sources != {expected}:
        return [
            f"{relative_path}: locked sources for {repository} are {sorted(sources)!r}, "
            f"expected only {expected!r}"
        ]
    return []


def _check_lock_source(
    root: Path,
    relative_path: str,
    repository: str,
    declared_revision: str,
    resolved_revision: str,
) -> list[str]:
    try:
        lock = _load_toml(root / relative_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: unable to parse lockfile: {error}"]
    prefix = f"git+{repository}?"
    sources = {
        package.get("source")
        for package in lock.get("package", [])
        if isinstance(package, dict)
        and isinstance(package.get("source"), str)
        and package["source"].startswith(prefix)
    }
    expected = f"git+{repository}?rev={declared_revision}#{resolved_revision}"
    if sources != {expected}:
        return [
            f"{relative_path}: locked sources for {repository} are {sorted(sources)!r}, "
            f"expected only {expected!r}"
        ]
    return []


def _check_blake_oracle_source(root: Path, ledger: PinLedger) -> list[str]:
    base = root / "tools" / "stwo-interop-rs"
    provenance_path = base / "upstream_blake_provenance.json"
    label = provenance_path.relative_to(root)
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{provenance_path.relative_to(root)}: invalid provenance: {error}"]
    expected_fields = {
        "schema",
        "repository",
        "commit",
        "source_path",
        "source_tree_sha256",
        "source_files",
        "transport_patch",
    }
    if not isinstance(provenance, dict) or set(provenance) != expected_fields:
        return ["tools/stwo-interop-rs/upstream_blake_provenance.json: invalid schema"]
    errors: list[str] = []
    if provenance["repository"] != ledger.native_repository:
        errors.append(f"{label}: Blake oracle provenance repository does not match Native pin")
    if provenance["commit"] != ledger.native_revision:
        errors.append(f"{label}: Blake oracle provenance commit does not match Native pin")
    files = provenance["source_files"]
    if not isinstance(files, list) or not files or any(
        not isinstance(path, str) or Path(path).is_absolute() for path in files
    ):
        return errors + ["Blake oracle provenance source_files is invalid"]
    source_root = base / "src" / "upstream_blake"
    actual = sorted(
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*.rs")
        if path.name != "transport.rs"
    )
    if actual != sorted(files):
        errors.append("Blake oracle vendored source file set drifted")
        return errors

    digest = hashlib.sha256()
    for relative in sorted(files):
        path = source_root / relative
        data = path.read_bytes()
        if relative == "mod.rs":
            if data.count(b"pub mod air;") != 1:
                errors.append("Blake oracle air visibility patch drifted")
                continue
            data = data.replace(b"pub mod air;", b"mod air;")
        elif relative == "air.rs":
            marker = b"pub mod transport;\n\n"
            if data.count(marker) != 1:
                errors.append("Blake oracle transport declaration drifted")
                continue
            data = data.replace(marker, b"")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    if digest.hexdigest() != provenance["source_tree_sha256"]:
        errors.append("Blake oracle vendored AIR differs from pinned upstream source")
    return errors


def _text_pins(ledger: PinLedger) -> tuple[TextPin, ...]:
    native = ledger.native_revision
    riscv = ledger.riscv_revision
    cairo = ledger.cairo_revision
    cairo_stwo = ledger.cairo_stwo_revision
    return (
        TextPin(
            "scripts/riscv_equivalence.py",
            "Stark-V PINNED_STARK_V_REVISION",
            rf'^PINNED_STARK_V_REVISION = "({REVISION_RE})"$',
            riscv,
        ),
        TextPin(
            "vectors/riscv_elfs/trace_vectors.json",
            "Stark-V trace vector provenance commit",
            rf'^ "stark_v_commit": "({REVISION_RE})",$',
            riscv,
        ),
        TextPin(
            "scripts/e2e_interop_lib/controller.py",
            "Native UPSTREAM_COMMIT",
            rf'^UPSTREAM_COMMIT = "({REVISION_RE})"$',
            native,
        ),
        TextPin(
            "scripts/prove_checkpoints.py",
            "Native UPSTREAM_COMMIT",
            rf'^UPSTREAM_COMMIT = "({REVISION_RE})"$',
            native,
        ),
        TextPin(
            "scripts/native_proof_matrix_lib/model.py",
            "Native INTEROP_UPSTREAM_COMMIT",
            rf'^INTEROP_UPSTREAM_COMMIT = "({REVISION_RE})"$',
            native,
        ),
        TextPin(
            "src/interop/examples_artifact.zig",
            "Native UPSTREAM_COMMIT",
            rf'^pub const UPSTREAM_COMMIT: \[\]const u8 = "({REVISION_RE})";$',
            native,
        ),
        TextPin(
            "tools/stwo-interop-rs/src/main.rs",
            "Native UPSTREAM_COMMIT",
            rf'^const UPSTREAM_COMMIT: &str = "({REVISION_RE})";$',
            native,
        ),
        TextPin(
            "tools/stwo-vector-gen/src/main.rs",
            "Native UPSTREAM_COMMIT",
            rf'^const UPSTREAM_COMMIT: &str = "({REVISION_RE})";$',
            native,
        ),
        TextPin(
            "tools/stwo-cf-vector-gen/src/main.rs",
            "Native UPSTREAM_COMMIT",
            rf'^const UPSTREAM_COMMIT: &str = "({REVISION_RE})";$',
            native,
        ),
        TextPin(
            "tools/stwo-cairo-verifier-rs/src/lib.rs",
            "Stwo-Cairo repository",
            r'^pub const STWO_CAIRO_REPOSITORY: &str = "([^"]+)";$',
            ledger.cairo_repository,
        ),
        TextPin(
            "tools/stwo-cairo-verifier-rs/src/lib.rs",
            "Stwo-Cairo revision",
            rf'^pub const STWO_CAIRO_REVISION: &str = "({REVISION_RE})";$',
            cairo,
        ),
        TextPin(
            "tools/stwo-cairo-verifier-rs/src/lib.rs",
            "Cairo Stwo repository",
            r'^pub const STWO_REPOSITORY: &str = "([^"]+)";$',
            ledger.cairo_stwo_repository,
        ),
        TextPin(
            "tools/stwo-cairo-verifier-rs/src/lib.rs",
            "Cairo Stwo revision",
            rf'^pub const STWO_REVISION: &str = "({REVISION_RE})";$',
            cairo_stwo,
        ),
        TextPin(
            "scripts/generate_cairo_claim_registry.py",
            "official claim-generator Stwo-Cairo revision",
            rf'^PINNED_STWO_CAIRO_REVISION = "({REVISION_RE})"$',
            ledger.official_cairo_revision,
        ),
        TextPin(
            "scripts/generate_cairo_claim_registry.py",
            "official claim-generator Stwo revision",
            rf'^PINNED_STWO_REVISION = "({REVISION_RE})"$',
            ledger.official_cairo_stwo_revision,
        ),
        TextPin(
            "tools/stwo-cairo-official-verifier-rs/src/lib.rs",
            "official verifier Stwo-Cairo repository",
            r'^pub const STWO_CAIRO_REPOSITORY: &str = "([^"]+)";$',
            ledger.official_cairo_repository,
        ),
        TextPin(
            "tools/stwo-cairo-official-verifier-rs/src/lib.rs",
            "official verifier Stwo-Cairo revision",
            rf'^pub const STWO_CAIRO_REVISION: &str = "({REVISION_RE})";$',
            ledger.official_cairo_revision,
        ),
        TextPin(
            "tools/stwo-cairo-official-verifier-rs/src/lib.rs",
            "official verifier Stwo repository",
            r'^pub const STWO_REPOSITORY: &str = "([^"]+)";$',
            ledger.official_cairo_stwo_repository,
        ),
        TextPin(
            "tools/stwo-cairo-official-verifier-rs/src/lib.rs",
            "official verifier Stwo revision",
            rf'^pub const STWO_REVISION: &str = "({REVISION_RE})";$',
            ledger.official_cairo_stwo_revision,
        ),
        TextPin(
            "src/frontends/cairo/air/official_claim_registry.zig",
            "official generated claim-registry Stwo-Cairo revision",
            rf'^    \.stwo_cairo = "({REVISION_RE})",$',
            ledger.official_cairo_revision,
        ),
        TextPin(
            "src/frontends/cairo/air/official_claim_registry.zig",
            "official generated claim-registry Stwo revision",
            rf'^    \.stwo = "({REVISION_RE})",$',
            ledger.official_cairo_stwo_revision,
        ),
        TextPin(
            "src/tools/metal_prover_session/state.zig",
            "resident session Stwo-Cairo revision",
            rf'^pub const rust_verifier_stwo_cairo_revision = "({REVISION_RE})";$',
            cairo,
        ),
        TextPin(
            "src/tools/metal_prover_session/state.zig",
            "resident session Stwo revision",
            rf'^pub const rust_verifier_stwo_revision = "({REVISION_RE})";$',
            cairo_stwo,
        ),
        TextPin(
            "src/frontends/cairo/prover.zig",
            "Cairo prover Stwo-Cairo revision",
            rf'^pub const pinned_stwo_cairo_revision = "({REVISION_RE})";$',
            cairo,
        ),
        TextPin(
            "src/frontends/cairo/prover.zig",
            "Cairo prover Stwo revision",
            rf'^pub const pinned_stwo_revision = "({REVISION_RE})";$',
            cairo_stwo,
        ),
        TextPin(
            "archive/cairo/legacy_claim_registry.zig",
            "generated claim-registry Stwo-Cairo revision",
            rf'^    \.stwo_cairo = "({REVISION_RE})",$',
            cairo,
        ),
        TextPin(
            "archive/cairo/legacy_claim_registry.zig",
            "generated claim-registry Stwo revision",
            rf'^    \.stwo = "({REVISION_RE})",$',
            cairo_stwo,
        ),
        TextPin(
            ".github/workflows/ci.yml",
            "hosted Cairo checkout revision",
            rf'^          STWO_CAIRO_REVISION: ({REVISION_RE})$',
            cairo,
        ),
        TextPin(
            ".github/workflows/ci.yml",
            "hosted Cairo checkout repository",
            r"^          git -C \"\$STWO_CAIRO_RUST_ROOT\" remote add origin (\S+)$",
            ledger.cairo_repository,
        ),
    )


def validate_repository(root: Path = ROOT, ledger_path: Path | None = None) -> list[str]:
    path = ledger_path or root / "conformance" / "upstream.md"
    try:
        ledger = parse_ledger(path)
    except (OSError, PinLedgerError) as error:
        return [f"{path}: {error}"]

    errors: list[str] = []
    for pin in _text_pins(ledger):
        errors.extend(_check_text_pin(root, pin))

    native_manifests = {
        "tools/stwo-interop-rs/Cargo.toml": ("stwo",),
        "tools/stwo-vector-gen/Cargo.toml": ("stwo",),
        "tools/stwo-cf-vector-gen/Cargo.toml": ("stwo", "stwo-constraint-framework"),
    }
    for manifest, dependencies in native_manifests.items():
        for dependency in dependencies:
            errors.extend(
                _check_manifest_dependency(
                    root,
                    manifest,
                    dependency,
                    ledger.native_repository,
                    ledger.native_revision,
                )
            )
        errors.extend(
            _check_lock_sources(
                root,
                str(Path(manifest).with_name("Cargo.lock")),
                ledger.native_repository,
                ledger.native_revision,
            )
        )

    errors.extend(_check_blake_oracle_source(root, ledger))
    errors.extend(_check_official_cairo_manifest(root, ledger))
    errors.extend(
        check_official_cairo_vectors(
            root,
            cairo_repository=ledger.official_cairo_repository,
            cairo_revision=ledger.official_cairo_revision,
            stwo_repository=ledger.official_cairo_stwo_repository,
            stwo_revision=ledger.official_cairo_stwo_revision,
        )
    )
    official_lock = "tools/stwo-cairo-official-verifier-rs/Cargo.lock"
    errors.extend(
        _check_lock_source(
            root,
            official_lock,
            ledger.official_cairo_repository,
            ledger.official_cairo_revision,
            ledger.official_cairo_revision,
        )
    )
    errors.extend(
        _check_lock_source(
            root,
            official_lock,
            ledger.official_cairo_stwo_repository,
            ledger.official_cairo_stwo_revision[:8],
            ledger.official_cairo_stwo_revision,
        )
    )
    errors.extend(_check_cairo_manifest(root, ledger))
    cairo_lock = "tools/stwo-cairo-verifier-rs/Cargo.lock"
    errors.extend(
        _check_lock_sources(root, cairo_lock, ledger.cairo_repository, ledger.cairo_revision)
    )
    errors.extend(
        _check_lock_sources(
            root,
            cairo_lock,
            ledger.cairo_stwo_repository,
            ledger.cairo_stwo_revision,
        )
    )
    errors.extend(_check_cairo_trace_oracle_manifest(root, ledger))
    trace_lock = "tools/stwo-cairo-trace-oracle/Cargo.lock"
    errors.extend(
        _check_lock_sources(root, trace_lock, ledger.cairo_repository, ledger.cairo_revision)
    )
    errors.extend(_check_replaced_lock_sources(root, trace_lock, ledger))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--ledger", type=Path, help="override ledger path")
    args = parser.parse_args(argv)

    errors = validate_repository(args.root.resolve(), args.ledger)
    if errors:
        print("upstream pin validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("upstream pin ledger matches all Native, Stark-V, and Cairo carriers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
