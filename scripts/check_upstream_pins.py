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


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "conformance" / "upstream.md"
REVISION_RE = r"[0-9a-f]{40}"


class PinLedgerError(ValueError):
    """The checked-in upstream ledger is missing or ambiguous."""


@dataclasses.dataclass(frozen=True)
class PinLedger:
    native_repository: str
    native_revision: str
    riscv_sail_repository: str
    riscv_sail_revision: str
    riscv_sail_compiler_version: str
    riscv_spike_repository: str
    riscv_spike_revision: str
    riscv_arch_test_repository: str
    riscv_arch_test_revision: str
    riscv_legacy_repository: str
    riscv_legacy_revision: str
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
        riscv_sail_repository=_single_field(
            text, r"^- Sail RISC-V repository: `([^`]+)`$", "Sail RISC-V repository"
        ),
        riscv_sail_revision=_single_field(
            text,
            rf"^- Pinned Sail RISC-V commit: `({REVISION_RE})`$",
            "Sail RISC-V revision",
        ),
        riscv_sail_compiler_version=_single_field(
            text,
            r"^- Pinned Sail compiler version: `([^`]+)`$",
            "Sail compiler version",
        ),
        riscv_spike_repository=_single_field(
            text, r"^- Spike repository: `([^`]+)`$", "Spike repository"
        ),
        riscv_spike_revision=_single_field(
            text,
            rf"^- Pinned Spike commit: `({REVISION_RE})`$",
            "Spike revision",
        ),
        riscv_arch_test_repository=_single_field(
            text,
            r"^- RISC-V Architectural Tests repository: `([^`]+)`$",
            "RISC-V Architectural Tests repository",
        ),
        riscv_arch_test_revision=_single_field(
            text,
            rf"^- Pinned RISC-V Architectural Tests commit: `({REVISION_RE})`$",
            "RISC-V Architectural Tests revision",
        ),
        riscv_legacy_repository=_single_field(
            text,
            r"^- Legacy Stark-V repository: `([^`]+)`$",
            "legacy Stark-V repository",
        ),
        riscv_legacy_revision=_single_field(
            text,
            rf"^- Pinned legacy Stark-V commit: `({REVISION_RE})`$",
            "legacy Stark-V revision",
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


def _check_riscv_formal_profile(root: Path, ledger: PinLedger) -> list[str]:
    relative_path = "conformance/riscv/rv32im-sail-profile.json"
    try:
        profile = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: unable to parse formal profile: {error}"]

    if not isinstance(profile, dict):
        return [f"{relative_path}: formal profile must be a JSON object"]
    authorities = profile.get("authorities")
    legacy = profile.get("legacy_protocol_layout")
    transport = profile.get("rvfi_transport")
    if (
        not isinstance(authorities, dict)
        or not isinstance(legacy, dict)
        or not isinstance(transport, dict)
    ):
        return [f"{relative_path}: missing authority objects"]

    expected_authorities = {
        ("sail", "repository"): ledger.riscv_sail_repository,
        ("sail", "revision"): ledger.riscv_sail_revision,
        ("sail", "compiler"): ledger.riscv_sail_compiler_version,
        ("spike", "repository"): ledger.riscv_spike_repository,
        ("spike", "revision"): ledger.riscv_spike_revision,
        ("riscv_arch_test", "repository"): ledger.riscv_arch_test_repository,
        ("riscv_arch_test", "revision"): ledger.riscv_arch_test_revision,
    }
    errors: list[str] = []
    expected_decode_exclusions = [
        {
            "instruction": "FENCE.I",
            "word": 0x0000_100F,
            "reason": "Zifencei is outside the proof profile",
            "pinned_sail_disposition": (
                "retires despite extensions.Zifencei.supported=false"
            ),
        }
    ]
    if profile.get("isa", {}).get("decode_exclusions") != expected_decode_exclusions:
        errors.append(
            f"{relative_path}: ISA decode exclusions are not the audited closed set"
        )
    for (authority, field), expected in expected_authorities.items():
        value = authorities.get(authority)
        actual = value.get(field) if isinstance(value, dict) else None
        if actual != expected:
            errors.append(
                f"{relative_path}: authorities.{authority}.{field} is "
                f"{actual!r}, expected {expected!r}"
            )

    for field, expected in (
        ("repository", ledger.riscv_legacy_repository),
        ("revision", ledger.riscv_legacy_revision),
        ("semantic_authority", False),
    ):
        if legacy.get(field) != expected:
            errors.append(
                f"{relative_path}: legacy_protocol_layout.{field} is "
                f"{legacy.get(field)!r}, expected {expected!r}"
            )

    sail = authorities.get("sail")
    if isinstance(sail, dict):
        expected_overrides = [
            "conformance/riscv/sail-rv32im-override.json",
            "conformance/riscv/sail-rv32im-tagged-options.json",
        ]
        if sail.get("configuration_overrides_in_order") != expected_overrides:
            errors.append(
                f"{relative_path}: Sail configuration override order is not canonical"
            )
        if sail.get("validated_isa_string") != "rv32im":
            errors.append(f"{relative_path}: Sail validated ISA string must be 'rv32im'")
        for override in expected_overrides:
            path = root / override
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                errors.append(f"{override}: unable to parse Sail override: {error}")
                continue
            if not isinstance(payload, dict):
                errors.append(f"{override}: Sail override must be a JSON object")

    expected_transport = {
        "protocol": "RVFI-DII v1",
        "entry_point": 0x0001_0000,
        "upstream_entry_point": 0x8000_0000,
        "scope": "c_emulator harness entry only; Sail ISA model sources are unchanged",
    }
    for field, expected in expected_transport.items():
        if transport.get(field) != expected:
            errors.append(
                f"{relative_path}: rvfi_transport.{field} is "
                f"{transport.get(field)!r}, expected {expected!r}"
            )

    patch = transport.get("patch")
    expected_patch_path = "conformance/riscv/sail-rvfi-zkvm-entry.patch"
    if not isinstance(patch, dict):
        errors.append(f"{relative_path}: rvfi_transport.patch must be an object")
    else:
        patch_path = patch.get("path")
        patch_sha256 = patch.get("sha256")
        if patch_path != expected_patch_path:
            errors.append(
                f"{relative_path}: rvfi_transport.patch.path is "
                f"{patch_path!r}, expected {expected_patch_path!r}"
            )
        if not isinstance(patch_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", patch_sha256
        ):
            errors.append(
                f"{relative_path}: rvfi_transport.patch.sha256 is not a lowercase SHA-256"
            )
        else:
            try:
                actual_patch_sha256 = hashlib.sha256(
                    (root / expected_patch_path).read_bytes()
                ).hexdigest()
            except OSError as error:
                errors.append(f"{expected_patch_path}: unable to read patch: {error}")
            else:
                if patch_sha256 != actual_patch_sha256:
                    errors.append(
                        f"{expected_patch_path}: SHA-256 is {actual_patch_sha256}, "
                        f"profile expects {patch_sha256}"
                    )
            errors.extend(
                _check_text_pin(
                    root,
                    TextPin(
                        "scripts/riscv_equivalence.py",
                        "RVFI transport patch SHA-256",
                        r'^PINNED_RVFI_TRANSPORT_PATCH_SHA256 = \(\n    "([0-9a-f]{64})"\n\)$',
                        patch_sha256,
                    ),
                )
            )

    try:
        equivalence_source = (root / "scripts/riscv_equivalence.py").read_text(
            encoding="utf-8"
        )
    except OSError as error:
        errors.append(f"scripts/riscv_equivalence.py: unable to read RVFI entry: {error}")
    else:
        entries = re.findall(
            r"^RVFI_DII_ENTRY = (0x[0-9A-Fa-f_]+)$",
            equivalence_source,
            flags=re.MULTILINE,
        )
        if len(entries) != 1:
            errors.append(
                "scripts/riscv_equivalence.py: expected exactly one RVFI_DII_ENTRY"
            )
        elif int(entries[0].replace("_", ""), 16) != transport.get("entry_point"):
            errors.append(
                "scripts/riscv_equivalence.py: RVFI_DII_ENTRY disagrees with "
                f"{relative_path}"
            )
    return errors


def _text_pins(ledger: PinLedger) -> tuple[TextPin, ...]:
    native = ledger.native_revision
    legacy_riscv = ledger.riscv_legacy_revision
    cairo = ledger.cairo_revision
    cairo_stwo = ledger.cairo_stwo_revision
    return (
        TextPin(
            "scripts/riscv_equivalence.py",
            "Sail PINNED_SAIL_REVISION",
            rf'^PINNED_SAIL_REVISION = "({REVISION_RE})"$',
            ledger.riscv_sail_revision,
        ),
        TextPin(
            "scripts/riscv_equivalence.py",
            "Spike PINNED_SPIKE_REVISION",
            rf'^PINNED_SPIKE_REVISION = "({REVISION_RE})"$',
            ledger.riscv_spike_revision,
        ),
        TextPin(
            "scripts/riscv_equivalence.py",
            "Sail compiler version",
            r'^PINNED_SAIL_COMPILER_VERSION = "([^"]+)"$',
            ledger.riscv_sail_compiler_version,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "Sail repository",
            r'^pub const sail_repository = "([^"]+)";$',
            ledger.riscv_sail_repository,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "Sail revision",
            rf'^pub const sail_revision = "({REVISION_RE})";$',
            ledger.riscv_sail_revision,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "Sail compiler version",
            r'^pub const sail_compiler_version = "([^"]+)";$',
            ledger.riscv_sail_compiler_version,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "Spike repository",
            r'^pub const spike_repository = "([^"]+)";$',
            ledger.riscv_spike_repository,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "Spike revision",
            rf'^pub const spike_revision = "({REVISION_RE})";$',
            ledger.riscv_spike_revision,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "architecture-test repository",
            r'^pub const arch_test_repository = "([^"]+)";$',
            ledger.riscv_arch_test_repository,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "architecture-test revision",
            rf'^pub const arch_test_revision = "({REVISION_RE})";$',
            ledger.riscv_arch_test_revision,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "legacy Stark-V repository",
            r'^pub const legacy_stark_v_repository = "([^"]+)";$',
            ledger.riscv_legacy_repository,
        ),
        TextPin(
            "src/frontends/riscv/isa/authority.zig",
            "legacy Stark-V revision",
            rf'^pub const legacy_stark_v_revision = "({REVISION_RE})";$',
            legacy_riscv,
        ),
        TextPin(
            "src/frontends/riscv/opcode_manifest.zig",
            "Sail semantic-authority revision",
            rf'^pub const semantic_authority_revision = "({REVISION_RE})";$',
            ledger.riscv_sail_revision,
        ),
        TextPin(
            "src/frontends/riscv/opcode_manifest.zig",
            "legacy Stark-V protocol revision",
            rf'^pub const legacy_layout_revision = "({REVISION_RE})";$',
            legacy_riscv,
        ),
        TextPin(
            "vectors/riscv_elfs/trace_vectors.json",
            "legacy Stark-V trace-layout provenance commit",
            rf'^ "legacy_protocol_layout": \{{\n'
            rf'  "repository": "[^"]+",\n'
            rf'  "revision": "({REVISION_RE})",$',
            legacy_riscv,
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
            "claim-generator Stwo-Cairo revision",
            rf'^PINNED_STWO_CAIRO_REVISION = "({REVISION_RE})"$',
            cairo,
        ),
        TextPin(
            "scripts/generate_cairo_claim_registry.py",
            "claim-generator Stwo revision",
            rf'^PINNED_STWO_REVISION = "({REVISION_RE})"$',
            cairo_stwo,
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
            "src/frontends/cairo/claim_registry.zig",
            "generated claim-registry Stwo-Cairo revision",
            rf'^    \.stwo_cairo = "({REVISION_RE})",$',
            cairo,
        ),
        TextPin(
            "src/frontends/cairo/claim_registry.zig",
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

    errors.extend(_check_riscv_formal_profile(root, ledger))

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
    print(
        "upstream pin ledger matches all Native, RISC-V formal/legacy, and Cairo carriers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
