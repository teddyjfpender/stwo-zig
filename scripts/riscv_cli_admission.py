"""Derive RISC-V proof admission from an installed CLI registry.

Runtime tooling must ask the exact executable it is about to invoke. Source
files and branch names are not admission authorities and can disagree with a
stale or externally supplied binary.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ADAPTER = "sail-rv32im-zkvm-elf"
AIR = "sail_rv32im_zkvm_v1"
ISA = "rv32im"
# Focused-registry product identity per selectable backend. Intentionally
# duplicated rather than imported from the CSP contract module: this module is
# a standalone admission authority and must not depend on benchmark code.
PRODUCT_NAMES = {"cpu": "stwo-riscv-cpu", "metal": "stwo-riscv-metal"}
MAX_REGISTRY_BYTES = 1 << 20
AGGREGATE_FIELDS = {
    "schema_version", "backend_availability", "product_matrix",
    "applications", "deferred_adapters",
}
FOCUSED_FIELDS = {
    "schema_version", "product", "backend_availability", "applications",
    "deferred_adapters", "guest_profiles",
}
FOCUSED_PRODUCT_FIELDS = {
    "schema_version", "name", "frontend", "backend", "role",
    "protocol_features", "protocol_manifest_sha256", "identity_sha256",
    "source", "zig_version", "target", "optimize", "runtime",
}
GUEST_PROFILE_FIELDS = {
    "profile", "version", "capability", "manifest_sha256", "status",
    "caller_component", "provider_component", "execution_placement",
    "runtime_requirement", "pcs_policies", "prove_command", "verify_command",
    "backend_fallback_allowed", "verification_requires_metal_device",
}


class AdmissionError(ValueError):
    """The CLI did not publish one canonical RISC-V admission state."""


@dataclass(frozen=True)
class Admission:
    phase: str
    release_status: str
    experimental: bool

    @property
    def arguments(self) -> tuple[str, ...]:
        return ("--experimental",) if self.experimental else ()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError(f"applications registry repeats JSON field {key!r}")
        result[key] = value
    return result


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AdmissionError(
            f"{label} fields drifted "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def parse(raw: bytes | str, *, backend: str = "cpu") -> Admission:
    """Parse an aggregate or focused CLI `applications` output, failing closed."""
    if backend not in PRODUCT_NAMES:
        raise AdmissionError(f"unknown RISC-V admission backend {backend!r}")
    if isinstance(raw, bytes):
        if len(raw) > MAX_REGISTRY_BYTES:
            raise AdmissionError("applications registry output is oversized")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdmissionError("applications registry is not UTF-8") from error
    elif len(raw.encode("utf-8")) > MAX_REGISTRY_BYTES:
        raise AdmissionError("applications registry output is oversized")
    try:
        root = json.loads(raw, object_pairs_hook=_strict_object)
    except json.JSONDecodeError as error:
        raise AdmissionError(f"applications registry is not valid JSON: {error}") from error
    if not isinstance(root, dict):
        raise AdmissionError("applications registry root is not an object")
    root_fields = set(root)
    focused = root_fields == FOCUSED_FIELDS
    if focused:
        product = root["product"]
        if not isinstance(product, dict):
            raise AdmissionError("focused applications registry product is not an object")
        _exact_fields(product, FOCUSED_PRODUCT_FIELDS, "focused RISC-V product")
        expected_product = {
            "name": PRODUCT_NAMES[backend],
            "frontend": "sail-rv32im-zkvm",
            "backend": backend,
        }
        if any(product.get(field) != value for field, value in expected_product.items()):
            raise AdmissionError("focused RISC-V product identity drifted")
        availability = root["backend_availability"]
        if availability != {backend: True}:
            raise AdmissionError("focused RISC-V backend availability drifted")
        profiles = root["guest_profiles"]
        if not isinstance(profiles, list) or len(profiles) != 1:
            raise AdmissionError("focused RISC-V guest-profile inventory drifted")
        profile = profiles[0]
        if not isinstance(profile, dict):
            raise AdmissionError("focused RISC-V guest profile is not an object")
        _exact_fields(profile, GUEST_PROFILE_FIELDS, "focused RISC-V guest profile")
        fixed_profile = {
            "profile": "rv32im-zkvm-poseidon2-v1",
            "version": 1,
            "status": "parity_gated",
            "caller_component": "riscv_guest_poseidon2_caller_v1",
            "provider_component": "riscv_guest_poseidon2_provider_v1",
            "pcs_policies": ["secure", "functional-development"],
            "backend_fallback_allowed": False,
            "verification_requires_metal_device": False,
        }
        if any(profile.get(name) != value for name, value in fixed_profile.items()):
            raise AdmissionError("focused RISC-V guest profile identity drifted")
        for name in (
            "capability", "manifest_sha256", "execution_placement",
            "runtime_requirement", "prove_command", "verify_command",
        ):
            if not isinstance(profile.get(name), str) or not profile[name]:
                raise AdmissionError("focused RISC-V guest profile authority is incomplete")
    elif root_fields == AGGREGATE_FIELDS:
        if backend != "cpu":
            raise AdmissionError(
                f"{backend} admission requires the focused product registry"
            )
        availability = root["backend_availability"]
        if (
            not isinstance(availability, dict)
            or set(availability) != {"cpu", "metal-hybrid"}
            or availability.get("cpu") is not True
            or not isinstance(availability.get("metal-hybrid"), bool)
            or not isinstance(root["product_matrix"], dict)
        ):
            raise AdmissionError("aggregate backend/product registry drifted")
    else:
        expected = FOCUSED_FIELDS if "product" in root else AGGREGATE_FIELDS
        _exact_fields(root, expected, "applications registry")
    if root["schema_version"] != 1:
        raise AdmissionError("applications registry schema is not version 1")
    applications = root["applications"]
    deferred = root["deferred_adapters"]
    if not isinstance(applications, list) or not isinstance(deferred, list):
        raise AdmissionError("applications registry adapter collections are not arrays")
    if any(not isinstance(entry, dict) for entry in [*applications, *deferred]):
        raise AdmissionError("applications registry contains a non-object entry")

    released = [entry for entry in applications if entry.get("adapter") == ADAPTER]
    staged = [entry for entry in deferred if entry.get("adapter") == ADAPTER]
    if len(released) + len(staged) != 1:
        raise AdmissionError("applications registry must contain exactly one RISC-V adapter")
    if released:
        entry = released[0]
        _exact_fields(entry, {"adapter", "air", "status", "isa", "backends"}, "RISC-V application")
        if entry != {
            "adapter": ADAPTER,
            "air": AIR,
            "status": "release_gated",
            "isa": ISA,
            "backends": [backend],
        }:
            raise AdmissionError("released RISC-V application declaration drifted")
        return Admission("promoted", "release_gated", False)

    entry = staged[0]
    expected_fields = {"adapter", "status", "isa", "backends", "reason"}
    if focused:
        expected_fields.add("air")
    _exact_fields(
        entry,
        expected_fields,
        "deferred RISC-V adapter",
    )
    reason = entry.get("reason")
    if (
        entry.get("status") != "not_release_gated"
        or (focused and entry.get("air") != AIR)
        or entry.get("isa") != ISA
        or entry.get("backends") != [backend]
        or not isinstance(reason, str)
        or not reason.strip()
    ):
        raise AdmissionError("deferred RISC-V adapter declaration drifted")
    return Admission("candidate", "not_release_gated", True)


def resolve(
    cli: Path,
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 30,
    backend: str = "cpu",
) -> Admission:
    """Resolve admission from `cli applications` with no ambient output."""
    try:
        completed = subprocess.run(
            [str(cli), "applications"],
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AdmissionError(f"cannot execute applications registry: {error}") from error
    if completed.returncode != 0:
        raise AdmissionError(
            f"applications registry command exited {completed.returncode}"
        )
    if completed.stderr:
        raise AdmissionError("applications registry command wrote unexpected stderr")
    return parse(completed.stdout, backend=backend)
