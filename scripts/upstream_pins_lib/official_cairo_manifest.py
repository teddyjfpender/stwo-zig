"""Manifest authority check for the official Cairo proof verifier."""

from __future__ import annotations

import tomllib
from pathlib import Path

from .model import PinLedger


def check(root: Path, ledger: PinLedger) -> list[str]:
    relative_path = "tools/stwo-cairo-official-verifier-rs/Cargo.toml"
    try:
        with (root / relative_path).open("rb") as handle:
            manifest = tomllib.load(handle)
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
