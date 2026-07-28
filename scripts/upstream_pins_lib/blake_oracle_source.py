"""Bind the vendored Native Blake AIR oracle to its pinned source tree."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .model import PinLedger


def check(root: Path, ledger: PinLedger) -> list[str]:
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
