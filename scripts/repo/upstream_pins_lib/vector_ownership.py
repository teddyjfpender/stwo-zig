"""Authenticate the live vector inventory without regenerating its contents."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

MANIFEST = "vectors/MANIFEST.json"
KINDS = {"golden_fixture", "guest_source", "retained_contract_fixture"}


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def vector_path(root: Path, name) -> Path | None:
    if not isinstance(name, str):
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or path.as_posix() != name or not name.startswith("vectors/"):
        return None
    candidate = root / name
    if candidate.is_symlink() or not candidate.resolve().is_relative_to((root / "vectors").resolve()):
        return None
    return candidate


def check(root: Path) -> list[str]:
    try:
        manifest = json.loads((root / MANIFEST).read_text(), object_pairs_hook=strict_pairs)
        if manifest.get("schema") != "stwo-zig-vectors-manifest-v1":
            return ["unsupported vector manifest schema"]
        groups, rows = manifest["groups"], manifest["files"]
        if not isinstance(groups, dict) or not isinstance(rows, list):
            return ["invalid vector inventory"]
        owners = {json.loads(p.read_text())["owner"] for p in root.glob("src/**/package.contract.json")}
        tracked = set(subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "vectors"],
            cwd=root,
        ).decode().rstrip("\0").split("\0")) - {"", MANIFEST}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        return [f"vector inventory unavailable: {error}"]
    errors, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            errors.append("invalid vector inventory row")
            continue
        name = row.get("path")
        path = vector_path(root, name)
        if path is None:
            errors.append(f"invalid vector path: {name}")
            continue
        if name in seen:
            errors.append(f"duplicate vector: {name}")
        seen.add(name)
        matching = [g for g in groups if name == g or name.startswith(g + "/")]
        group = row.get("group")
        if group not in groups:
            errors.append(f"unknown group for {name}")
        elif not matching or group != max(matching, key=len):
            errors.append(f"noncanonical group for {name}")
        if not path.is_file():
            errors.append(f"missing vector: {name}")
            continue
        data = path.read_bytes()
        if len(data) != row.get("bytes") or hashlib.sha256(data).hexdigest() != row.get("sha256"):
            errors.append(f"vector identity drift: {name}")
    for group, spec in groups.items():
        if vector_path(root, group) is None or not isinstance(spec, dict):
            errors.append(f"invalid vector group: {group}")
            continue
        if spec.get("owner") not in owners:
            errors.append(f"undeclared owner for {group}")
        if spec.get("kind") not in KINDS:
            errors.append(f"invalid vector retention kind for {group}")
        actual = sum(p == group or p.startswith(group + "/") for p in seen)
        if type(spec.get("files")) is not int or spec["files"] != actual:
            errors.append(f"vector group count drift: {group}")
    errors.extend(f"unlisted vector: {p}" for p in sorted(tracked - seen))
    errors.extend(f"untracked vector admission: {p}" for p in sorted(seen - tracked))
    return errors
