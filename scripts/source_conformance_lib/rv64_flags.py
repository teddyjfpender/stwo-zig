"""Declared RV64 environment switches and their generated source references.

Reference regeneration never declares a flag or changes its reviewed metadata.
The live-count target is a promotion gate, not a grandfathered source baseline.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path

from . import comments
from .common import EXCLUDED_DIRECTORY_NAMES

REGISTRY = Path("conformance/rv64-flags.json")
TOKEN = re.compile(r"\bSTWO_RV64_[A-Z0-9_]*[A-Z0-9]\b")
DEVICE_BUDGET_PREFIX = "STWO_RV64_" + "BUDGET_GUARD_BYTES_"
DEVICE_BUDGET_FAMILY = DEVICE_BUDGET_PREFIX + "{device}"
SUFFIXES = {".zig", ".py", ".sh", ".cu", ".cuh", ".c", ".cpp", ".h", ".hpp", ".rs", ".metal"}
LIVE = {"runtime", "qualification", "frozen", "retire-after-native-default"}
STATUSES = LIVE | {"constant", "reference-only"}


def references(repo: Path) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {}
    paths = [repo / "build.zig"]
    for directory in ("src", "scripts", "tests", "tools", "build", "build_support", ".github/workflows"):
        for base, dirs, files in os.walk(repo / directory):
            dirs[:] = sorted(set(dirs) - EXCLUDED_DIRECTORY_NAMES)
            paths.extend(Path(base) / name for name in sorted(files)
                         if Path(name).suffix in SUFFIXES | {".yml", ".yaml"})
    paths.extend(repo / "design/riscv-proving-stack/m7-handoff" / name for name in
                 ("default-runtime.json", "integration-stack-preset.json"))
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".zig":
            text = comments.strip_zig(text)
        elif path.suffix in {".cu", ".cuh", ".c", ".cpp", ".h", ".hpp", ".rs", ".metal"}:
            text = comments.strip_c(text)
        names = set(TOKEN.findall(text))
        names = {DEVICE_BUDGET_FAMILY if n.startswith(DEVICE_BUDGET_PREFIX) and n[len(DEVICE_BUDGET_PREFIX):].isdigit() else n for n in names}
        if DEVICE_BUDGET_PREFIX in text:
            names.add(DEVICE_BUDGET_FAMILY)
        for name in names:
            found.setdefault(name, set()).add(path.relative_to(repo).as_posix())
    return {name: sorted(paths) for name, paths in sorted(found.items())}


def load(repo: Path) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate flag registry key: {key}")
            result[key] = value
        return result
    payload = json.loads((repo / REGISTRY).read_text(), object_pairs_hook=unique)
    if payload.get("schema") != "rv64-flag-registry/v1" or not isinstance(payload.get("flags"), dict):
        raise ValueError("invalid RV64 flag registry schema")
    return payload


def check(repo: Path, *, refresh: bool = False, strict: bool = False) -> list[str]:
    actual = references(repo)
    if not actual and not (repo / REGISTRY).exists():
        return []
    try:
        payload = load(repo)
    except (OSError, ValueError, AttributeError) as error:
        return [f"RV64 flag registry: {error}"]
    declared = payload["flags"]
    errors = [f"undeclared RV64 flag: {name}" for name in actual.keys() - declared.keys()]
    errors += [f"stale RV64 flag declaration: {name}" for name in declared.keys() - actual.keys()]
    for name, entry in declared.items():
        if (not TOKEN.fullmatch(name) and name != DEVICE_BUDGET_FAMILY) or not isinstance(entry, dict):
            errors.append(f"invalid RV64 flag declaration: {name}")
            continue
        owner = entry.get("owner")
        if not isinstance(owner, str) or owner not in actual.get(name, []):
            errors.append(f"{name}: owner must be a current referencing source path")
        try:
            date = datetime.date.fromisoformat(entry.get("date", ""))
            if date > datetime.datetime.now(datetime.timezone.utc).date():
                raise ValueError("future date")
        except (ValueError, TypeError):
            errors.append(f"{name}: invalid review date")
        status = entry.get("status")
        if not isinstance(status, str) or status not in STATUSES or not isinstance(entry.get("default"), str) or not entry["default"].strip() or entry["default"] == "REVIEW_REQUIRED":
            errors.append(f"{name}: requires status and explicit unset default")
        if status in ("constant", "reference-only"):
            reader = re.compile(r"(?:getenv|getEnvVarOwned|hasEnvVarConstant)\([^\n;]*[\"']" + re.escape(name) + r"[\"']")
            if any(reader.search((repo / path).read_text()) for path in actual.get(name, [])):
                errors.append(f"{name}: an environment reader cannot be excluded from the live count")
        evidence = entry.get("default_evidence", {})
        if isinstance(status, str) and status in LIVE:
            if not isinstance(evidence, dict):
                errors.append(f"{name}: invalid default evidence")
                continue
            source, text = evidence.get("path"), evidence.get("text")
            if source not in actual.get(name, []) or not isinstance(text, str) or name.split("{")[0] not in text:
                errors.append(f"{name}: default needs a pinned source expression")
            elif text not in (repo / source).read_text():
                errors.append(f"{name}: default source expression changed; review its default")
        if refresh:
            entry["references"] = actual.get(name, [])
        elif entry.get("references") != actual.get(name, []):
            errors.append(f"{name}: stale generated references; use --update-rv64-flag-references")
    if strict:
        live = [name for name, e in declared.items() if isinstance(e, dict) and isinstance(e.get("status"), str) and e["status"] in LIVE]
        if len(live) >= 60:
            errors.append(f"RV64 live flag target not met: {len(live)} (required <60)")
        pending = [name for name in live if re.match(r"STWO_RV64_" + r"M[78]_", name)]
        if pending:
            errors.append(f"M7/M8 flags still require promotion or removal: {', '.join(sorted(pending))}")
    if refresh and not errors:
        (repo / REGISTRY).write_text(json.dumps(payload, indent=2) + "\n")
    return sorted(errors)
