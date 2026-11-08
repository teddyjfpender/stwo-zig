"""Validate raw bundle identity and resolve artifact references."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .codec import content_digest, sha256_file, strict_json
from .model import (
    EvidenceError,
    RAW_BUNDLE_SCHEMA,
    exact_object,
    require_hex,
    require_int,
    require_relative_path,
    require_string,
)


ARTIFACT_FIELDS = {"id", "path", "kind", "sha256", "bytes"}
BUNDLE_FIELDS = {"schema", "schema_version", "artifacts", "content_sha256"}


def validate_bundle(
    value: object,
    raw_root: Path,
    protocol: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    bundle = exact_object(value, BUNDLE_FIELDS, "raw bundle")
    if bundle["schema"] != RAW_BUNDLE_SCHEMA or bundle["schema_version"] != 1:
        raise EvidenceError("raw bundle schema is unsupported")
    require_hex(bundle["content_sha256"], 64, "raw bundle digest")
    if bundle["content_sha256"] != content_digest(bundle):
        raise EvidenceError("raw bundle digest mismatch")
    artifacts = bundle["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise EvidenceError("raw bundle must contain artifacts")
    if len(artifacts) > protocol["limits"]["max_artifacts"]:
        raise EvidenceError("raw bundle has too many artifacts")
    root = raw_root.resolve()
    result: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    allowed_kinds = set(protocol["artifact_kinds"])
    for index, item in enumerate(artifacts):
        artifact = exact_object(item, ARTIFACT_FIELDS, f"artifact[{index}]")
        identifier = require_string(artifact["id"], f"artifact[{index}].id")
        if identifier in result:
            raise EvidenceError("artifact IDs must be unique")
        relative = require_relative_path(artifact["path"], f"artifact[{index}].path")
        if relative in paths:
            raise EvidenceError("artifact paths must be unique")
        if artifact["kind"] not in allowed_kinds:
            raise EvidenceError("artifact kind is unsupported")
        require_hex(artifact["sha256"], 64, f"artifact[{index}].sha256")
        size = require_int(artifact["bytes"], f"artifact[{index}].bytes")
        if size > protocol["limits"]["max_artifact_bytes"]:
            raise EvidenceError("artifact exceeds its byte limit")
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise EvidenceError("artifact path escapes raw bundle")
        try:
            stat = path.lstat()
        except OSError as error:
            raise EvidenceError(f"artifact is missing: {relative}") from error
        if not path.is_file() or os.path.islink(path):
            raise EvidenceError(f"artifact is not a regular file: {relative}")
        if stat.st_size != size or sha256_file(path) != artifact["sha256"]:
            raise EvidenceError(f"artifact identity mismatch: {relative}")
        result[identifier] = artifact
        paths.add(relative)
    return result


def require_artifact(
    artifacts: dict[str, dict[str, Any]],
    identifier: object,
    kind: str,
    label: str,
) -> dict[str, Any]:
    name = require_string(identifier, label)
    artifact = artifacts.get(name)
    if artifact is None or artifact["kind"] != kind:
        raise EvidenceError(f"{label} does not reference a {kind} artifact")
    return artifact


def validate_attempt_ledger(
    raw_root: Path,
    artifact: dict[str, Any],
    attempts: list[dict[str, Any]],
    max_bytes: int,
) -> None:
    value = strict_json(raw_root / artifact["path"], max_bytes)
    exact_object(value, {"schema", "attempts"}, "attempt ledger")
    if value["schema"] != "build-monorepo-performance-attempt-ledger-v1":
        raise EvidenceError("attempt ledger schema is unsupported")
    if value["attempts"] != attempts:
        raise EvidenceError("attempt ledger and receipt attempts differ")


def validate_attempt_journal(
    raw_root: Path,
    artifact: dict[str, Any],
    attempts: list[dict[str, Any]],
) -> None:
    try:
        lines = (raw_root / artifact["path"]).read_bytes().splitlines(keepends=True)
    except OSError as error:
        raise EvidenceError("cannot read append-only attempt journal") from error
    if len(lines) != len(attempts):
        raise EvidenceError("attempt journal cardinality differs from receipt")
    from .codec import canonical_bytes
    if any(line != canonical_bytes(attempt) for line, attempt in zip(lines, attempts)):
        raise EvidenceError("attempt journal differs from receipt or is noncanonical")
