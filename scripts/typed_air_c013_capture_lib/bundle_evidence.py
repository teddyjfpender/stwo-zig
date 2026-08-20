"""Canonical file-graph primitives for independent C-013 validation."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_file,
)
from .model import CaptureError, DIGEST_RE


FILE_IDENTITY_FIELDS = {"path", "bytes", "sha256"}
MAX_JOURNAL_LINE_BYTES = 4 * 1024 * 1024
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def canonical_document(path: Path, name: str) -> tuple[dict[str, Any], bytes]:
    regular_file(path, name)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError(f"cannot read {name}: {path}") from error
    value = decode_strict(raw)
    if type(value) is not dict:
        raise CaptureError(f"{name} root must be an object")
    if raw != canonical_bytes(value):
        raise CaptureError(f"{name} is not canonical JSON")
    return value, raw


def regular_file(path: Path, name: str) -> None:
    try:
        if path.is_symlink() or not path.is_file():
            raise CaptureError(f"{name} must be a regular non-symlink file")
    except OSError as error:
        raise CaptureError(f"cannot inspect {name}: {path}") from error


def integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CaptureError(f"{name} must be an integer >= {minimum}")
    return value


def digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise CaptureError(f"{name} must be a lowercase SHA-256 digest")
    return value


def utc(value: Any, name: str) -> dt.datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise CaptureError(f"{name} must be canonical whole-second UTC")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        raise CaptureError(f"{name} is not a valid UTC timestamp") from error


def relative_path(value: Any, name: str) -> PurePosixPath:
    if type(value) is not str or not value or "\\" in value:
        raise CaptureError(f"{name} is not a normalized bundle-relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CaptureError(f"{name} is not a normalized bundle-relative path")
    return path


def file_identity(value: Any, name: str) -> dict[str, Any]:
    identity = exact_object(value, FILE_IDENTITY_FIELDS, name)
    relative_path(identity["path"], f"{name}.path")
    integer(identity["bytes"], f"{name}.bytes")
    digest(identity["sha256"], f"{name}.sha256")
    return identity


class EvidenceFiles:
    """Authenticate every claimed file and reject aliases, symlinks, and orphans."""

    def __init__(self, root: Path):
        if root.is_symlink() or not root.is_dir():
            raise CaptureError("capture bundle must be a non-symlink directory")
        self.root = root.resolve()
        self.claimed: dict[str, tuple[int, str]] = {}

    def bind_snapshot(self, relative: str, raw: bytes) -> None:
        """Bind a canonical root document that has no enclosing file identity."""
        relative_path(relative, "root evidence path")
        if relative in self.claimed:
            raise CaptureError(f"duplicate evidence path: {relative}")
        self.claimed[relative] = (len(raw), hashlib.sha256(raw).hexdigest())

    def claim(self, identity: dict[str, Any], name: str) -> Path:
        relative = relative_path(identity["path"], f"{name}.path").as_posix()
        if relative in self.claimed:
            raise CaptureError(f"duplicate evidence path: {relative}")
        parts = PurePosixPath(relative).parts
        target = self.root
        for index, part in enumerate(parts):
            target /= part
            if target.is_symlink():
                raise CaptureError(f"{name} path traverses a symlink")
            if index != len(parts) - 1 and not target.is_dir():
                raise CaptureError(f"{name} parent is not a directory")
        regular_file(target, name)
        size, actual_digest = sha256_file(target)
        expected = (
            integer(identity["bytes"], f"{name}.bytes"),
            digest(identity["sha256"], f"{name}.sha256"),
        )
        if (size, actual_digest) != expected:
            raise CaptureError(f"{name} byte count or SHA-256 mismatch")
        self.claimed[relative] = expected
        return target

    def finish(self) -> None:
        files: set[str] = set()
        directories: set[str] = set()
        for current, names, filenames in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            for name in names:
                child = current_path / name
                if child.is_symlink():
                    raise CaptureError(f"bundle contains a symlink: {child}")
                directories.add(child.relative_to(self.root).as_posix())
            for name in filenames:
                child = current_path / name
                regular_file(child, "bundle inventory entry")
                files.add(child.relative_to(self.root).as_posix())
        expected_files = set(self.claimed)
        if files != expected_files:
            raise CaptureError(
                "bundle file inventory drifted; "
                f"missing={sorted(expected_files - files)}, "
                f"unclaimed={sorted(files - expected_files)}"
            )
        if directories != {"attempts"}:
            raise CaptureError(
                "bundle directory inventory drifted; "
                f"expected=['attempts'], actual={sorted(directories)}"
            )
        for relative, expected in self.claimed.items():
            target = self.root.joinpath(*PurePosixPath(relative).parts)
            if sha256_file(target) != expected:
                raise CaptureError(f"evidence file changed during validation: {relative}")


def record_digest(record: dict[str, Any], name: str) -> None:
    digest(record.get("content_sha256"), f"{name}.content_sha256")
    if record["content_sha256"] != content_digest(record):
        raise CaptureError(f"{name} content digest mismatch")


def journal_records(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        with path.open("rb") as source:
            while True:
                raw = source.readline(MAX_JOURNAL_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_JOURNAL_LINE_BYTES or not raw.endswith(b"\n"):
                    raise CaptureError("journal record exceeds its limit or lacks newline")
                value = decode_strict(raw, maximum=MAX_JOURNAL_LINE_BYTES)
                if type(value) is not dict:
                    raise CaptureError("journal record root must be an object")
                if raw != canonical_bytes(value):
                    raise CaptureError("journal record is not canonical NDJSON")
                record_digest(value, f"journal record {len(result)}")
                result.append(value)
    except OSError as error:
        raise CaptureError("cannot read attempt journal") from error
    return result
