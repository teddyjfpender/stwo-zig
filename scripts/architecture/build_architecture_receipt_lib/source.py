"""Repository, host, and toolchain identities for architecture receipts."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, sha256_bytes
from .model import ReceiptError, require_hex40


def _git(root: Path, *args: str, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReceiptError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def dirty_content(root: Path) -> tuple[bool, str]:
    digest = hashlib.sha256()
    diff = _git(root, "diff", "--binary", "HEAD", "--", binary=True)
    assert isinstance(diff, bytes)
    digest.update(len(diff).to_bytes(8, "big"))
    digest.update(diff)
    untracked = _git(
        root, "ls-files", "--others", "--exclude-standard", "-z", binary=True,
    )
    assert isinstance(untracked, bytes)
    paths = sorted(item for item in untracked.split(b"\0") if item)
    for raw_path in paths:
        try:
            relative = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReceiptError("untracked path is not UTF-8") from error
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ReceiptError(f"unsupported untracked evidence path: {relative}")
        content = path.read_bytes()
        for value in (raw_path, content):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return bool(diff or paths), digest.hexdigest()


def source_identity(root: Path, candidate: str | None, repository: str) -> dict[str, Any]:
    head = str(_git(root, "rev-parse", "--verify", "HEAD"))
    require_hex40(head, "repository HEAD")
    if candidate is not None and candidate != head:
        raise ReceiptError(f"candidate {candidate} does not match repository HEAD {head}")
    tree = str(_git(root, "rev-parse", "--verify", f"{head}^{{tree}}"))
    require_hex40(tree, "repository tree")
    dirty, dirty_sha256 = dirty_content(root)
    return {
        "repository": repository,
        "commit": head,
        "tree": tree,
        "clean": not dirty,
        "dirty_content_sha256": dirty_sha256,
    }


def _command_version(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError:
        return "unavailable"
    if result.returncode != 0:
        return "unavailable"
    return (result.stdout or result.stderr).strip() or "unavailable"


def host_identity(role: str) -> dict[str, Any]:
    raw = {
        "role": role,
        "os": "macos" if sys.platform == "darwin" else sys.platform,
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "runner_name": os.environ.get("RUNNER_NAME", "local"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT", "local"),
    }
    return {**raw, "identity_sha256": sha256_bytes(canonical_bytes(raw))}


def toolchain_identity() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "zig": _command_version(["zig", "version"]),
        "rustc": _command_version(["rustc", "--version"]),
    }
