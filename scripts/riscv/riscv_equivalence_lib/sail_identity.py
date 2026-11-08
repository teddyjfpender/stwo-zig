"""Pinned Sail executable identity verification from the formal profile."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .contract import EquivalenceError

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "conformance" / "riscv" / "rv32im-sail-profile.json"


def verify_sail_binary(sail_bin: Path) -> dict[str, str]:
    """Fail closed unless the executable identifies the pinned model/toolchain."""
    profile = _load_profile()
    sail = profile["authorities"]["sail"]
    patch = profile["rvfi_transport"]["patch"]
    patch_path = ROOT / patch["path"]
    patch_sha256 = sha256_file(patch_path)
    if patch_sha256 != patch["sha256"]:
        raise EquivalenceError(
            f"{patch_path}: SHA-256 is {patch_sha256}, "
            f"expected {patch['sha256']}"
        )
    result = subprocess.run(
        [str(sail_bin), "--build-info"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    build_info = result.stdout + result.stderr
    expected = (
        f"Sail RISC-V git: {sail['tag']}",
        f"Sail: Sail {sail['compiler']} ",
    )
    missing = [line for line in expected if line not in build_info]
    if missing:
        raise EquivalenceError(
            f"{sail_bin}: build identity does not contain {missing!r}"
        )
    return {
        "repository_revision": sail["revision"],
        "model_tag": sail["tag"],
        "compiler_version": sail["compiler"],
        "binary_sha256": sha256_file(sail_bin),
        "transport_patch_sha256": patch_sha256,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    try:
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        sail = profile["authorities"]["sail"]
        patch = profile["rvfi_transport"]["patch"]
        if profile["schema"] != "stwo-riscv-formal-profile-v1":
            raise KeyError("schema")
        for field in ("revision", "tag", "compiler"):
            if not isinstance(sail[field], str) or not sail[field]:
                raise KeyError(f"authorities.sail.{field}")
        if not isinstance(patch["path"], str) or not isinstance(patch["sha256"], str):
            raise KeyError("rvfi_transport.patch")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise EquivalenceError(f"{PROFILE_PATH}: invalid formal profile: {error}") from error
    return profile
