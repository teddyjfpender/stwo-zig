"""Pinned CuMetal checkout and compatibility-patch authentication."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


AUDITED_COMMIT = "e88dd103bddaff9a134913dec4bd8439817d160c"
AUDITED_VERSION = "0.1.3"
PATCHED_FILES = frozenset(
    {
        "compiler/passes/src/intrinsic_lower.cpp",
        "compiler/ptx/src/lower_to_llvm.cpp",
        "compiler/ptx/src/parser.cpp",
        "runtime/registration/registration.cpp",
    }
)


class CuMetalToolchainError(RuntimeError):
    """The CuMetal source/toolchain identity is not the supported profile."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        input=input_text,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git(checkout: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return _run(["git", "-C", str(checkout), *arguments])


def _patch_id(contents: str) -> str:
    result = _run(["git", "patch-id", "--stable"], input_text=contents)
    fields = result.stdout.split()
    if result.returncode != 0 or not fields:
        raise CuMetalToolchainError(
            f"cannot authenticate CuMetal compatibility patch: {result.stderr.strip()}"
        )
    return fields[0]


def verify_checkout(
    checkout: Path,
    patch: Path,
    *,
    allow_unpatched: bool = False,
) -> dict[str, object]:
    """Verify the exact base commit and either an exact patch or a clean tree."""

    checkout = checkout.resolve()
    patch = patch.resolve()
    if not patch.is_file():
        raise CuMetalToolchainError(f"CuMetal compatibility patch is absent: {patch}")
    head = _git(checkout, "rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() != AUDITED_COMMIT:
        raise CuMetalToolchainError(
            f"CuMetal checkout must be pinned to {AUDITED_COMMIT}"
        )
    staged = _git(checkout, "diff", "--cached", "--quiet")
    if staged.returncode != 0:
        raise CuMetalToolchainError("CuMetal checkout contains staged changes")
    untracked = _git(
        checkout,
        "ls-files",
        "--others",
        "--exclude-standard",
    )
    if untracked.returncode != 0 or untracked.stdout.strip():
        raise CuMetalToolchainError("CuMetal checkout contains untracked files")
    names = _git(checkout, "diff", "--name-only")
    if names.returncode != 0:
        raise CuMetalToolchainError("cannot inspect CuMetal checkout changes")
    changed = frozenset(filter(None, names.stdout.splitlines()))
    patch_contents = patch.read_text(encoding="utf-8")
    expected_patch_id = _patch_id(patch_contents)
    if not changed:
        if not allow_unpatched:
            raise CuMetalToolchainError(
                "CuMetal compatibility patch is not applied; run "
                "scripts/cuda_cumetal_toolchain.py --apply"
            )
        return {
            "commit": AUDITED_COMMIT,
            "version": AUDITED_VERSION,
            "patched": False,
            "patch_sha256": sha256_file(patch),
            "patch_id": expected_patch_id,
        }
    if changed != PATCHED_FILES:
        extras = ", ".join(sorted(changed ^ PATCHED_FILES))
        raise CuMetalToolchainError(
            f"CuMetal checkout differs outside the supported patch: {extras}"
        )
    actual = _git(checkout, "diff", "--binary", "--full-index")
    if actual.returncode != 0 or _patch_id(actual.stdout) != expected_patch_id:
        raise CuMetalToolchainError(
            "CuMetal checkout changes do not equal the authenticated patch"
        )
    return {
        "commit": AUDITED_COMMIT,
        "version": AUDITED_VERSION,
        "patched": True,
        "patch_sha256": sha256_file(patch),
        "patch_id": expected_patch_id,
    }


def apply_compatibility_patch(checkout: Path, patch: Path) -> dict[str, object]:
    """Apply the authenticated patch only to an exact, clean base checkout."""

    verify_checkout(checkout, patch, allow_unpatched=True)
    names = _git(checkout, "diff", "--name-only")
    if names.stdout.strip():
        return verify_checkout(checkout, patch)
    checked = _git(checkout, "apply", "--check", str(patch.resolve()))
    if checked.returncode != 0:
        raise CuMetalToolchainError(
            f"CuMetal patch does not apply: {checked.stderr.strip()}"
        )
    applied = _git(checkout, "apply", str(patch.resolve()))
    if applied.returncode != 0:
        raise CuMetalToolchainError(
            f"cannot apply CuMetal patch: {applied.stderr.strip()}"
        )
    return verify_checkout(checkout, patch)
