"""Fork-qualification receipts and exact git-tree policy verification."""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest, ManifestError

SCHEMA_VERSION = 1
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REQUIRED_CHECKS = (
    "allowed_diff",
    "locked_tree",
    "source_modes",
    "harness_tests",
    "release_build",
    "public_benchmark",
)


class QualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TreeEvidence:
    candidate_commit: str
    frontier_commit: str
    candidate_tree: str
    changed_paths: list[str]
    patch_bytes: int
    patch_digest: str
    locked_tree_digest: str


def _git(repo: Path, *args: str, check: bool = True) -> bytes:
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True,
    )
    if check and proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip()
        raise QualificationError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def _commit(repo: Path, ref: str) -> str:
    value = _git(repo, "rev-parse", f"{ref}^{{commit}}").decode().strip()
    if not HEX40_RE.fullmatch(value):
        raise QualificationError(f"cannot resolve full commit for {ref!r}")
    return value


def _mode(repo: Path, commit: str, path: str) -> str | None:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not raw:
        return None
    head = raw.split(b"\t", 1)[0].decode()
    return head.split(" ", 1)[0]


def _locked_digest(repo: Path, manifest: Manifest, commit: str) -> str:
    entries = []
    raw = _git(repo, "ls-tree", "-r", "-z", commit)
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path_raw = record.split(b"\t", 1)
        path = path_raw.decode(errors="strict")
        if manifest.is_locked(path):
            entries.append(meta + b"\t" + path_raw + b"\0")
    return "sha256:" + hashlib.sha256(b"".join(entries)).hexdigest()


def inspect_tree(
    repo: Path,
    manifest: Manifest,
    frontier_ref: str,
    candidate_ref: str = "HEAD",
    *,
    board: str | None = None,
) -> TreeEvidence:
    frontier = _commit(repo, frontier_ref)
    candidate = _commit(repo, candidate_ref)
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", frontier, candidate], cwd=repo,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise QualificationError("candidate is not descended from the declared frontier")

    raw_paths = _git(
        repo, "diff", "--name-only", "-z", "--no-renames", frontier, candidate,
    )
    paths = sorted(p.decode() for p in raw_paths.split(b"\0") if p)
    if not paths:
        raise QualificationError("candidate has no changes from the frontier")
    policy = manifest.raw.get("qualification_policy", {})
    max_paths = int(policy.get("max_changed_paths", 100))
    if len(paths) > max_paths:
        raise QualificationError(
            f"candidate changes {len(paths)} paths; policy limit is {max_paths}"
        )
    unsafe = [
        path for path in paths
        if path.startswith("/") or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        or any(ord(ch) < 32 or ord(ch) > 126 for ch in path)
    ]
    if unsafe:
        raise QualificationError(f"candidate contains unsafe path names: {unsafe[:10]}")
    violations, strays = manifest.classify_touched(paths, board=board)
    if violations:
        raise QualificationError(f"locked paths changed: {violations[:10]}")
    if strays:
        raise QualificationError(f"paths outside the editable set changed: {strays[:10]}")

    for path in paths:
        before = _mode(repo, frontier, path)
        after = _mode(repo, candidate, path)
        if before is not None and after is not None and before != after:
            raise QualificationError(f"file mode changed for {path}: {before} -> {after}")
        if after is not None and after != "100644":
            raise QualificationError(f"candidate path is not a regular non-executable file: {path}")

    frontier_locked = _locked_digest(repo, manifest, frontier)
    candidate_locked = _locked_digest(repo, manifest, candidate)
    if frontier_locked != candidate_locked:
        raise QualificationError("locked-tree digest changed")
    patch = _git(
        repo, "diff", "--binary", "--full-index", "--no-renames", frontier, candidate,
    )
    max_patch_bytes = int(policy.get("max_patch_bytes", 5 * 1024 * 1024))
    if len(patch) > max_patch_bytes:
        raise QualificationError(
            f"candidate patch is {len(patch)} bytes; policy limit is {max_patch_bytes}"
        )
    tree = _git(repo, "rev-parse", f"{candidate}^{{tree}}").decode().strip()
    return TreeEvidence(
        candidate_commit=candidate,
        frontier_commit=frontier,
        candidate_tree=tree,
        changed_paths=paths,
        patch_bytes=len(patch),
        patch_digest="sha256:" + hashlib.sha256(patch).hexdigest(),
        locked_tree_digest=candidate_locked,
    )


def build_receipt(
    repo: Path,
    manifest: Manifest,
    frontier_ref: str,
    submitter_login: str,
    checks: dict[str, bool],
    claim: dict,
    workflow: dict | None = None,
    *,
    board: str | None = None,
) -> dict:
    policy_checks = manifest.raw.get("qualification_policy", {}).get("required_checks")
    if policy_checks is not None and set(policy_checks) != set(REQUIRED_CHECKS):
        raise QualificationError(
            "manifest qualification checks disagree with the receipt implementation"
        )
    claim_board = claim.get("board")
    if board is not None and board != claim_board:
        raise QualificationError(
            "qualification source-policy board does not match the claimed board"
        )
    evidence = inspect_tree(
        repo,
        manifest,
        frontier_ref,
        board=board if board is not None else claim_board,
    )
    missing = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
    if missing:
        raise QualificationError(f"qualification checks not proven green: {missing}")
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_commit": evidence.candidate_commit,
        "frontier_commit": evidence.frontier_commit,
        "candidate_tree": evidence.candidate_tree,
        "changed_paths": evidence.changed_paths,
        "patch_bytes": evidence.patch_bytes,
        "patch_digest": evidence.patch_digest,
        "locked_tree_digest": evidence.locked_tree_digest,
        "submitter_login": submitter_login,
        "checks": {name: bool(checks[name]) for name in REQUIRED_CHECKS},
        "claim": claim,
        "workflow": workflow or {},
    }


def validate_receipt(receipt: dict, manifest: Manifest) -> None:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != SCHEMA_VERSION:
        raise QualificationError(f"qualification schema_version must be {SCHEMA_VERSION}")
    for key in ("candidate_commit", "frontier_commit", "candidate_tree"):
        value = receipt.get(key)
        if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
            raise QualificationError(f"qualification {key} must be full lowercase 40-hex")
    for key in ("patch_digest", "locked_tree_digest"):
        value = receipt.get(key)
        if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
            raise QualificationError(f"qualification {key} is invalid")
    paths = receipt.get("changed_paths")
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
        raise QualificationError("qualification changed_paths must be a non-empty list")
    if not isinstance(receipt.get("patch_bytes"), int) or receipt["patch_bytes"] <= 0:
        raise QualificationError("qualification patch_bytes must be a positive integer")
    checks = receipt.get("checks")
    if not isinstance(checks, dict):
        raise QualificationError("qualification checks must be an object")
    missing = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
    if missing:
        raise QualificationError(f"qualification checks not green: {missing}")
    login = receipt.get("submitter_login")
    if not isinstance(login, str) or not LOGIN_RE.fullmatch(login):
        raise QualificationError("qualification submitter_login is invalid")
    claim = receipt.get("claim")
    if not isinstance(claim, dict):
        raise QualificationError("qualification claim must be an object")
    try:
        manifest.validate_workload_class(
            claim.get("workload_class"),
            board=claim.get("board"),
            include_disabled=False,
        )
    except ManifestError as exc:
        raise QualificationError(
            f"qualification claim has an invalid workload_class: {exc}"
        ) from exc
    if claim.get("dimension") not in ("time", "rss", "energy"):
        raise QualificationError("qualification claim has an invalid dimension")
    if not isinstance(claim.get("board"), str) or not claim["board"]:
        raise QualificationError("qualification claim has an invalid board")
    score = claim.get("shipping_index")
    if (not isinstance(score, (int, float)) or isinstance(score, bool)
            or not math.isfinite(score) or score <= 0):
        raise QualificationError("qualification claim has an invalid shipping_index")
    if not isinstance(receipt.get("workflow"), dict):
        raise QualificationError("qualification workflow must be an object")


def verify_receipt(repo: Path, manifest: Manifest, receipt: dict) -> TreeEvidence:
    """Recompute all git evidence; never trust a fork receipt's pass booleans."""
    validate_receipt(receipt, manifest)
    evidence = inspect_tree(
        repo,
        manifest,
        receipt["frontier_commit"],
        receipt["candidate_commit"],
        board=receipt["claim"]["board"],
    )
    comparisons = {
        "candidate_tree": evidence.candidate_tree,
        "changed_paths": evidence.changed_paths,
        "patch_bytes": evidence.patch_bytes,
        "patch_digest": evidence.patch_digest,
        "locked_tree_digest": evidence.locked_tree_digest,
    }
    for key, actual in comparisons.items():
        if receipt.get(key) != actual:
            raise QualificationError(f"qualification {key} does not match candidate tree")
    return evidence


def receipt_digest(receipt: dict) -> str:
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()
