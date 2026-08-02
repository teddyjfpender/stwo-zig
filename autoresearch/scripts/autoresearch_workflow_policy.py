#!/usr/bin/env python3
"""Trusted tree and verdict policy for autoresearch judge workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SUBMISSION_PREFIX = "autoresearch/submissions/"


class PolicyError(RuntimeError):
    """The candidate or unsigned verdict does not match trusted authority."""


def _git(repo: Path, *args: str) -> bytes:
    process = subprocess.run(["git", *args], cwd=repo, capture_output=True)
    if process.returncode != 0:
        detail = process.stderr.decode(errors="replace").strip()
        raise PolicyError(f"git {' '.join(args)} failed: {detail}")
    return process.stdout


def _commit(repo: Path, ref: str) -> str:
    commit = _git(repo, "rev-parse", f"{ref}^{{commit}}").decode().strip()
    if not HEX40_RE.fullmatch(commit):
        raise PolicyError(f"cannot resolve a full commit for {ref!r}")
    return commit


def _mode(repo: Path, commit: str, path: str) -> str | None:
    record = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not record:
        return None
    return record.split(b"\t", 1)[0].decode().split(" ", 1)[0]


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def inspect_candidate(
    repo: Path,
    authority_root: Path,
    base_ref: str,
    candidate_ref: str,
) -> dict:
    """Validate one submission candidate using policy loaded from trusted base."""
    sys.path.insert(0, str(authority_root / "autoresearch" / "cli"))
    from stwo_perf import manifest as manifest_mod  # pylint: disable=import-outside-toplevel

    manifest = manifest_mod.load(authority_root)
    base = _commit(repo, base_ref)
    candidate = _commit(repo, candidate_ref)
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, candidate],
        cwd=repo,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise PolicyError("candidate is not descended from the pull-request base")

    raw_paths = _git(
        repo, "diff", "--name-only", "-z", "--no-renames", base, candidate,
    )
    paths = sorted(path.decode() for path in raw_paths.split(b"\0") if path)
    if not paths:
        raise PolicyError("candidate has no changes from the pull-request base")

    unsafe = [
        path for path in paths
        if path.startswith("/")
        or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        or any(ord(character) < 32 or ord(character) > 126 for character in path)
    ]
    if unsafe:
        raise PolicyError(f"candidate contains unsafe path names: {unsafe[:10]}")

    submission_ids = {
        Path(path).parts[2]
        for path in paths
        if path.startswith(SUBMISSION_PREFIX) and len(Path(path).parts) > 3
    }
    if len(submission_ids) != 1:
        raise PolicyError(
            "candidate must change exactly one autoresearch submission directory"
        )
    submission_id = submission_ids.pop()
    submission_root = f"{SUBMISSION_PREFIX}{submission_id}/"
    if _git(repo, "ls-tree", "-r", "--name-only", base, "--", submission_root):
        raise PolicyError("candidate modifies an existing submission directory")

    policy = manifest.raw.get("qualification_policy", {})
    max_paths = int(policy.get("max_changed_paths", 100))
    if len(paths) > max_paths:
        raise PolicyError(
            f"candidate changes {len(paths)} paths; policy limit is {max_paths}"
        )
    governed_paths = [path for path in paths if not path.startswith(submission_root)]
    locked, stray = manifest.classify_touched(governed_paths)
    if locked:
        raise PolicyError(f"locked paths changed: {locked[:10]}")
    if stray:
        raise PolicyError(f"paths outside the editable set changed: {stray[:10]}")

    for path in paths:
        before = _mode(repo, base, path)
        after = _mode(repo, candidate, path)
        if before is not None and after is not None and before != after:
            raise PolicyError(f"file mode changed for {path}: {before} -> {after}")
        if after is not None and after != "100644":
            raise PolicyError(f"candidate path is not a regular non-executable file: {path}")

    required = ("note.md", "verdict.json", "delta.json")
    candidate_names = set(
        _git(repo, "ls-tree", "-r", "--name-only", candidate, "--", submission_root)
        .decode()
        .splitlines()
    )
    missing = [name for name in required if submission_root + name not in candidate_names]
    if missing:
        raise PolicyError(f"submission is missing required files: {missing}")

    patch = _git(
        repo, "diff", "--binary", "--full-index", "--no-renames", base, candidate,
    )
    max_patch_bytes = int(policy.get("max_patch_bytes", 5 * 1024 * 1024))
    if len(patch) > max_patch_bytes:
        raise PolicyError(
            f"candidate patch is {len(patch)} bytes; policy limit is {max_patch_bytes}"
        )
    receipt = {
        "schema": "autoresearch_judge_preflight_v1",
        "base_commit": base,
        "candidate_commit": candidate,
        "candidate_tree": _git(repo, "rev-parse", f"{candidate}^{{tree}}").decode().strip(),
        "submission_id": submission_id,
        "changed_paths": paths,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def validate_receipt(receipt: dict) -> None:
    if receipt.get("schema") != "autoresearch_judge_preflight_v1":
        raise PolicyError("preflight receipt schema is unsupported")
    for key in ("base_commit", "candidate_commit", "candidate_tree"):
        if not HEX40_RE.fullmatch(str(receipt.get(key, ""))):
            raise PolicyError(f"preflight {key} is not full lowercase hex")
    expected = dict(receipt)
    digest = expected.pop("receipt_sha256", None)
    if not re.fullmatch(r"[0-9a-f]{64}", str(digest or "")):
        raise PolicyError("preflight receipt digest is missing")
    if hashlib.sha256(_canonical(expected)).hexdigest() != digest:
        raise PolicyError("preflight receipt digest mismatches")


def finalize_verdict(unsigned_path: Path, receipt: dict, output_path: Path) -> None:
    """Bind the measured verdict to preflight identity, then HMAC-sign it."""
    validate_receipt(receipt)
    verdict = json.loads(unsigned_path.read_text(encoding="utf-8"))
    if verdict.get("kind") != "judged":
        raise PolicyError("unsigned verdict is not a judged result")
    bindings = {
        "repo_commit": receipt["candidate_commit"][:12],
        "predecessor_commit": receipt["base_commit"][:12],
        "submission_id": receipt["submission_id"],
    }
    for key, expected in bindings.items():
        if verdict.get(key) != expected:
            raise PolicyError(f"unsigned verdict {key} does not match preflight")

    verdict.pop("judge_signature", None)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
    from stwo_perf import signing  # pylint: disable=import-outside-toplevel

    signed = signing.sign(verdict)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--repo", type=Path, required=True)
    inspect.add_argument("--authority-root", type=Path, required=True)
    inspect.add_argument("--base", required=True)
    inspect.add_argument("--candidate", required=True)
    inspect.add_argument("--out", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo", type=Path, required=True)
    verify.add_argument("--authority-root", type=Path, required=True)
    verify.add_argument("--base", required=True)
    verify.add_argument("--candidate", required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--unsigned", type=Path, required=True)
    finalize.add_argument("--receipt", type=Path, required=True)
    finalize.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.command in ("inspect", "verify"):
        actual = inspect_candidate(
            args.repo.resolve(), args.authority_root.resolve(), args.base, args.candidate,
        )
        if args.command == "inspect":
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        else:
            recorded = json.loads(args.receipt.read_text(encoding="utf-8"))
            validate_receipt(recorded)
            if recorded != actual:
                raise PolicyError("preflight receipt does not match authority recomputation")
        return 0

    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    finalize_verdict(args.unsigned, receipt, args.out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PolicyError) as error:
        raise SystemExit(f"autoresearch workflow policy: {error}") from error
