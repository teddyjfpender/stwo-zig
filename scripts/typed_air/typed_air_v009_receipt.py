#!/usr/bin/env python3
"""Mint and replay the clean typed-AIR V-009 release receipt.

The receipt deliberately names an already-tested immutable commit.  The later
commit that adds the receipt is not made self-referential.  Hosted run records
are fetched from GitHub when minting, while replay is entirely local and binds
their immutable IDs together with every checked repository artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY = SCRIPT_DIR.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.typed_air_r006_capture_lib.codec import (  # noqa: E402
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_file,
    write_new,
)
from scripts.typed_air_r006_capture_lib.model import CaptureError  # noqa: E402


SCHEMA = "stwo.typed-air.v009-clean-release-receipt.v1"
SCHEMA_VERSION = 1
MILESTONE = "V-009"
CLASSIFICATION = "clean-immutable-typed-air-release-evidence"
REQUIRED_WORKFLOWS = {
    "CI",
    "RISC-V formal refinement",
    "RISC-V Sail differential",
    "RISC-V Sail formal provisioning",
}
REQUIRED_ARTIFACTS = (
    "design/typed-air/artifacts/m3-compat-v1/index-v1.tsv",
    "design/typed-air/artifacts/p003-work-profile-closure-v1/matrix-v1.json",
    "design/typed-air/artifacts/r006-csp-closeout-v1/receipt-v1.json",
    "design/typed-air/artifacts/recursive-temporal-parent-v1/receipt-v1.json",
    "formal/riscv-refinement/generated-manifest.json",
    "formal/riscv-refinement/refinement-receipt.json",
)
RECEIPT_FIELDS = {
    "artifacts",
    "claim_boundary",
    "classification",
    "content_sha256",
    "hosted_runs",
    "milestone",
    "recursion",
    "schema",
    "schema_version",
    "subject",
    "toolchain",
}
SUBJECT_FIELDS = {"branch", "commit", "tree", "worktree_clean"}
ARTIFACT_FIELDS = {"bytes", "path", "sha256"}
RUN_FIELDS = {"conclusion", "head_sha", "run_id", "url", "workflow"}
RECURSION_FIELDS = {
    "crossover",
    "leaf_count",
    "leaf_proof_bytes",
    "leaf_prove_us",
    "leaf_verify_us",
    "parent_count",
    "parent_proof_bytes",
    "parent_prove_us",
    "parent_verify_us",
    "peak_rss_bytes",
    "pipeline_prove_us",
    "pipeline_single_worker_work_us",
    "pipeline_verify_us",
    "process_wall_us",
    "protocol_id_words",
    "root_height",
    "root_proof_bytes",
    "root_prove_us",
    "root_proof_sha256",
    "root_verify_us",
    "target_security_bits",
    "temporal_parent_verified",
    "universal_typed_air_rows",
}
CLAIM_FIELDS = {
    "lookup_v2_default",
    "multilevel_recursive_aggregation_verified",
    "proof_system_soundness",
    "whole_frontend_verified",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MULTILEVEL = re.compile(
    rb"TEMPORAL_MULTILEVEL_REAL leaves=(\d+) verified_parents=(\d+) "
    rb"root_height=(\d+) parent_bytes=(\d+) root_bytes=(\d+) "
    rb"root_prove_ms=([0-9]+\.[0-9]+) root_verify_ms=([0-9]+\.[0-9]+) "
    rb"root_sha256=([0-9a-f]{64}) root_proof=true"
)
LEAF_PROOF = re.compile(
    rb"SEGMENT_V2_OUTER status=verified rows=(\d+) domains=(\d+) "
    rb"proof_size_estimate_bytes=\d+ canonical_proof_bytes=(\d+) "
    rb"canonicalize_ms=([0-9]+\.[0-9]+) prove_ms=([0-9]+\.[0-9]+) "
    rb"verify_ms=([0-9]+\.[0-9]+) publication_ms=([0-9]+\.[0-9]+) "
    rb"draws=\d+ cols=\d+/\d+/\d+ workers=(\d+)"
)
PARENT_PROOF = re.compile(
    rb"TEMPORAL_PARENT_REAL_PROOF bytes=(\d+) prove_ms=([0-9]+\.[0-9]+) "
    rb"verify_ms=([0-9]+\.[0-9]+) rows=(\d+) pair_poseidon=(\d+)"
)
MAX_RSS = re.compile(rb"(?m)^\s*(\d+)\s+maximum resident set size\s*$")
PROCESS_WALL = re.compile(rb"(?m)^\s*([0-9]+\.[0-9]+)\s+real(?:\s|$)")


class ReceiptError(CaptureError):
    """V-009 evidence is malformed or no longer reproducible."""


def _git(root: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise ReceiptError(f"git {' '.join(arguments)} failed") from error


def _tool_version(argv: list[str]) -> str:
    try:
        value = subprocess.run(
            argv, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError(f"cannot resolve tool version: {argv[0]}") from error
    if not value or "\n" in value:
        raise ReceiptError(f"noncanonical tool version: {argv[0]}")
    return value


def _require_digest(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ReceiptError(f"{label} must be canonical lowercase hex")
    return value


def _relative_artifact(root: Path, value: Any) -> Path:
    if type(value) is not str or not value or value.startswith("/"):
        raise ReceiptError("artifact path must be repository-relative")
    candidate = root / value
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ReceiptError(f"artifact escapes the repository: {value}") from error
    if candidate.is_symlink() or not resolved.is_file():
        raise ReceiptError(f"artifact must be a regular non-symlink file: {value}")
    return resolved


def _artifact_record(root: Path, relative: str) -> dict[str, Any]:
    path = _relative_artifact(root, relative)
    size, digest = sha256_file(path)
    return {"path": relative, "bytes": size, "sha256": digest}


def _github_run(run_id: str) -> dict[str, Any]:
    if not run_id.isdigit() or int(run_id) <= 0:
        raise ReceiptError("GitHub run ID must be a positive decimal integer")
    try:
        raw = subprocess.run(
            [
                "gh",
                "run",
                "view",
                run_id,
                "--json",
                "databaseId,headSha,status,conclusion,workflowName,url",
            ],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
        ).stdout
        value = decode_strict(raw)
    except (OSError, subprocess.CalledProcessError, CaptureError) as error:
        raise ReceiptError(f"cannot read GitHub run {run_id}") from error
    run = exact_object(
        value,
        {"conclusion", "databaseId", "headSha", "status", "url", "workflowName"},
        "GitHub run",
    )
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise ReceiptError(f"GitHub run {run_id} is not a completed success")
    return {
        "workflow": run["workflowName"],
        "run_id": run["databaseId"],
        "head_sha": run["headSha"],
        "conclusion": run["conclusion"],
        "url": run["url"],
    }


def _multilevel_record(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReceiptError(f"cannot read multilevel gate log: {path}") from error
    matches = MULTILEVEL.findall(raw)
    if len(matches) != 1:
        raise ReceiptError("multilevel gate log must contain exactly one terminal receipt")
    leaves, parents, height, parent_bytes, root_bytes, prove, verify, digest = matches[0]
    leaf_matches = LEAF_PROOF.findall(raw)
    parent_matches = PARENT_PROOF.findall(raw)
    rss_matches = MAX_RSS.findall(raw)
    wall_matches = PROCESS_WALL.findall(raw)
    if len(leaf_matches) != 4 or len(parent_matches) != 2:
        raise ReceiptError("multilevel gate log has incomplete leaf or parent evidence")
    if len(rss_matches) != 1 or len(wall_matches) != 1:
        raise ReceiptError("multilevel gate log has incomplete process resource evidence")

    leaf_bytes = [int(match[2]) for match in leaf_matches]
    leaf_prove_us = [_milliseconds_to_us(match[4]) for match in leaf_matches]
    leaf_verify_us = [_milliseconds_to_us(match[5]) for match in leaf_matches]
    parent_proof_bytes = [int(match[0]) for match in parent_matches]
    parent_prove_us = [_milliseconds_to_us(match[1]) for match in parent_matches]
    parent_verify_us = [_milliseconds_to_us(match[2]) for match in parent_matches]
    root_prove_us = _milliseconds_to_us(prove)
    root_verify_us = _milliseconds_to_us(verify)
    pipeline_prove_us = sum(leaf_prove_us) + sum(parent_prove_us) + root_prove_us
    pipeline_verify_us = sum(leaf_verify_us) + sum(parent_verify_us) + root_verify_us
    direct_leaf_bytes = sum(leaf_bytes)
    total_parent_bytes = sum(parent_proof_bytes)
    root_byte_count = int(root_bytes)
    if (
        any(int(match[0]) != 39 or int(match[1]) != 47 or int(match[7]) != 1
            for match in leaf_matches)
        or any(int(match[3]) != 36 or int(match[4]) != 0 for match in parent_matches)
        or int(parent_bytes) != total_parent_bytes
    ):
        raise ReceiptError("multilevel proof geometry or single-worker custody changed")
    return {
        "protocol_id_words": [
            369535897,
            1353874838,
            1147415759,
            568299296,
            1554543833,
            1672540135,
            1992443198,
            914248870,
        ],
        "target_security_bits": 120,
        "universal_typed_air_rows": 36,
        "leaf_count": int(leaves),
        "leaf_proof_bytes": leaf_bytes,
        "leaf_prove_us": leaf_prove_us,
        "leaf_verify_us": leaf_verify_us,
        "parent_count": int(parents),
        "parent_proof_bytes": parent_proof_bytes,
        "parent_prove_us": parent_prove_us,
        "parent_verify_us": parent_verify_us,
        "root_height": int(height),
        "root_proof_bytes": root_byte_count,
        "root_prove_us": root_prove_us,
        "root_verify_us": root_verify_us,
        "root_proof_sha256": digest.decode("ascii"),
        "pipeline_prove_us": pipeline_prove_us,
        "pipeline_verify_us": pipeline_verify_us,
        "pipeline_single_worker_work_us": pipeline_prove_us + pipeline_verify_us,
        "process_wall_us": _seconds_to_us(wall_matches[0]),
        "peak_rss_bytes": int(rss_matches[0]),
        "crossover": {
            "direct_leaf_proof_bytes": direct_leaf_bytes,
            "two_parent_proof_bytes": total_parent_bytes,
            "root_over_direct_leaf": {
                "numerator": root_byte_count,
                "denominator": direct_leaf_bytes,
            },
            "root_over_two_parent": {
                "numerator": root_byte_count,
                "denominator": total_parent_bytes,
            },
        },
        "temporal_parent_verified": True,
    }


def _milliseconds_to_us(value: bytes) -> int:
    whole, fraction = value.split(b".", 1)
    if len(fraction) != 3:
        raise ReceiptError("proof timing must have millisecond precision")
    return int(whole) * 1000 + int(fraction)


def _seconds_to_us(value: bytes) -> int:
    whole, fraction = value.split(b".", 1)
    if not 1 <= len(fraction) <= 6:
        raise ReceiptError("process timing precision is unsupported")
    return int(whole) * 1_000_000 + int(fraction.ljust(6, b"0"))


def mint_receipt(
    root: Path,
    subject: str,
    run_ids: Sequence[str],
    multilevel_log: Path,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReceiptError("V-009 mint requires a clean worktree")
    commit = _git(root, "rev-parse", subject)
    tree = _git(root, "rev-parse", f"{commit}^{{tree}}")
    branch = _git(root, "branch", "--show-current")
    if branch != "main":
        raise ReceiptError("V-009 must be minted from main")
    runs = sorted((_github_run(value) for value in run_ids), key=lambda item: item["workflow"])
    if {run["workflow"] for run in runs} != REQUIRED_WORKFLOWS:
        raise ReceiptError("V-009 hosted workflow set is incomplete or unexpected")
    if any(run["head_sha"] != commit for run in runs):
        raise ReceiptError("V-009 hosted run does not bind the subject commit")
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "milestone": MILESTONE,
        "classification": CLASSIFICATION,
        "subject": {
            "branch": branch,
            "commit": commit,
            "tree": tree,
            "worktree_clean": True,
        },
        "toolchain": {
            "zig": _tool_version(["zig", "version"]),
            "python": platform.python_version(),
            "host": f"{platform.system()}-{platform.machine()}",
        },
        "hosted_runs": runs,
        "artifacts": [_artifact_record(root, path) for path in REQUIRED_ARTIFACTS],
        "recursion": _multilevel_record(multilevel_log),
        "claim_boundary": {
            "lookup_v2_default": True,
            "multilevel_recursive_aggregation_verified": True,
            "whole_frontend_verified": False,
            "proof_system_soundness": False,
        },
    }
    result["content_sha256"] = content_digest(result)
    return validate_receipt_value(root, result, require_canonical=None)


def validate_receipt_value(
    root: Path,
    value: Any,
    *,
    require_canonical: bytes | None,
) -> dict[str, Any]:
    receipt = exact_object(value, RECEIPT_FIELDS, "V-009 receipt")
    if require_canonical is not None and canonical_bytes(receipt) != require_canonical:
        raise ReceiptError("V-009 receipt encoding is not canonical JSON")
    if (
        receipt["schema"] != SCHEMA
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["milestone"] != MILESTONE
        or receipt["classification"] != CLASSIFICATION
        or receipt["content_sha256"] != content_digest(receipt)
    ):
        raise ReceiptError("V-009 receipt authority changed")

    subject = exact_object(receipt["subject"], SUBJECT_FIELDS, "V-009 subject")
    commit = _require_digest(subject["commit"], "subject commit", HEX40)
    tree = _require_digest(subject["tree"], "subject tree", HEX40)
    if subject != {
        "branch": "main",
        "commit": commit,
        "tree": tree,
        "worktree_clean": True,
    }:
        raise ReceiptError("V-009 subject is not a clean main revision")
    if _git(root, "rev-parse", f"{commit}^{{tree}}") != tree:
        raise ReceiptError("V-009 commit/tree binding changed")

    toolchain = exact_object(
        receipt["toolchain"], {"host", "python", "zig"}, "V-009 toolchain"
    )
    if any(type(toolchain[key]) is not str or not toolchain[key] for key in toolchain):
        raise ReceiptError("V-009 toolchain is incomplete")

    runs = receipt["hosted_runs"]
    if type(runs) is not list or len(runs) != len(REQUIRED_WORKFLOWS):
        raise ReceiptError("V-009 hosted run count changed")
    workflows: set[str] = set()
    for raw_run in runs:
        run = exact_object(raw_run, RUN_FIELDS, "V-009 hosted run")
        if (
            type(run["workflow"]) is not str
            or run["workflow"] in workflows
            or type(run["run_id"]) is not int
            or run["run_id"] <= 0
            or run["head_sha"] != commit
            or run["conclusion"] != "success"
            or run["url"] != f"https://github.com/teddyjfpender/stwo-zig/actions/runs/{run['run_id']}"
        ):
            raise ReceiptError("V-009 hosted run binding changed")
        workflows.add(run["workflow"])
    if workflows != REQUIRED_WORKFLOWS:
        raise ReceiptError("V-009 hosted workflow set changed")

    artifacts = receipt["artifacts"]
    if type(artifacts) is not list or len(artifacts) != len(REQUIRED_ARTIFACTS):
        raise ReceiptError("V-009 artifact inventory changed")
    paths: list[str] = []
    for raw_artifact in artifacts:
        artifact = exact_object(raw_artifact, ARTIFACT_FIELDS, "V-009 artifact")
        path = artifact["path"]
        if type(path) is not str or path in paths:
            raise ReceiptError("V-009 artifact paths are duplicated or malformed")
        size, digest = sha256_file(_relative_artifact(root, path))
        if artifact["bytes"] != size or artifact["sha256"] != digest:
            raise ReceiptError(f"V-009 artifact identity changed: {path}")
        paths.append(path)
    if tuple(paths) != REQUIRED_ARTIFACTS:
        raise ReceiptError("V-009 artifact order changed")

    recursion = exact_object(receipt["recursion"], RECURSION_FIELDS, "V-009 recursion")
    if (
        recursion["protocol_id_words"] != [
            369535897,
            1353874838,
            1147415759,
            568299296,
            1554543833,
            1672540135,
            1992443198,
            914248870,
        ]
        or recursion["target_security_bits"] != 120
        or recursion["universal_typed_air_rows"] != 36
        or recursion["leaf_count"] != 4
        or recursion["parent_count"] != 2
        or recursion["root_height"] != 2
        or type(recursion["root_proof_bytes"]) is not int
        or recursion["root_proof_bytes"] <= 0
        or type(recursion["peak_rss_bytes"]) is not int
        or recursion["peak_rss_bytes"] <= 0
        or type(recursion["process_wall_us"]) is not int
        or recursion["process_wall_us"] <= 0
        or recursion["temporal_parent_verified"] is not True
    ):
        raise ReceiptError("V-009 recursion boundary changed")
    _require_digest(recursion["root_proof_sha256"], "root proof digest", HEX64)
    _validate_crossover(recursion)

    claims = exact_object(receipt["claim_boundary"], CLAIM_FIELDS, "V-009 claims")
    if claims != {
        "lookup_v2_default": True,
        "multilevel_recursive_aggregation_verified": True,
        "whole_frontend_verified": False,
        "proof_system_soundness": False,
    }:
        raise ReceiptError("V-009 claim boundary changed")
    return receipt


def _positive_int_list(value: Any, expected: int, label: str) -> list[int]:
    if (
        type(value) is not list
        or len(value) != expected
        or any(type(item) is not int or item <= 0 for item in value)
    ):
        raise ReceiptError(f"{label} must contain {expected} positive integers")
    return value


def _validate_ratio(value: Any, numerator: int, denominator: int, label: str) -> None:
    ratio = exact_object(value, {"denominator", "numerator"}, label)
    if ratio != {"numerator": numerator, "denominator": denominator}:
        raise ReceiptError(f"{label} changed")


def _validate_crossover(recursion: dict[str, Any]) -> None:
    leaf_bytes = _positive_int_list(recursion["leaf_proof_bytes"], 4, "leaf bytes")
    leaf_prove = _positive_int_list(recursion["leaf_prove_us"], 4, "leaf prove")
    leaf_verify = _positive_int_list(recursion["leaf_verify_us"], 4, "leaf verify")
    parent_bytes = _positive_int_list(recursion["parent_proof_bytes"], 2, "parent bytes")
    parent_prove = _positive_int_list(recursion["parent_prove_us"], 2, "parent prove")
    parent_verify = _positive_int_list(recursion["parent_verify_us"], 2, "parent verify")
    for name in ("root_prove_us", "root_verify_us", "pipeline_prove_us",
                 "pipeline_verify_us", "pipeline_single_worker_work_us"):
        if type(recursion[name]) is not int or recursion[name] <= 0:
            raise ReceiptError(f"{name} must be positive")
    expected_prove = sum(leaf_prove) + sum(parent_prove) + recursion["root_prove_us"]
    expected_verify = sum(leaf_verify) + sum(parent_verify) + recursion["root_verify_us"]
    if (
        recursion["pipeline_prove_us"] != expected_prove
        or recursion["pipeline_verify_us"] != expected_verify
        or recursion["pipeline_single_worker_work_us"] != expected_prove + expected_verify
    ):
        raise ReceiptError("recursive pipeline work accounting changed")
    crossover = exact_object(
        recursion["crossover"],
        {"direct_leaf_proof_bytes", "root_over_direct_leaf", "root_over_two_parent", "two_parent_proof_bytes"},
        "V-009 recursion crossover",
    )
    direct_bytes = sum(leaf_bytes)
    two_parent_bytes = sum(parent_bytes)
    if (
        crossover["direct_leaf_proof_bytes"] != direct_bytes
        or crossover["two_parent_proof_bytes"] != two_parent_bytes
        or two_parent_bytes <= recursion["root_proof_bytes"]
        or direct_bytes <= recursion["root_proof_bytes"]
    ):
        raise ReceiptError("recursive proof-size crossover changed")
    _validate_ratio(
        crossover["root_over_direct_leaf"],
        recursion["root_proof_bytes"],
        direct_bytes,
        "root/direct-leaf ratio",
    )
    _validate_ratio(
        crossover["root_over_two_parent"],
        recursion["root_proof_bytes"],
        two_parent_bytes,
        "root/two-parent ratio",
    )


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = decode_strict(raw)
    except (OSError, CaptureError) as error:
        raise ReceiptError(f"cannot read V-009 receipt {path}: {error}") from error
    return validate_receipt_value(root.resolve(strict=True), value, require_canonical=raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    commands = parser.add_subparsers(dest="command", required=True)
    mint = commands.add_parser("mint")
    mint.add_argument("--subject", default="HEAD")
    mint.add_argument("--github-run", action="append", required=True)
    mint.add_argument("--multilevel-log", type=Path, required=True)
    mint.add_argument("--output", type=Path, required=True)
    replay = commands.add_parser("validate")
    replay.add_argument("receipt", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "mint":
            if len(args.github_run) != len(REQUIRED_WORKFLOWS):
                raise ReceiptError("mint requires exactly four hosted run IDs")
            receipt = mint_receipt(
                args.repository,
                args.subject,
                args.github_run,
                args.multilevel_log,
            )
            write_new(args.output, canonical_bytes(receipt))
        else:
            receipt = validate_receipt(args.repository, args.receipt)
        print(
            canonical_bytes(
                {
                    "schema": SCHEMA,
                    "status": "VALID",
                    "content_sha256": receipt["content_sha256"],
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    except CaptureError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
