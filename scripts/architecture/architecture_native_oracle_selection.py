#!/usr/bin/env python3
"""Select one authenticated Native oracle producer job and immutable artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"^[0-9a-f]{40}$")
ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = "teddyjfpender/stwo-zig"
REPOSITORY_ID = 1152389958
OWNER_ID = 92999717
WORKFLOW_PATH = ".github/workflows/native-oracle.yml"


class SelectionError(ValueError):
    pass


def _strict(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SelectionError(f"duplicate producer metadata key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise SelectionError("producer API metadata is not an object")
    return value


def select(
    *, role: str, run: dict[str, Any], jobs: dict[str, Any],
    artifacts: dict[str, Any], authority_commit: str, authority_root: Path,
) -> dict[str, Any]:
    if role not in {"linux", "macos"} or HEX40.fullmatch(authority_commit) is None:
        raise SelectionError("Native oracle selection identity is invalid")
    if (
        run.get("path") != WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != authority_commit
        or run.get("repository", {}).get("full_name") != REPOSITORY
        or run.get("repository", {}).get("id") != REPOSITORY_ID
        or run.get("actor", {}).get("id") != OWNER_ID
        or run.get("triggering_actor", {}).get("id") != OWNER_ID
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise SelectionError("Native oracle producer run is outside the authority boundary")
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    if (
        not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0
        or not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt <= 0
    ):
        raise SelectionError("Native oracle producer run identity is malformed")
    expected_job_name = f"Native oracle producer ({role})"
    matched_jobs = [
        job for job in jobs.get("jobs", [])
        if isinstance(job, dict)
        and job.get("name") == expected_job_name
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("run_id") == run_id
        and job.get("run_attempt") == run_attempt
        and job.get("head_sha") == authority_commit
    ]
    if len(matched_jobs) != 1:
        raise SelectionError("Native oracle producer job is not uniquely successful")
    expected_name = f"native-oracle-{role}-{authority_commit}-{run_id}-{run_attempt}"
    matched_artifacts = [
        artifact for artifact in artifacts.get("artifacts", [])
        if isinstance(artifact, dict)
        and artifact.get("name") == expected_name
        and artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == run_id
        and artifact.get("workflow_run", {}).get("head_sha") == authority_commit
    ]
    if len(matched_artifacts) != 1:
        raise SelectionError("Native oracle artifact is not uniquely live for the producer run")
    artifact = matched_artifacts[0]
    artifact_id = artifact.get("id")
    artifact_digest = artifact.get("digest")
    if (
        not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id <= 0
        or not isinstance(artifact_digest, str)
        or ARTIFACT_DIGEST.fullmatch(artifact_digest) is None
    ):
        raise SelectionError("Native oracle artifact identity is malformed")
    workflow = authority_root.resolve() / WORKFLOW_PATH
    if not workflow.is_file() or workflow.is_symlink():
        raise SelectionError("Native oracle authority workflow is missing or unsafe")
    tree = run.get("head_commit", {}).get("tree_id")
    if not isinstance(tree, str) or HEX40.fullmatch(tree) is None:
        raise SelectionError("Native oracle producer tree identity is missing")
    producer = {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "candidate": authority_commit,
        "tree": tree,
        "workflow_sha": authority_commit,
        "workflow_path": WORKFLOW_PATH,
        "workflow_definition_sha256": hashlib.sha256(workflow.read_bytes()).hexdigest(),
        "producer_job": f"native-oracle-producer-{role}",
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    return {
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "artifact_name": expected_name,
        "producer": producer,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("linux", "macos"), required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--jobs", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = select(
            role=args.role, run=_strict(args.run), jobs=_strict(args.jobs),
            artifacts=_strict(args.artifacts), authority_commit=args.authority_commit,
            authority_root=args.authority_root,
        )
        args.output.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, UnicodeError, json.JSONDecodeError, SelectionError) as error:
        print(f"Native oracle producer selection: FAIL: {error}", file=sys.stderr)
        return 2
    print("Native oracle producer selection: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
