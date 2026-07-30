#!/usr/bin/env python3
"""Fork-CI qualification: reject forbidden diffs and emit a bound receipt."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "autoresearch" / "cli"))
from stwo_perf import manifest as manifest_mod, qualification  # noqa: E402


def _claim(verdict: dict) -> dict:
    objective = verdict.get("declared_objective", {})
    score = verdict.get("score", {}).get("R_geomean")
    return {
        "board": objective.get("board"),
        "workload_class": objective.get("workload_class"),
        "dimension": objective.get("dimension"),
        "shipping_index": score,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", required=True, help="full canonical frontier commit")
    parser.add_argument("--board", help="board whose editable-path policy applies")
    parser.add_argument("--preflight", action="store_true",
                        help="only enforce tree/path/mode policy")
    parser.add_argument("--verdict", help="claimed verdict emitted by stwo-perf run")
    parser.add_argument("--login", help="GitHub submitter login (defaults to GITHUB_ACTOR)")
    parser.add_argument("--out", help="receipt output path")
    args = parser.parse_args()

    manifest = manifest_mod.load(Path.cwd())
    evidence = qualification.inspect_tree(
        manifest.root,
        manifest,
        args.frontier,
        board=args.board,
    )
    print(
        f"qualified source policy: {evidence.candidate_commit[:12]} descends from "
        f"{evidence.frontier_commit[:12]}; {len(evidence.changed_paths)} editable path(s)"
    )
    if args.preflight:
        return 0
    if not args.verdict or not args.out:
        parser.error("--verdict and --out are required unless --preflight is used")
    verdict = json.loads(Path(args.verdict).read_text())
    if verdict.get("kind") != "claimed":
        raise SystemExit("qualification verdict must be kind=claimed")
    if verdict.get("repo_commit") != evidence.candidate_commit[:12]:
        raise SystemExit("claimed verdict was not produced for the candidate commit")
    workflow = {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
    }
    receipt = qualification.build_receipt(
        manifest.root, manifest, evidence.frontier_commit,
        args.login or os.environ.get("GITHUB_ACTOR", ""),
        {name: True for name in qualification.REQUIRED_CHECKS},
        _claim(verdict), workflow,
        board=args.board,
    )
    qualification.validate_receipt(receipt, manifest)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"qualification receipt: {out} ({qualification.receipt_digest(receipt)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
