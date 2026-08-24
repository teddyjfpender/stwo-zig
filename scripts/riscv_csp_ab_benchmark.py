#!/usr/bin/env python3
"""Plan and run a fail-closed native EthProofs CSP old-vs-current A/B."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.riscv_csp_ab_benchmark_lib import contract, runner  # noqa: E402


def _evidence_path(path: Path, active: Path) -> Path:
    resolved = path.resolve()
    root = active.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return resolved
    completed = runner._run(  # The check is centralized with runner diagnostics.
        ["git", "check-ignore", "--quiet", "--no-index", "--", os.fspath(relative)],
        cwd=root,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise contract.ABError(
            "plan/artifact paths inside the active repository must be ignored; "
            "otherwise writing evidence would invalidate the source snapshot"
        )
    return resolved


def _summary(plan: dict) -> dict:
    return {
        "schema": plan["schema"],
        "status": plan["status"],
        "seal_sha256": plan["seal_sha256"],
        "baseline_commit": plan["arms"]["baseline"]["head"],
        "current_temporary_commit": plan["arms"]["current"]["head"],
        "current_active_content_sha256": plan["arms"]["current"][
            "source_content_sha256"
        ],
        "active_worktree_dirty": plan["arms"]["current"]["active_snapshot"][
            "active_worktree_dirty"
        ],
        "case_count": plan["workload"]["case_count"],
        "profile_count": plan["workload"]["profile_count"],
        "serial_launch_count": len(plan["schedule"]),
        "quiet_host_admissible": plan["publishable_preflight"]["admissible"],
        "quiet_host_reasons": plan["publishable_preflight"]["reasons"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    plan_parser = subcommands.add_parser("plan", help="seal the complete 16-case cohort")
    plan_parser.add_argument("--active-root", type=Path, default=ROOT)
    plan_parser.add_argument("--out", type=Path, required=True)
    plan_parser.add_argument("--rounds", type=int, default=2)
    plan_parser.add_argument("--warmups", type=int, default=1)
    plan_parser.add_argument("--samples", type=int, default=5)
    plan_parser.add_argument("--workers", type=int, required=True)
    plan_parser.add_argument("--timeout", type=int, default=3600)

    validate_parser = subcommands.add_parser("validate-plan", help="validate a sealed plan")
    validate_parser.add_argument("plan", type=Path)

    smoke_parser = subcommands.add_parser(
        "smoke", help="run one non-statistical sha256/128 proof per arm"
    )
    smoke_parser.add_argument("plan", type=Path)
    smoke_parser.add_argument("--artifacts", type=Path, required=True)
    smoke_parser.add_argument("--confirm-heavyweight", required=True)

    run_parser = subcommands.add_parser("run", help="run the complete sealed A/B cohort")
    run_parser.add_argument("plan", type=Path)
    run_parser.add_argument("--artifacts", type=Path, required=True)
    run_parser.add_argument("--confirm-heavyweight", required=True)
    run_parser.add_argument(
        "--allow-nonnormative-power",
        action="store_true",
        help=(
            "run the full cohort under captured battery/quiet conditions while "
            "forbidding a publishable performance claim"
        ),
    )

    args = parser.parse_args(argv)
    if args.command == "plan":
        active = runner.repository_root(args.active_root)
        output = _evidence_path(args.out, active)
        plan = runner.create_plan(
            active,
            rounds=args.rounds,
            warmups=args.warmups,
            samples=args.samples,
            workers=args.workers,
            timeout_seconds=args.timeout,
        )
        contract.write_new_json(output, plan)
        print(json.dumps(_summary(plan), indent=2, sort_keys=True))
        print(f"plan: {output}")
        return 0
    if args.command == "validate-plan":
        plan, _ = contract.load_json(args.plan.resolve())
        contract.validate_plan(plan)
        print(json.dumps(_summary(plan), indent=2, sort_keys=True))
        return 0

    plan, _ = contract.load_json(args.plan.resolve())
    contract.validate_plan(plan)
    active = runner.repository_root(Path(plan["active_repository"]))
    artifact = _evidence_path(args.artifacts, active)
    if args.command == "smoke":
        output = runner.execute_smoke(
            args.plan.resolve(),
            artifact,
            confirmation=args.confirm_heavyweight,
        )
    else:
        output = runner.execute_plan(
            args.plan.resolve(),
            artifact,
            confirmation=args.confirm_heavyweight,
            allow_nonnormative_power=args.allow_nonnormative_power,
        )
    print(f"report: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except contract.ABError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
