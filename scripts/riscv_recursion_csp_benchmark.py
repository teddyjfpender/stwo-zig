#!/usr/bin/env python3
"""Plan and measure legacy-native versus typed-recursive CSP proof work.

The canonical outer collector retains independently verified 36-row
verifier-subsystem artifacts, but keeps full recursive comparison unavailable
until the parent proof is production-active. This runner never substitutes
static cost ledgers, prose estimates, wrapper wall time, or
``num_constraints=0`` for end-to-end measurements.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.riscv_recursion_csp_benchmark_lib import (  # noqa: E402
    EvidenceError,
    atomic_write_new,
    build_comparison,
    build_plan,
    canonical_bytes,
    collect_active_outer_probe,
    collect_canonical_outer_report,
    collect_shape_audit,
    load_json,
    validate_plan,
    validate_active_outer_probe,
    validate_recursive_report,
    validate_shape_audit,
)


CURRENT_SOURCE_CAPTURE_GUIDANCE = """canonical recursive CSP comparison requires a fresh clean same-commit native cohort.
Prerequisite: `git status --porcelain=v1 --untracked-files=all` must print nothing.
Capture it with fresh output paths:
  zig build stwo-zig-riscv-cpu riscv-trace-dump riscv-recursion-csp-producer -Doptimize=ReleaseFast
  python3 scripts/riscv_csp_benchmark.py --backend cpu --cli zig-out/bin/stwo-zig-riscv-cpu --trace-cli zig-out/bin/riscv-trace-dump --report-out zig-out/riscv-csp-current-native.json
  python3 scripts/riscv_recursion_csp_benchmark.py plan --native-report zig-out/riscv-csp-current-native.json --output zig-out/riscv-recursion-current.plan.json
The report, plan, artifact directory, and final output paths must not already exist."""


def _has_source_alignment_failure(report: dict[str, object]) -> bool:
    source_errors = {
        "NativeMeasurementCommitMismatch",
        "DirtyProducerNotComparable",
        "PublicValuesDigestMismatch",
    }
    samples = report.get("samples")
    if type(samples) is not list:
        return False
    for sample in samples:
        if type(sample) is not dict or type(sample.get("attempts")) is not list:
            continue
        for attempt in sample["attempts"]:
            if type(attempt) is not dict or type(attempt.get("record")) is not dict:
                continue
            failure = attempt["record"].get("failure")
            if type(failure) is dict and failure.get("error_name") in source_errors:
                return True
    return False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    shape_audit = commands.add_parser(
        "audit-shapes",
        help="inspect exact recursion-profile coverage without constructing proofs",
    )
    shape_audit.add_argument(
        "--inspector",
        default=ROOT / "zig-out/bin/stwo-zig-riscv-recursion-shape-inspector",
        type=Path,
    )
    shape_audit.add_argument(
        "--manifest",
        default=ROOT / "vectors/riscv_csp/manifest-v2.json",
        type=Path,
    )
    shape_audit.add_argument(
        "--timeout-seconds",
        default=120,
        type=int,
    )
    shape_audit.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new sealed shape-audit path; an existing file is never replaced",
    )

    validate_shape = commands.add_parser(
        "validate-shapes",
        help="validate a sealed bounded recursion-profile shape audit",
    )
    validate_shape.add_argument("--audit", required=True, type=Path)

    plan = commands.add_parser(
        "plan", help="normalize a native CSP report and pin the recursion boundary"
    )
    plan.add_argument("--native-report", required=True, type=Path)
    plan.add_argument(
        "--pair-node-source",
        type=Path,
        help="override the repository pair-node source (primarily for boundary tests)",
    )
    plan.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new plan path; an existing file is never replaced",
    )

    compare = commands.add_parser(
        "compare", help="emit an honest diagnostic comparison from a sealed plan"
    )
    compare.add_argument("--plan", required=True, type=Path)
    compare.add_argument(
        "--recursive-report",
        type=Path,
        help="complete producer report; omit while recursive proof production is unavailable",
    )
    compare.add_argument(
        "--active-outer-probe",
        type=Path,
        help="optional sealed non-CSP readiness probe; never used to calculate ratios",
    )
    compare.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new comparison path; an existing file is never replaced",
    )

    validate_plan_command = commands.add_parser(
        "validate-plan", help="validate a plan and re-check its pinned source boundary"
    )
    validate_plan_command.add_argument("--plan", required=True, type=Path)

    validate_report_command = commands.add_parser(
        "validate-recursive", help="validate a complete recursive producer report"
    )
    validate_report_command.add_argument("--plan", required=True, type=Path)
    validate_report_command.add_argument("--recursive-report", required=True, type=Path)

    probe = commands.add_parser(
        "probe-active-outer",
        help=(
            "run the verified active outer gate in fresh processes; this is a "
            "non-CSP readiness probe using the plan's warmup/sample schedule, not "
            "comparison evidence"
        ),
    )
    probe.add_argument("--plan", required=True, type=Path)
    probe.add_argument("--workers", required=True, type=int)
    probe.add_argument(
        "--zig",
        default="zig",
        help="Zig executable name or path (default: zig from PATH)",
    )
    probe.add_argument(
        "--timeout-seconds",
        default=3600,
        type=int,
        help="per-attempt timeout (default: 3600)",
    )
    probe.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new probe path; an existing file is never replaced",
    )

    validate_probe = commands.add_parser(
        "validate-active-probe",
        help="validate a sealed non-CSP active-outer readiness probe",
    )
    validate_probe.add_argument("--plan", required=True, type=Path)
    validate_probe.add_argument("--probe", required=True, type=Path)

    collect = commands.add_parser(
        "collect-canonical-outer",
        help=(
            "run canonical CSP native-leaf plus active 36-row outer proofs; "
            "results remain subsystem-only until complete parent recursion exists"
        ),
    )
    collect.add_argument("--plan", required=True, type=Path)
    collect.add_argument(
        "--producer",
        default=ROOT / "zig-out/bin/stwo-zig-riscv-recursive-csp-producer",
        type=Path,
    )
    collect.add_argument(
        "--manifest",
        default=ROOT / "vectors/riscv_csp/manifest-v2.json",
        type=Path,
    )
    collect.add_argument("--workers", required=True, type=int)
    collect.add_argument(
        "--timeout-seconds",
        default=3600,
        type=int,
        help="per-attempt timeout (default: 3600)",
    )
    collect.add_argument(
        "--artifact-directory",
        required=True,
        type=Path,
        help="fresh directory retaining every request, attempt record, and wire",
    )
    collect.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new sealed subsystem report path; an existing file is never replaced",
    )
    return parser


def _publish(path: Path, document: dict[str, object]) -> None:
    encoded = canonical_bytes(document)
    atomic_write_new(path, encoded)
    print(f"{document['schema']} {document['canonical_digest']} {path.resolve()}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "audit-shapes":
            audit = collect_shape_audit(
                repo_root=ROOT,
                manifest_path=args.manifest,
                inspector=args.inspector,
                timeout_seconds=args.timeout_seconds,
            )
            _publish(args.output, audit)
        elif args.command == "validate-shapes":
            audit, _ = load_json(args.audit.resolve())
            validate_shape_audit(audit, repo_root=ROOT)
            print(audit["canonical_digest"])
        elif args.command == "plan":
            native, raw = load_json(args.native_report.resolve())
            pair_source = args.pair_node_source
            if pair_source is not None and not pair_source.is_absolute():
                pair_source = ROOT / pair_source
            plan = build_plan(
                native,
                native_raw=raw,
                repo_root=ROOT,
                pair_node_path=pair_source,
            )
            _publish(args.output, plan)
        elif args.command == "compare":
            plan, _ = load_json(args.plan.resolve())
            recursive = None
            if args.recursive_report is not None:
                recursive, _ = load_json(args.recursive_report.resolve())
            active_probe = None
            if args.active_outer_probe is not None:
                active_probe, _ = load_json(args.active_outer_probe.resolve())
            comparison = build_comparison(
                plan,
                recursive_report=recursive,
                repo_root=ROOT,
                active_outer_probe=active_probe,
            )
            _publish(args.output, comparison)
        elif args.command == "validate-plan":
            plan, _ = load_json(args.plan.resolve())
            validate_plan(plan, repo_root=ROOT)
            print(plan["canonical_digest"])
        elif args.command == "validate-recursive":
            plan, _ = load_json(args.plan.resolve())
            recursive, _ = load_json(args.recursive_report.resolve())
            validate_plan(plan, repo_root=ROOT)
            validate_recursive_report(recursive, plan=plan)
            print(recursive["canonical_digest"])
        elif args.command == "probe-active-outer":
            plan, _ = load_json(args.plan.resolve())
            resolved_zig = shutil.which(args.zig)
            if resolved_zig is None:
                raise EvidenceError(f"cannot resolve Zig executable: {args.zig}")
            probe = collect_active_outer_probe(
                plan,
                repo_root=ROOT,
                zig_executable=Path(resolved_zig),
                workers=args.workers,
                timeout_seconds=args.timeout_seconds,
            )
            _publish(args.output, probe)
            if probe["status"] != "verified_non_csp_probe":
                return 2
        elif args.command == "validate-active-probe":
            plan, _ = load_json(args.plan.resolve())
            probe, _ = load_json(args.probe.resolve())
            validate_plan(plan, repo_root=ROOT)
            validate_active_outer_probe(probe, plan=plan)
            print(probe["canonical_digest"])
        elif args.command == "collect-canonical-outer":
            plan, _ = load_json(args.plan.resolve())
            report = collect_canonical_outer_report(
                plan,
                repo_root=ROOT,
                manifest_path=args.manifest,
                producer=args.producer,
                artifact_directory=args.artifact_directory,
                worker_count=args.workers,
                timeout_seconds=args.timeout_seconds,
            )
            _publish(args.output, report)
            if report["status"] != "verified_verifier_subsystem":
                if _has_source_alignment_failure(report):
                    print(CURRENT_SOURCE_CAPTURE_GUIDANCE, file=sys.stderr)
                return 2
        else:  # pragma: no cover - argparse owns the command set.
            raise EvidenceError(f"unsupported command: {args.command}")
    except (EvidenceError, OSError, ValueError) as error:
        print(f"recursion CSP benchmark failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
