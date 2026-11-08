"""Thin CLI for plan generation, bounded host capture, and independent validation."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from .capture import HostCaptureController, NativeProofEvidenceHook, SubprocessExecutor
from .codec import atomic_write, canonical_bytes, sha256_bytes, strict_json
from .model import DEFAULT_PROTOCOL, ROOT, EvidenceError
from .plan import build_plan, load_and_validate_plan
from .policy import load_protocol
from .receipt import load_and_validate_receipt


def _paths(path: Path) -> dict[str, str]:
    value = strict_json(path, 1024 * 1024, canonical=False)
    return {key: str(item) for key, item in value.items()}


def _worktree_identity(path: str) -> tuple[str, str, str]:
    root = Path(path)
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", *args], cwd=root, text=True, capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise EvidenceError(f"cannot inspect capture worktree {root}: {result.stderr.strip()}")
        return result.stdout.strip()
    return git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}"), git("status", "--porcelain=v1")


def _check_worktrees(plan: dict) -> None:
    for arm in ("baseline", "candidate"):
        commit, tree, status = _worktree_identity(plan["paths"][f"{arm}_root"])
        expected = plan["sources"][arm]
        if (commit, tree, status) != (expected["commit"], expected["tree"], ""):
            raise EvidenceError(f"{arm} worktree is not the exact clean planned source")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("create-plan")
    plan.add_argument("--host-role", choices=("linux", "macos"), required=True)
    plan.add_argument("--session-nonce", required=True)
    plan.add_argument("--candidate-commit", required=True)
    plan.add_argument("--candidate-tree", required=True)
    plan.add_argument("--paths", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    validate_plan = sub.add_parser("validate-plan")
    validate_plan.add_argument("--plan", type=Path, required=True)
    capture = sub.add_parser("capture-host")
    capture.add_argument("--plan", type=Path, required=True)
    capture.add_argument("--schedule", type=Path, required=True)
    capture.add_argument("--staging-root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--timeout-seconds", type=float, default=3600.0)
    capture.add_argument("--rust-oracle-bin", type=Path)
    validate = sub.add_parser("validate-receipt")
    validate.add_argument("--linux-plan", type=Path, required=True)
    validate.add_argument("--macos-plan", type=Path, required=True)
    validate.add_argument("--receipt", type=Path, required=True)
    validate.add_argument("--raw-root", type=Path, required=True)
    validate.add_argument("--trusted-attestations", type=Path, required=True)
    validate.add_argument("--binding-out", type=Path)
    return parser


def _main(
    args: argparse.Namespace,
    oracle_runner: Callable[[Path, Path, float], dict[str, Any]] | None,
) -> dict:
    root = args.root.resolve()
    protocol, protocol_digest = load_protocol(root, args.protocol)
    if args.command == "create-plan":
        value = build_plan(
            protocol=protocol, protocol_sha256=protocol_digest,
            host_role=args.host_role, session_nonce=args.session_nonce,
            candidate_commit=args.candidate_commit, candidate_tree=args.candidate_tree,
            paths=_paths(args.paths),
        )
        digest = atomic_write(args.output, value)
        return {"status": "PASS", "plan_path": str(args.output.resolve()), "plan_sha256": digest}
    if args.command == "validate-plan":
        _, digest = load_and_validate_plan(args.plan, protocol, protocol_digest)
        return {"status": "PASS", "plan_path": str(args.plan.resolve()), "plan_sha256": digest}
    if args.command == "capture-host":
        plan, digest = load_and_validate_plan(args.plan, protocol, protocol_digest)
        _check_worktrees(plan)
        schedule = strict_json(args.schedule, protocol["limits"]["max_json_bytes"], canonical=False)
        if set(schedule) != {"schema", "requests"} or schedule["schema"] != "build-performance-capture-schedule-v1":
            raise EvidenceError("capture schedule schema is unsupported")
        has_proofs = any(request.get("stage") in {"warmup", "sample"} for request in schedule["requests"])
        if has_proofs and args.rust_oracle_bin is None:
            raise EvidenceError("proof capture requires the pinned Rust Stwo oracle binary")
        if has_proofs and oracle_runner is None:
            raise EvidenceError("proof capture lacks the repository Rust-oracle adapter")
        hook = (
            NativeProofEvidenceHook(args.rust_oracle_bin, args.timeout_seconds, oracle_runner)
            if args.rust_oracle_bin is not None else None
        )
        controller = HostCaptureController(
            plan=plan, plan_sha256=digest, staging_root=args.staging_root,
            executor=SubprocessExecutor(hook), timeout_seconds=args.timeout_seconds,
        )
        for request in schedule["requests"]:
            controller.run_attempt(request)
        captured = controller.seal()
        result = {
            "schema": "build-performance-host-capture-v1",
            "host_role": plan["host_role"],
            "plan_sha256": digest,
            "attempts": captured.attempts,
            "artifacts": captured.artifacts,
            "attempt_ledger_artifact": captured.attempt_ledger_artifact,
            "attempt_journal_artifact": captured.attempt_journal_artifact,
            "terminal_attempt_sha256": captured.terminal_attempt_sha256,
            "attempt_count": captured.attempt_count,
        }
        atomic_write(args.output, result)
        return {"status": "CAPTURED", "capture_path": str(args.output.resolve())}
    plans: dict[str, dict] = {}
    digests: dict[str, str] = {}
    for role in ("linux", "macos"):
        plans[role], digests[role] = load_and_validate_plan(
            getattr(args, f"{role}_plan"), protocol, protocol_digest,
        )
    trusted = strict_json(args.trusted_attestations, 1024 * 1024, canonical=False)
    result = load_and_validate_receipt(
        args.receipt, root=root, protocol=protocol, protocol_sha256=protocol_digest,
        plans=plans, plan_digests=digests, raw_root=args.raw_root,
        trusted_attestations=trusted,
    )
    binding = result.architecture_binding()
    if args.binding_out:
        atomic_write(args.binding_out, binding)
    return binding


def main(
    argv: list[str] | None = None,
    *,
    oracle_runner: Callable[[Path, Path, float], dict[str, Any]] | None = None,
) -> int:
    try:
        result = _main(_parser().parse_args(argv), oracle_runner)
    except EvidenceError as error:
        print(json.dumps({"status": "NO-GO", "error": str(error)}, sort_keys=True))
        return 1
    print(canonical_bytes(result).decode("ascii"), end="")
    return 0
