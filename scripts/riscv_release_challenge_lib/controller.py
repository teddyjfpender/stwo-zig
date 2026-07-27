"""Archived pre-Sail challenge-format orchestration for forensic tests."""

from __future__ import annotations

import argparse
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from . import execution, model


ROOT = Path(__file__).resolve().parents[2]


def identity_from_args(args: argparse.Namespace) -> dict[str, Any]:
    manifest = model.strict_json(args.bundle / "manifest.json")
    oracle_receipt = model.strict_json(args.bundle / "oracle-receipt.json")
    oracle = oracle_receipt.get("oracle")
    domains = manifest.get("domains")
    producer = manifest.get("producer")
    if not isinstance(oracle, dict) or not isinstance(domains, dict) or not isinstance(producer, dict):
        raise model.ChallengeError("exhaustive anchor identity is incomplete")
    oracle_domain = domains.get("oracle_build")
    run = producer.get("run")
    if not isinstance(oracle_domain, dict) or not isinstance(run, dict):
        raise model.ChallengeError("exhaustive anchor domain or run identity is incomplete")
    return {
        "repository": {"full_name": args.repository, "id": args.repository_id},
        "candidate": {
            "commit": args.candidate,
            "tree_oid": args.tree,
            "phase": args.phase,
            "executable_sha256": model.sha256_file(args.cli),
            "trace_executable_sha256": model.sha256_file(args.trace_cli),
        },
        "workflow": {
            "commit": args.workflow_sha,
            "run_id": args.run_id,
            "attempt": args.run_attempt,
        },
        "anchor": {
            "manifest_sha256": model.sha256_file(args.bundle / "manifest.json"),
            "candidate_commit": manifest.get("candidate_commit"),
            "tree_oid": manifest.get("repository_tree_oid"),
            "producer_run_id": run.get("id"),
            "oracle_repository": oracle.get("repository"),
            "oracle_commit": oracle.get("commit"),
            "oracle_domain_sha256": oracle_domain.get("sha256"),
            "oracle_executable_sha256": oracle.get("executable_sha256"),
            "verifier_executable_sha256": model.sha256_file(args.bundle / "bin/stwo-zig"),
        },
    }


def issue(args: argparse.Namespace) -> int:
    try:
        identity = identity_from_args(args)
        nonce = bytes.fromhex(args.nonce_hex) if args.nonce_hex else secrets.token_bytes(32)
        challenge = model.issue(identity, nonce, int(time.time()))
        model.atomic_json(args.output, challenge)
        print(f"riscv release challenge: issued {challenge['challenge_id_sha256']}")
        return 0
    except (OSError, ValueError) as error:
        print(f"riscv release challenge: {error}", file=sys.stderr)
        return 1


def run(args: argparse.Namespace) -> int:
    try:
        identity = identity_from_args(args)
        result = execution.execute(
            challenge_path=args.challenge,
            identity=identity,
            cli=args.cli,
            trace_cli=args.trace_cli,
            oracle_cli=args.bundle / "bin/cp11_dump",
            verifier_cli=args.bundle / "bin/stwo-zig",
            evidence_dir=args.evidence_dir,
            replay_ledger=args.replay_ledger,
        )
        model.atomic_json(args.result, result)
        print(f"riscv release challenge: PASS in {result['timing']['wall_duration_ns'] / 1e9:.3f}s")
        return 0
    except (OSError, ValueError, TimeoutError) as error:
        print(f"riscv release challenge: {error}", file=sys.stderr)
        return 1


def add_identity_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--phase", choices=("candidate", "promoted"), required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--trace-cli", type=Path, required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("issue")
    add_identity_args(command)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--nonce-hex", help=argparse.SUPPRESS)
    command.set_defaults(handler=issue)
    command = subparsers.add_parser("execute")
    add_identity_args(command)
    command.add_argument("--challenge", type=Path, required=True)
    command.add_argument("--evidence-dir", type=Path, required=True)
    command.add_argument("--replay-ledger", type=Path, required=True)
    command.add_argument("--result", type=Path, required=True)
    command.set_defaults(handler=run)
    args = parser.parse_args(argv)
    return args.handler(args)
