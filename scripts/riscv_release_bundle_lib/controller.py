"""Archived pre-Sail bundle-format orchestration for forensic tests."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import model


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCRIPT = Path(__file__).resolve().parents[1] / "riscv_release_evidence.py"


def validate_oracle_receipt(
    root: Path, receipt: Path, candidate: str, *, immutable: bool = False,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(EVIDENCE_SCRIPT),
            "--receipt",
            str(receipt),
            "--candidate",
            candidate,
            *(["--at-receipt-time"] if immutable else []),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()
        raise model.BundleError(f"oracle receipt invalid: {diagnostic}")


def pack(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    evidence = args.evidence_dir.resolve()
    output = args.output_dir.resolve()
    created_output = False
    try:
        tree = model.require_clean_head(root, args.candidate)
        if output.exists():
            raise model.BundleError(f"output directory already exists: {output}")
        gate = model.strict_json(evidence / "release-gate.json")
        oracle = model.strict_json(evidence / "oracle-receipt.json")
        summary = model.strict_json(evidence / "cli/summary.json")
        trust = model.strict_json(args.trust_context)
        policy = model.strict_json(args.policy_context)
        model.validate_gate_report(gate, args.candidate, args.phase)
        validate_oracle_receipt(root, evidence / "oracle-receipt.json", args.candidate)
        executable_sha256 = model.sha256_file(args.cli)
        model.validate_cli_summary(summary, args.candidate, args.phase, executable_sha256)
        model.validate_executable_digests(
            oracle, cli=args.cli, oracle_cli=args.oracle_cli, trace_cli=args.trace_cli,
        )

        output.mkdir(parents=True, exist_ok=False)
        created_output = True
        for name, relative in model.FILE_LAYOUT.items():
            source = {
                "release-gate.json": evidence / "release-gate.json",
                "oracle-receipt.json": evidence / "oracle-receipt.json",
                "cli/summary.json": evidence / "cli/summary.json",
                "bin/stwo-zig": args.cli,
                "bin/cp11_dump": args.oracle_cli,
                "bin/riscv-trace-dump": args.trace_cli,
            }[name]
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)

        files = {
            name: model.file_record(output / relative)
            for name, relative in model.FILE_LAYOUT.items()
        }
        domains = model.source_domains(root)
        domains["oracle_build"] = model.oracle_domain(oracle)
        domains["toolchains"] = {
            "schema": "release-gate-toolchains-v1",
            "sha256": model.canonical_sha256(gate.get("toolchains")),
        }
        created_at = int(time.time())
        model.validate_trust_context(
            trust, candidate=args.candidate, phase=args.phase, tree=tree,
        )
        model.validate_policy_context(
            policy,
            candidate=args.candidate,
            workflow_commit=trust["workflow"]["commit_sha"],
        )
        manifest = {
            "schema": model.SCHEMA,
            "phase": args.phase,
            "candidate_commit": args.candidate,
            "repository_tree_oid": tree,
            "created_at_unix": created_at,
            "expires_at_unix": created_at + model.BUNDLE_RETENTION_SECONDS,
            "coverage": model.COVERAGE,
            "producer": trust,
            "release_policy": policy,
            "domains": domains,
            "files": files,
        }
        model.atomic_write_json(output / "manifest.json", manifest)
        print(f"riscv release bundle: packed exhaustive evidence at {output}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if created_output and output.exists():
            shutil.rmtree(output)
        print(f"riscv release bundle: {error}", file=sys.stderr)
        return 1


def verify(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    bundle = args.bundle.resolve()
    try:
        tree = model.require_clean_head(root, args.candidate)
        manifest = model.strict_json(bundle / "manifest.json")
        if manifest.get("schema") != model.SCHEMA:
            raise model.BundleError("bundle schema drifted")
        if (manifest.get("phase"), manifest.get("candidate_commit")) != (
            args.phase, args.candidate,
        ):
            raise model.BundleError("bundle is not bound to the requested phase and candidate")
        if manifest.get("repository_tree_oid") != tree:
            raise model.BundleError("bundle repository tree identity drifted")
        model.validate_lifetime(manifest)
        if manifest.get("coverage") != model.COVERAGE:
            raise model.BundleError("bundle exhaustive coverage declaration drifted")
        expected_producer = model.strict_json(args.trust_context)
        model.validate_trust_context(
            expected_producer, candidate=args.candidate, phase=args.phase, tree=tree,
        )
        if manifest.get("producer") != expected_producer:
            raise model.BundleError(
                "bundle producer identity does not match the selected producer run"
            )
        expected_policy = model.strict_json(args.policy_context)
        model.validate_policy_context(
            expected_policy,
            candidate=args.candidate,
            workflow_commit=expected_producer["workflow"]["commit_sha"],
        )
        if manifest.get("release_policy") != expected_policy:
            raise model.BundleError("bundle release policy does not match trusted main")
        files = model.validate_files(bundle, manifest)
        gate = model.strict_json(files["release-gate.json"])
        oracle = model.strict_json(files["oracle-receipt.json"])
        summary = model.strict_json(files["cli/summary.json"])
        model.validate_gate_report(gate, args.candidate, args.phase)
        validate_oracle_receipt(
            root, files["oracle-receipt.json"], args.candidate, immutable=True,
        )
        model.validate_cli_summary(
            summary, args.candidate, args.phase, model.sha256_file(files["bin/stwo-zig"]),
        )
        model.validate_executable_digests(
            oracle,
            cli=files["bin/stwo-zig"],
            oracle_cli=files["bin/cp11_dump"],
            trace_cli=files["bin/riscv-trace-dump"],
        )
        domains = model.source_domains(root)
        domains["oracle_build"] = model.oracle_domain(oracle)
        domains["toolchains"] = {
            "schema": "release-gate-toolchains-v1",
            "sha256": model.canonical_sha256(gate.get("toolchains")),
        }
        if manifest.get("domains") != domains:
            raise model.BundleError("bundle source/toolchain content domains drifted")
        print("riscv release bundle: exact-source exhaustive evidence is valid")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"riscv release bundle: {error}", file=sys.stderr)
        return 1


def verify_anchor(args: argparse.Namespace) -> int:
    """Validate a reusable exhaustive anchor against the current trusted policy."""
    root = args.root.resolve()
    bundle = args.bundle.resolve()
    try:
        model.require_clean_head(root, args.candidate)
        manifest = model.strict_json(bundle / "manifest.json")
        if manifest.get("schema") != model.SCHEMA:
            raise model.BundleError("anchor bundle schema drifted")
        anchor_candidate = model.require_commit(
            manifest.get("candidate_commit"), "anchor candidate",
        )
        anchor_tree = model.require_commit(
            manifest.get("repository_tree_oid"), "anchor tree",
        )
        anchor_phase = manifest.get("phase")
        if anchor_phase not in ("candidate", "promoted"):
            raise model.BundleError("anchor phase drifted")
        model.validate_lifetime(manifest)
        if manifest.get("coverage") != model.COVERAGE:
            raise model.BundleError("anchor exhaustive coverage declaration drifted")
        expected_producer = model.strict_json(args.trust_context)
        model.validate_trust_context(
            expected_producer,
            candidate=anchor_candidate,
            phase=anchor_phase,
            tree=anchor_tree,
        )
        if manifest.get("producer") != expected_producer:
            raise model.BundleError("anchor producer differs from the selected trusted run")
        current_policy = model.strict_json(args.policy_context)
        model.validate_policy_context(
            current_policy,
            candidate=args.candidate,
            workflow_commit=args.workflow_sha,
        )
        anchor_policy = manifest.get("release_policy")
        if not isinstance(anchor_policy, dict):
            raise model.BundleError("anchor release policy is missing")
        model.validate_policy_context(
            anchor_policy,
            candidate=anchor_candidate,
            workflow_commit=expected_producer["workflow"]["commit_sha"],
        )
        if anchor_policy.get("domain") != current_policy.get("domain"):
            raise model.BundleError("anchor release policy differs from trusted current policy")
        files = model.validate_files(bundle, manifest)
        gate = model.strict_json(files["release-gate.json"])
        oracle = model.strict_json(files["oracle-receipt.json"])
        summary = model.strict_json(files["cli/summary.json"])
        model.validate_gate_report(gate, anchor_candidate, anchor_phase)
        validate_oracle_receipt(
            root, files["oracle-receipt.json"], anchor_candidate, immutable=True,
        )
        model.validate_cli_summary(
            summary,
            anchor_candidate,
            anchor_phase,
            model.sha256_file(files["bin/stwo-zig"]),
        )
        model.validate_executable_digests(
            oracle,
            cli=files["bin/stwo-zig"],
            oracle_cli=files["bin/cp11_dump"],
            trace_cli=files["bin/riscv-trace-dump"],
        )
        domains = manifest.get("domains")
        if not isinstance(domains, dict) or domains.get("oracle_build") != model.oracle_domain(oracle):
            raise model.BundleError("anchor oracle build domain drifted")
        expected_toolchain = {
            "schema": "release-gate-toolchains-v1",
            "sha256": model.canonical_sha256(gate.get("toolchains")),
        }
        if domains.get("toolchains") != expected_toolchain:
            raise model.BundleError("anchor toolchain domain drifted")
        print(
            "riscv release bundle: reusable exhaustive anchor is valid "
            f"(anchor={anchor_candidate}, candidate={args.candidate})"
        )
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"riscv release bundle: {error}", file=sys.stderr)
        return 1


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--phase", choices=("candidate", "promoted"), required=True)
    parser.add_argument("--trust-context", type=Path, required=True)
    parser.add_argument("--policy-context", type=Path, required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("pack")
    add_identity_arguments(command)
    command.add_argument("--evidence-dir", type=Path, required=True)
    command.add_argument("--cli", type=Path, required=True)
    command.add_argument("--oracle-cli", type=Path, required=True)
    command.add_argument("--trace-cli", type=Path, required=True)
    command.add_argument("--output-dir", type=Path, required=True)
    command.set_defaults(handler=pack)
    command = subparsers.add_parser("verify")
    add_identity_arguments(command)
    command.add_argument("--bundle", type=Path, required=True)
    command.set_defaults(handler=verify)
    command = subparsers.add_parser("verify-anchor")
    command.add_argument("--candidate", required=True)
    command.add_argument("--workflow-sha", required=True)
    command.add_argument("--trust-context", type=Path, required=True)
    command.add_argument("--policy-context", type=Path, required=True)
    command.add_argument("--bundle", type=Path, required=True)
    command.set_defaults(handler=verify_anchor)
    args = parser.parse_args(argv)
    return args.handler(args)
