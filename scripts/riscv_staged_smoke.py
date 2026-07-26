#!/usr/bin/env python3
"""Staged riscv CLI smoke: prove, independently verify, and reject tampering.

Exercises the installed CLI end to end on a committed, cross-verified vector
ELF: `prove --elf` must produce a v4 artifact that a separate `verify
--artifact --elf` invocation cryptographically accepts (printing its honest
release status), and a single-bit tamper of the public statement must be
rejected. Part of the riscv release gate; also runnable standalone.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.riscv_staged_smoke_lib import contracts, mutations, profiles  # noqa: E402

ELF = "vectors/riscv_elfs/branch_fib.elf"
ELF_SHA256 = "7ff124d1aea7433225b018c7f4dbcae7f693506c0ac34d6790c60cd50c7b2c3f"
COMMAND_TIMEOUT_SECONDS = 1_800
MULTI_SHARD_TOTAL_STEPS = 131_078
MULTI_SHARD_ADDI_ROWS = 65_538
MULTI_SHARD_PROGRAM_WORDS = 8
MULTI_SHARD_ELF_SHA256 = "06d217624c13bed63beecbc15127b1fbcd098ee520ac11a20d864cb38d7577a0"
WITNESS_LAYOUT_SHA256 = "c1fbdc34701f9b27513652bd292ec06001e9847d5c75b6dc01aeed0b597c58af"


def write_multi_shard_elf(path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import riscv_trace_vectors as vectors  # pylint: disable=import-outside-toplevel

    elf = vectors.build_release_elf(vectors.prog_multi_shard_addi())
    digest = hashlib.sha256(elf).hexdigest()
    if digest != MULTI_SHARD_ELF_SHA256:
        raise RuntimeError(f"multi-shard ELF digest drift: {digest}")
    path.write_bytes(elf)


def write_unsupported_elf(path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import riscv_trace_vectors as vectors  # pylint: disable=import-outside-toplevel

    path.write_bytes(vectors.build_release_elf([0x0000_0073]))  # ECALL is outside the proof ISA.


def command(cli: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(cli), *args], cwd=ROOT, capture_output=True, text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def git_identity() -> tuple[str, bool]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    return head, bool(status)


def require_rejection(
    result: subprocess.CompletedProcess[str], outputs: tuple[Path, ...], label: str,
    expected_errors: tuple[str, ...] = (),
) -> dict[str, object]:
    if result.returncode == 0 or any(path.exists() for path in outputs):
        raise contracts.ContractError(f"{label}: rejected invocation published output")
    if expected_errors and not any(error in result.stderr for error in expected_errors):
        raise contracts.ContractError(
            f"{label}: expected one of {expected_errors}, got {result.stderr!r}"
        )
    return {
        "returncode": result.returncode,
        "stdout_sha256": contracts.sha256_text(result.stdout),
        "stderr_sha256": contracts.sha256_text(result.stderr),
    }


def prepare_cli(cli_argument: Path | None) -> tuple[Path, str, int, int]:
    """Resolve the CLI, building only when no authenticated prebuilt path was supplied."""
    started = time.monotonic_ns()
    if cli_argument is None:
        subprocess.run(
            ["zig", "build", "stwo-zig", "-Doptimize=ReleaseFast"],
            cwd=ROOT,
            check=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        return (
            ROOT / "zig-out" / "bin" / "stwo-zig",
            "local_releasefast_build",
            1,
            time.monotonic_ns() - started,
        )
    return cli_argument.resolve(), "prebuilt", 0, time.monotonic_ns() - started


def timing_evidence(
    command_metrics: list[dict[str, object]], *, smoke_started: int,
    build_command_count: int, build_duration_ns: int,
) -> dict[str, object]:
    return {
        "wall_duration_ns": time.monotonic_ns() - smoke_started,
        "build_command_count": build_command_count,
        "build_duration_ns": build_duration_ns,
        "cli_command_count": len(command_metrics),
        "cli_command_duration_ns": sum(
            int(metric["duration_ns"]) for metric in command_metrics
        ),
        "commands": command_metrics,
    }


def main() -> int:
    smoke_started = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("candidate", "promoted"), default="candidate")
    parser.add_argument("--profile", choices=("exhaustive", "fast"), default="exhaustive")
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--producer-receipt", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    fast = args.profile == "fast"
    if fast and (args.cli is None or args.producer_receipt is None or args.evidence_dir is None):
        parser.error("--profile fast requires --cli, --producer-receipt, and --evidence-dir")
    if not fast and args.producer_receipt is not None:
        parser.error("--producer-receipt is only valid with --profile fast")
    candidate = args.phase == "candidate"
    expected_status = "not_release_gated" if candidate else "release_gated"

    cli, cli_origin, build_command_count, build_duration_ns = prepare_cli(args.cli)
    if not cli.is_file():
        print(f"riscv staged smoke: CLI is not a file: {cli}", file=sys.stderr)
        return 1
    implementation_commit, implementation_dirty = git_identity()
    executable_sha256 = hashlib.sha256(cli.read_bytes()).hexdigest()
    producer_link: dict[str, object] | None = None
    if fast:
        try:
            producer_link = profiles.validate_producer_receipt(
                args.producer_receipt,
                cli,
                phase=args.phase,
                candidate_commit=implementation_commit,
                implementation_dirty=implementation_dirty,
            )
        except contracts.ContractError as error:
            print(f"riscv staged smoke: {error}", file=sys.stderr)
            return 1

    command_metrics: list[dict[str, object]] = []

    def run(*command_args: str) -> subprocess.CompletedProcess[str]:
        started = time.monotonic_ns()
        result = command(cli, *command_args)
        command_metrics.append({
            "ordinal": len(command_metrics),
            "argv": list(command_args),
            "duration_ns": time.monotonic_ns() - started,
            "returncode": result.returncode,
        })
        return result

    visible_digests: dict[str, str] = {}
    exhaustive_help_cases = {
        "root-help": ("--help",),
        "prove-help": ("prove", "--help"),
        "bench-help": ("bench", "--help"),
        "verify-help": ("verify", "--help"),
        "applications-help": ("applications", "--help"),
    }
    help_cases = exhaustive_help_cases if not fast else {"root-help": ("--help",)}
    try:
        for name, command_args in help_cases.items():
            result = run(*command_args)
            if result.returncode != 0 or result.stderr:
                raise contracts.ContractError(f"{name}: installed help failed")
            visible_digests[name] = contracts.validate_visible_snapshot(name, result.stdout)
        if not fast:
            for name, command_args in {
                "missing-command": (),
                "unknown-command": ("not-a-command",),
            }.items():
                result = run(*command_args)
                if result.returncode == 0 or result.stdout:
                    raise contracts.ContractError(f"{name}: diagnostic did not fail on stderr")
                visible_digests[name] = contracts.validate_visible_snapshot(
                    name, result.stderr, diagnostic=True,
                )
        registry_result = run("applications")
        if registry_result.returncode != 0 or registry_result.stderr:
            raise contracts.ContractError("applications: installed registry command failed")
        registry = contracts.strict_json_object(registry_result.stdout, "applications")
        contracts.validate_registry(registry, expected_status)
        visible_digests["applications"] = contracts.sha256_text(registry_result.stdout)
    except contracts.ContractError as error:
        print(f"riscv staged smoke: {error}", file=sys.stderr)
        return 1

    if args.evidence_dir:
        evidence_dir = args.evidence_dir.resolve()
        evidence_dir.mkdir(parents=True, exist_ok=False)
        workspace = contextlib.nullcontext(str(evidence_dir))
    else:
        workspace = tempfile.TemporaryDirectory()

    with workspace as tmp:
        multi_shard_elf = Path(tmp) / "multi_shard_addi.elf"
        write_multi_shard_elf(multi_shard_elf)
        artifact = Path(tmp) / "proof.json"
        report = Path(tmp) / "report.json"
        benchmark_report = Path(tmp) / "benchmark.json"
        benchmark_artifact = Path(tmp) / "benchmark-proof.json"
        denied_artifact = Path(tmp) / "denied.json"
        denied_report = Path(tmp) / "denied-report.json"

        rejection_results: dict[str, dict[str, object]] = {}

        def elf_prove_args(elf: str, *, backend: str = "cpu", input_path: Path | None = None) -> list[str]:
            values = [
                "prove", "--elf", elf, "--backend", backend, "--protocol", "functional",
                "--output", str(denied_artifact), "--report-out", str(denied_report),
            ]
            if input_path is not None:
                values.extend(("--input", str(input_path)))
            if candidate:
                values.append("--experimental")
            return values

        admission = [
            "prove", "--elf", str(multi_shard_elf), "--backend", "cpu", "--protocol", "functional",
            "--output", str(denied_artifact), "--report-out", str(denied_report),
        ]
        if not candidate:
            admission.append("--experimental")
        denied = run(*admission)
        try:
            rejection_results["phase-admission"] = require_rejection(
                denied,
                (denied_artifact, denied_report),
                "phase admission",
                ("ExperimentalFlagRequired",) if candidate else ("ExperimentalFlagAfterPromotion",),
            )
        except contracts.ContractError as error:
            print(f"riscv staged smoke: {error}", file=sys.stderr)
            return 1

        if not fast:
            malformed_elf = Path(tmp) / "malformed.elf"
            malformed_elf.write_bytes(b"not an ELF")
            unsupported_elf = Path(tmp) / "unsupported-ecall.elf"
            write_unsupported_elf(unsupported_elf)
            oversized_input = Path(tmp) / "oversized-input.bin"
            with oversized_input.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            irrelevant = run(
                "verify", "--artifact", "does-not-exist.json", "--elf", ELF,
                "--experimental",
            )
            try:
                rejection_results["irrelevant-experimental"] = require_rejection(
                    irrelevant, (), "irrelevant --experimental", ("IrrelevantArgument",),
                )
                negative_cases = {
                    "malformed-elf": (
                        elf_prove_args(str(malformed_elf)),
                        ("BufferTooSmall", "InvalidMagic"),
                    ),
                    "undeclared-release-abi": (
                        elf_prove_args("vectors/riscv_elfs/negative/undeclared_program.elf"),
                        ("MissingReleaseAbiSymbol",),
                    ),
                    "unsupported-instruction": (
                        elf_prove_args(str(unsupported_elf)),
                        ("InvalidInstruction",),
                    ),
                    "oversized-input": (
                        elf_prove_args(ELF, input_path=oversized_input),
                        ("FileTooBig",),
                    ),
                    "missing-input": (
                        elf_prove_args(ELF, input_path=Path(tmp) / "missing-input.bin"),
                        ("FileNotFound",),
                    ),
                    "unsupported-backend": (
                        elf_prove_args(ELF, backend="metal-hybrid"),
                        ("staged only",),
                    ),
                }
                for label, (case_args, expected_errors) in negative_cases.items():
                    result = run(*case_args)
                    rejection_results[label] = require_rejection(
                        result, (denied_artifact, denied_report), label, expected_errors,
                    )

                sentinel = b"existing-output-must-survive\n"
                denied_artifact.write_bytes(sentinel)
                occupied_proof = run(*elf_prove_args(ELF))
                if occupied_proof.returncode == 0 or denied_artifact.read_bytes() != sentinel or \
                        denied_report.exists():
                    raise contracts.ContractError(
                        "existing proof output was replaced or accompanied"
                    )
                rejection_results["existing-proof"] = {
                    "returncode": occupied_proof.returncode,
                    "stderr_sha256": contracts.sha256_text(occupied_proof.stderr),
                }
                denied_artifact.unlink()
                denied_report.write_bytes(sentinel)
                occupied_report = run(*elf_prove_args(ELF))
                if occupied_report.returncode == 0 or denied_report.read_bytes() != sentinel or \
                        denied_artifact.exists():
                    raise contracts.ContractError(
                        "existing report output was replaced or accompanied"
                    )
                rejection_results["existing-report"] = {
                    "returncode": occupied_report.returncode,
                    "stderr_sha256": contracts.sha256_text(occupied_report.stderr),
                }
                denied_report.unlink()
            except contracts.ContractError as error:
                print(f"riscv staged smoke: {error}", file=sys.stderr)
                return 1

        prove_args = [
            "prove", "--elf", str(multi_shard_elf), "--backend", "cpu", "--protocol", "functional",
            "--output", str(artifact), "--report-out", str(report),
        ]
        if candidate:
            prove_args.append("--experimental")
        prove = run(*prove_args)
        if prove.returncode != 0:
            print(f"riscv staged smoke: prove failed: {prove.stdout}{prove.stderr}",
                  file=sys.stderr)
            return 1
        if not artifact.is_file() or not report.is_file():
            print("riscv staged smoke: atomic artifact/report publication is incomplete",
                  file=sys.stderr)
            return 1
        if prove.stdout:
            print("riscv staged smoke: --report-out prove also wrote stdout", file=sys.stderr)
            return 1
        try:
            payload = contracts.strict_json_object(artifact.read_text(), "artifact")
            report_payload = contracts.strict_json_object(report.read_text(), "prove report")
            statement_digest = contracts.require_sha256(
                report_payload.get("statement_sha256"), "prove report.statement_sha256",
            )
            contracts.validate_artifact(
                payload,
                expected_status=expected_status,
                expected_commit=implementation_commit,
                expected_dirty=implementation_dirty,
                elf_sha256=MULTI_SHARD_ELF_SHA256,
                input_sha256=hashlib.sha256(b"").hexdigest(),
                witness_layout_sha256=WITNESS_LAYOUT_SHA256,
            )
            proof_bytes = bytes.fromhex(payload["proof_bytes_hex"])
            contracts.validate_prove_report(
                report_payload,
                expected_status=expected_status,
                experimental=candidate,
                statement_sha256=statement_digest,
                proof_path=str(artifact),
                expected_commit=implementation_commit,
                expected_dirty=implementation_dirty,
                executable_sha256=executable_sha256,
            )
        except (contracts.ContractError, ValueError) as error:
            print(f"riscv staged smoke: {error}", file=sys.stderr)
            return 1
        statement = payload["statement"]
        if statement.get("segment_ordinal") != 0 or statement.get("segment_count") != 1:
            print("riscv staged smoke: artifact segment geometry drifted", file=sys.stderr)
            return 1
        family_counts: dict[int, int] = {}
        for component in payload["statement"]["components"]:
            family = component["family"]
            family_counts[family] = family_counts.get(family, 0) + 1
        if report_payload["total_steps"] != MULTI_SHARD_TOTAL_STEPS or \
                max(family_counts.values(), default=0) < 2:
            print("riscv staged smoke: installed CLI proof did not cross a family shard",
                  file=sys.stderr)
            return 1
        verify = run(
            "verify", "--artifact", str(artifact), "--elf", str(multi_shard_elf),
            "--protocol", "functional",
            "--expect-statement-digest", statement_digest,
        )
        if verify.returncode != 0:
            print(f"riscv staged smoke: honest artifact rejected: {verify.stdout}"
                  f"{verify.stderr}", file=sys.stderr)
            return 1
        try:
            verify_payload = contracts.strict_json_object(verify.stdout, "verify receipt")
            contracts.validate_verify_receipt(
                verify_payload,
                expected_status=expected_status,
                policy="functional",
                statement_sha256=statement_digest,
                proof_bytes=proof_bytes,
                transcript_state_blake2s=report_payload["transcript_state_blake2s"],
                expected_commit=implementation_commit,
                expected_dirty=implementation_dirty,
                executable_sha256=executable_sha256,
            )
        except contracts.ContractError as error:
            print(f"riscv staged smoke: {error}", file=sys.stderr)
            return 1
        wrong_elf = run(
            "verify", "--artifact", str(artifact), "--elf", ELF,
            "--protocol", "functional",
            "--expect-statement-digest", statement_digest,
        )
        if wrong_elf.returncode == 0 or "ElfDigestMismatch" not in wrong_elf.stderr:
            print(
                "riscv staged smoke: artifact accepted against the wrong ELF: "
                f"{wrong_elf.stderr}",
                file=sys.stderr,
            )
            return 1
        verify_receipt_path = Path(tmp) / "verify-receipt.json"
        verify_receipt_path.write_text(verify.stdout)
        claim_order_evidence: dict[str, object] | None = None
        if not fast:
            try:
                claim_swap_payload, claim_swap_indices = mutations.swap_same_family_opcode_claims(
                    json.loads(artifact.read_text())
                )
            except (KeyError, TypeError, ValueError) as error:
                print(f"riscv staged smoke: cannot construct claim-order mutation: {error}",
                      file=sys.stderr)
                return 1
            claim_swap_path = Path(tmp) / "claim-order-swapped.json"
            claim_swap_path.write_text(json.dumps(claim_swap_payload))
            claim_swap = run(
                "verify", "--artifact", str(claim_swap_path),
                "--elf", str(multi_shard_elf), "--protocol", "functional",
                "--expect-statement-digest", statement_digest,
            )
            if claim_swap.returncode == 0 or "OodsNotMatching" not in claim_swap.stderr:
                print("riscv staged smoke: same-family shard claims did not fail as "
                      f"OodsNotMatching: {claim_swap.stderr}", file=sys.stderr)
                return 1
            reverted_claim_swap = run(
                "verify", "--artifact", str(artifact), "--elf", str(multi_shard_elf),
                "--protocol", "functional",
                "--expect-statement-digest", statement_digest,
            )
            if reverted_claim_swap.returncode != 0 or reverted_claim_swap.stderr or \
                    reverted_claim_swap.stdout != verify.stdout:
                print("riscv staged smoke: honest artifact did not recover after claim-order "
                      f"mutation: {reverted_claim_swap.stderr}", file=sys.stderr)
                return 1
            claim_order_evidence = {
                "component_indices": list(claim_swap_indices),
                "artifact_sha256": profiles.sha256_file(claim_swap_path),
                "returncode": claim_swap.returncode,
                "expected_error": "OodsNotMatching",
                "stderr_sha256": contracts.sha256_text(claim_swap.stderr),
                "reverted_receipt_sha256": contracts.sha256_text(
                    reverted_claim_swap.stdout
                ),
            }
        wrong_digest = "00" * 32 if statement_digest != "00" * 32 else "11" * 32
        wrong_statement = run(
            "verify", "--artifact", str(artifact), "--elf", str(multi_shard_elf),
            "--protocol", "functional",
            "--expect-statement-digest", wrong_digest,
        )
        if wrong_statement.returncode == 0:
            print("riscv staged smoke: wrong external statement digest accepted",
                  file=sys.stderr)
            return 1
        downgrade: subprocess.CompletedProcess[str] | None = None
        if not fast:
            downgrade = run(
                "verify", "--artifact", str(artifact), "--elf", str(multi_shard_elf),
                "--expect-statement-digest", statement_digest,
            )
            if downgrade.returncode == 0:
                print("riscv staged smoke: functional artifact passed default secure policy",
                      file=sys.stderr)
                return 1
        payload["statement"]["final_pc"] ^= 4
        tampered = Path(tmp) / "tampered.json"
        tampered.write_text(json.dumps(payload))
        tamper = run(
            "verify", "--artifact", str(tampered), "--elf", str(multi_shard_elf),
            "--protocol", "functional",
            "--expect-statement-digest", statement_digest,
        )
        if tamper.returncode == 0:
            print("riscv staged smoke: TAMPERED ARTIFACT ACCEPTED", file=sys.stderr)
            return 1
        provenance_tampered = Path(tmp) / "provenance-tampered.json"
        payload = json.loads(artifact.read_text())
        payload["provenance"]["witness_layout_sha256"] = "00" * 32
        provenance_tampered.write_text(json.dumps(payload))
        provenance_tamper = run(
            "verify", "--artifact", str(provenance_tampered),
            "--elf", str(multi_shard_elf), "--protocol", "functional",
            "--expect-statement-digest", statement_digest,
        )
        if provenance_tamper.returncode == 0:
            print("riscv staged smoke: MUTATED PROVENANCE ACCEPTED", file=sys.stderr)
            return 1
        expected_wire_errors = {
            "trailing": "TrailingProofBytes",
            "truncated": "EndOfStream",
            "length-bomb": "InvalidProofShape",
        }
        proof_wire_results: dict[str, dict[str, object]] = {}
        proof_wire_cases = mutations.proof_wire(
            json.loads(artifact.read_text())["proof_bytes_hex"]
        )
        if fast:
            proof_wire_cases = {"trailing": proof_wire_cases["trailing"]}
        for mutation, proof_hex in proof_wire_cases.items():
            mutated_payload = json.loads(artifact.read_text())
            mutated_payload["proof_bytes_hex"] = proof_hex
            mutation_path = Path(tmp) / f"proof-{mutation}.json"
            mutation_path.write_text(json.dumps(mutated_payload))
            result = run(
                "verify", "--artifact", str(mutation_path),
                "--elf", str(multi_shard_elf), "--protocol", "functional",
                "--expect-statement-digest", statement_digest,
            )
            expected_error = expected_wire_errors[mutation]
            proof_wire_results[mutation] = {
                "returncode": result.returncode,
                "expected_error": expected_error,
                "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            }
            if result.returncode == 0 or expected_error not in result.stderr:
                print(f"riscv staged smoke: {mutation} proof wire did not fail as "
                      f"{expected_error}: {result.stderr}",
                      file=sys.stderr)
                return 1
        hostile_artifact_results: dict[str, dict[str, object]] = {}
        if not fast:
            artifact_text = artifact.read_text()
            artifact_payload = contracts.strict_json_object(artifact_text, "artifact")
            for mutation, (mutated_text, expected_error) in mutations.hostile_json(
                    artifact_text, artifact_payload).items():
                mutation_path = Path(tmp) / f"artifact-{mutation}.json"
                mutation_path.write_text(mutated_text)
                result = run(
                    "verify", "--artifact", str(mutation_path),
                    "--elf", str(multi_shard_elf), "--protocol", "functional",
                    "--expect-statement-digest", statement_digest,
                )
                expected_errors = (expected_error,)
                if mutation == "corrupt-json":
                    expected_errors = ("SyntaxError", "UnexpectedToken", "UnexpectedEndOfInput")
                hostile_artifact_results[mutation] = {
                    "returncode": result.returncode,
                    "expected_error": expected_error,
                    "stderr_sha256": contracts.sha256_text(result.stderr),
                }
                if result.returncode == 0 or not any(
                        error in result.stderr for error in expected_errors):
                    print(f"riscv staged smoke: hostile {mutation} did not fail closed: "
                          f"{result.stderr}", file=sys.stderr)
                    return 1

        benchmark_evidence: dict[str, object] | None = None
        if not fast:
            bench_args = [
                "bench", "--elf", ELF, "--backend", "cpu", "--protocol", "functional",
                "--warmups", "0", "--samples", "2", "--report-out", str(benchmark_report),
                "--proof-out", str(benchmark_artifact),
            ]
            if candidate:
                bench_args.append("--experimental")
            benchmark = run(*bench_args)
            if benchmark.returncode != 0:
                print(
                    f"riscv staged smoke: benchmark failed: {benchmark.stdout}{benchmark.stderr}",
                    file=sys.stderr,
                )
                return 1
            if benchmark.stdout or not benchmark_artifact.is_file():
                print("riscv staged smoke: benchmark publication contract drifted", file=sys.stderr)
                return 1
            try:
                benchmark_payload = contracts.strict_json_object(
                    benchmark_report.read_text(), "benchmark report",
                )
                benchmark_artifact_payload = contracts.strict_json_object(
                    benchmark_artifact.read_text(), "benchmark artifact",
                )
                contracts.validate_benchmark_report(
                    benchmark_payload,
                    expected_status=expected_status,
                    experimental=candidate,
                    warmups=0,
                    samples=2,
                    proof_path=str(benchmark_artifact),
                    expected_commit=implementation_commit,
                    expected_dirty=implementation_dirty,
                    executable_sha256=executable_sha256,
                    require_resource_availability=sys.platform == "darwin",
                )
                contracts.validate_artifact(
                    benchmark_artifact_payload,
                    expected_status=expected_status,
                    expected_commit=implementation_commit,
                    expected_dirty=implementation_dirty,
                    elf_sha256=ELF_SHA256,
                    input_sha256=hashlib.sha256(b"").hexdigest(),
                    witness_layout_sha256=WITNESS_LAYOUT_SHA256,
                )
                if benchmark_payload["artifact_sha256"] != hashlib.sha256(
                        benchmark_artifact.read_bytes()).hexdigest():
                    raise contracts.ContractError("benchmark artifact digest drifted")
            except contracts.ContractError as error:
                print(f"riscv staged smoke: {error}", file=sys.stderr)
                return 1
            benchmark_statement = benchmark_payload["statement_sha256"]
            benchmark_verify = run(
                "verify", "--artifact", str(benchmark_artifact), "--elf", ELF,
                "--protocol", "functional",
                "--expect-statement-digest", benchmark_statement,
            )
            if benchmark_verify.returncode != 0:
                print(f"riscv staged smoke: retained benchmark proof rejected: "
                      f"{benchmark_verify.stderr}", file=sys.stderr)
                return 1
            try:
                benchmark_verify_payload = contracts.strict_json_object(
                    benchmark_verify.stdout, "benchmark verify receipt",
                )
                contracts.validate_verify_receipt(
                    benchmark_verify_payload,
                    expected_status=expected_status,
                    policy="functional",
                    statement_sha256=benchmark_statement,
                    proof_bytes=bytes.fromhex(benchmark_artifact_payload["proof_bytes_hex"]),
                    transcript_state_blake2s=benchmark_payload["transcript_state_blake2s"],
                    expected_commit=implementation_commit,
                    expected_dirty=implementation_dirty,
                    executable_sha256=executable_sha256,
                )
            except contracts.ContractError as error:
                print(f"riscv staged smoke: {error}", file=sys.stderr)
                return 1
            benchmark_verify_receipt_path = Path(tmp) / "benchmark-verify-receipt.json"
            benchmark_verify_receipt_path.write_text(benchmark_verify.stdout)
            benchmark_evidence = {
                "report_sha256": profiles.sha256_file(benchmark_report),
                "artifact_sha256": profiles.sha256_file(benchmark_artifact),
                "verify_receipt_sha256": contracts.sha256_text(benchmark_verify.stdout),
                "retained_verify_receipt_sha256": profiles.sha256_file(
                    benchmark_verify_receipt_path
                ),
            }

        if hashlib.sha256(cli.read_bytes()).hexdigest() != executable_sha256:
            print("riscv staged smoke: installed executable changed during evidence run",
                  file=sys.stderr)
            return 1

        if args.evidence_dir:
            summary = {
                "schema": (
                    "riscv_cli_evidence_v2" if fast else "riscv_cli_evidence_v1"
                ),
                "profile": args.profile,
                "phase": args.phase,
                "release_status": expected_status,
                "implementation_commit": implementation_commit,
                "implementation_dirty": implementation_dirty,
                "executable_sha256": executable_sha256,
                "cli_origin": cli_origin,
                "producer_receipt": producer_link,
                "coverage": {
                    "installed_cli_identity": "executed",
                    "registry_admission": "executed",
                    "cross_family_shard_proof": "executed",
                    "independent_verification": "executed",
                    "external_statement_tamper": "executed",
                    "artifact_statement_tamper": "executed",
                    "provenance_tamper": "executed",
                    "proof_wire_mutations": sorted(proof_wire_results),
                    "boundary_rejection_matrix": (
                        "executed" if not fast else "producer_receipt"
                    ),
                    "claim_order_mutation": "executed" if not fast else "producer_receipt",
                    "hostile_artifact_matrix": "executed" if not fast else "producer_receipt",
                    "two_sample_benchmark": "executed" if not fast else "producer_receipt",
                },
                "timing": timing_evidence(
                    command_metrics,
                    smoke_started=smoke_started,
                    build_command_count=build_command_count,
                    build_duration_ns=build_duration_ns,
                ),
                "generator": "scripts/riscv_trace_vectors.py::build_release_elf",
                "multi_shard_program": "declared ADDI/BLT loop with halt-flag epilogue",
                "multi_shard_program_words": MULTI_SHARD_PROGRAM_WORDS,
                "multi_shard_addi_rows": MULTI_SHARD_ADDI_ROWS,
                "multi_shard_elf_sha256": MULTI_SHARD_ELF_SHA256,
                "total_steps": report_payload["total_steps"],
                "n_components": report_payload["n_components"],
                "family_component_counts": family_counts,
                "statement_sha256": statement_digest,
                "transcript_state_blake2s": report_payload["transcript_state_blake2s"],
                "artifact_sha256": profiles.sha256_file(artifact),
                "report_sha256": profiles.sha256_file(report),
                "benchmark_report_sha256": (
                    None if benchmark_evidence is None
                    else benchmark_evidence["report_sha256"]
                ),
                "benchmark_artifact_sha256": (
                    None if benchmark_evidence is None
                    else benchmark_evidence["artifact_sha256"]
                ),
                "benchmark_evidence": benchmark_evidence,
                "tampered_artifact_sha256": profiles.sha256_file(tampered),
                "claim_order_swap": claim_order_evidence,
                "independent_verify_returncode": verify.returncode,
                "wrong_statement_returncode": wrong_statement.returncode,
                "policy_downgrade_returncode": (
                    None if downgrade is None else downgrade.returncode
                ),
                "tamper_returncode": tamper.returncode,
                "provenance_tamper_returncode": provenance_tamper.returncode,
                "proof_wire_mutation_returncodes": proof_wire_results,
                "hostile_artifact_results": hostile_artifact_results,
                "boundary_rejection_results": rejection_results,
                "visible_output_sha256": visible_digests,
                "verify_receipt_sha256": contracts.sha256_text(verify.stdout),
                "retained_verify_receipt_sha256": profiles.sha256_file(verify_receipt_path),
                "benchmark_verify_receipt_sha256": (
                    None if benchmark_evidence is None
                    else benchmark_evidence["verify_receipt_sha256"]
                ),
                "retained_benchmark_verify_receipt_sha256": (
                    None if benchmark_evidence is None
                    else benchmark_evidence["retained_verify_receipt_sha256"]
                ),
            }
            (Path(tmp) / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n"
            )
    print(f"riscv {args.phase} {args.profile} smoke: admission, prove, independent verify, "
          "policy, and tamper gates all hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
