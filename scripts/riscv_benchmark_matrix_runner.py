"""Row execution and report assembly for the staged RISC-V matrix."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import platform
import re
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import scripts.riscv_benchmark_matrix_contract as contract
import scripts.riscv_benchmark_matrix_model as model
from scripts import riscv_cli_admission
from scripts.riscv_benchmark_matrix_runtime import (
    DEFAULT_CANDIDATE_CLI,
    DEFAULT_TRACE_CLI,
    METAL,
    MIN_RUST_PARALLELISM,
    PROTOCOL,
    ROOT,
    UNSUPPORTED_PROOF_FAMILY_STDERR,
    Capture,
    EvidenceStore,
    MatrixRunError,
    candidate_identity,
    canonical_digest,
    collect_host_environment,
    file_identity,
    input_args as _input_args,
    prepare_oracle,
    run_capture,
    run_oracle_semantics,
    safe_id as _safe_id,
    semantic_parity,
    semantic_summary as _semantic_summary,
    successful as _successful,
    validate_public_input as _validate_public_input,
)
from scripts.riscv_release_oracle_lib.public_values import (
    PUBLIC_DATA_FIELDS,
    parse_proof_artifact_public_data,
    parse_public_values_diagnostic,
    require_sha256 as require_public_sha256,
    strict_object,
)
from scripts.riscv_staged_smoke_lib import contracts as staged_contracts
from scripts.riscv_stark_v_benchmark import parse_phase_seconds, power_evidence_block


def _sample(
    capture: Capture,
    *,
    iteration: int,
    warmup: bool,
    order_position: int,
    cycles: int,
    phases: dict[str, float],
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    for name, seconds in phases.items():
        if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
            raise MatrixRunError(f"invalid {name} phase timing: {seconds!r}")
    if type(cycles) is not int or cycles <= 0:
        raise MatrixRunError("timing lane did not publish a positive cycle count")
    return {
        "iteration": iteration,
        "warmup": warmup,
        "order_position": order_position,
        "argv": list(capture.argv),
        "duration_ns": capture.duration_ns,
        "cpu_time_ns": capture.cpu_time_ns,
        "cpu_wall_ratio": capture.cpu_wall_ratio,
        "cycles": cycles,
        "phases_seconds": phases,
        "stdout": capture.stdout_identity,
        "stderr": capture.stderr_identity,
        "evidence": evidence,
    }


def _cycles_from_log(raw: bytes) -> int:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", raw.decode(errors="replace"))
    match = re.search(r"completed with (\d+) cycles", clean)
    if match is None:
        raise MatrixRunError("Stark-V timing lane did not publish a cycle count")
    return int(match.group(1))


def _timing_report(
    mode: str,
    warmups: int,
    samples: int,
    orders: list[list[str]],
    candidate_samples: list[dict[str, Any]],
    rust_samples: list[dict[str, Any]],
) -> dict[str, Any]:
    measured_candidate = candidate_samples[warmups:]
    measured_rust = rust_samples[warmups:]
    candidate_seconds = [item["duration_ns"] / 1_000_000_000 for item in measured_candidate]
    rust_seconds = [item["duration_ns"] / 1_000_000_000 for item in measured_rust]
    candidate_median = statistics.median(candidate_seconds)
    rust_median = statistics.median(rust_seconds)
    rust_parallel = statistics.median(item["cpu_wall_ratio"] for item in measured_rust)
    return {
        "mode": mode,
        "clock": "time.monotonic_ns",
        "warmups": warmups,
        "samples": samples,
        "pair_orders": orders,
        "candidate": candidate_samples,
        "stark_v": rust_samples,
        "summary": {
            "candidate_median_seconds": candidate_median,
            "stark_v_median_seconds": rust_median,
            "candidate_over_stark_v": candidate_median / rust_median,
            "stark_v_median_cpu_wall_ratio": rust_parallel,
        },
    }


def _validate_candidate_benchmark(
    payload: dict[str, Any],
    workload: model.Workload,
    candidate: dict[str, Any],
    proof_path: str | None,
    admission: riscv_cli_admission.Admission,
) -> None:
    staged_contracts.validate_benchmark_report(
        payload,
        expected_status=admission.release_status,
        experimental=admission.experimental,
        warmups=0,
        samples=1,
        proof_path=proof_path,
        expected_commit=candidate["commit"],
        expected_dirty=candidate["dirty"],
        executable_sha256=candidate["executables"]["riscv_cpu"]["sha256"],
        require_resource_availability=platform.system() == "Darwin",
    )
    if payload["profiled"] is not False or payload["total_steps"] <= 0:
        raise MatrixRunError(f"{workload.row_id}: candidate benchmark report drifted")
    for field in (
        "median_seconds", "mean_execution_seconds", "mean_witness_seconds",
        "mean_proving_seconds", "mean_verification_seconds",
    ):
        value = payload[field]
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise MatrixRunError(f"{workload.row_id}: invalid candidate {field}")


def _run_candidate_proof_sample(
    candidate_cli: Path,
    workload: model.Workload,
    candidate: dict[str, Any],
    store: EvidenceStore,
    iteration: int,
    warmup: bool,
    order_position: int,
    retain_artifact: bool,
    admission: riscv_cli_admission.Admission,
) -> tuple[dict[str, Any], dict[str, Any], Path | None, dict[str, Any]]:
    safe = _safe_id(workload.row_id)
    report_rel = f"candidate-reports/{safe}.{iteration}.bench.json"
    report_path = store.root / report_rel
    report_path.parent.mkdir(parents=True, exist_ok=True)
    proof_rel = f"proofs/{safe}.proof.json"
    proof_path = store.root / proof_rel if retain_artifact else None
    argv = [
        str(candidate_cli), "bench", "--elf", str(ROOT / workload.elf_rel),
        "--backend", "cpu", "--protocol", "functional", *admission.arguments,
        "--warmups", "0", "--samples", "1", "--report-out", str(report_path),
        *_input_args(workload),
    ]
    if proof_path is not None:
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        argv.extend(["--proof-out", str(proof_path)])
    capture = run_capture(argv, store, f"logs/{safe}.candidate-proof.{iteration}")
    _successful(capture, f"{workload.row_id}: candidate proof sample {iteration}")
    if capture.stdout:
        raise MatrixRunError(f"{workload.row_id}: report-out candidate wrote stdout")
    report = contract.strict_json_file(report_path, f"{workload.row_id} benchmark report")
    _validate_candidate_benchmark(
        report, workload, candidate, str(proof_path) if proof_path is not None else None,
        admission,
    )
    report_identity = file_identity(report_path, path_label=report_rel)
    phases = {
        "execution": float(report["mean_execution_seconds"]),
        "witness": float(report["mean_witness_seconds"]),
        "prove": float(report["mean_proving_seconds"]),
        "verify": float(report["mean_verification_seconds"]),
        "total": float(report["sample_seconds"][0]),
    }
    sample = _sample(
        capture,
        iteration=iteration,
        warmup=warmup,
        order_position=order_position,
        cycles=report["total_steps"],
        phases=phases,
        evidence=report_identity,
    )
    return sample, report, proof_path, report_identity


def _rust_env() -> dict[str, str]:
    return {**os.environ, "RUST_LOG": "info"}


def _run_rust_proof_sample(
    timing_binary: Path,
    workload: model.Workload,
    store: EvidenceStore,
    iteration: int,
    warmup: bool,
    order_position: int,
) -> dict[str, Any]:
    safe = _safe_id(workload.row_id)
    argv = [
        str(timing_binary), "bench", "--elf", str(ROOT / workload.elf_rel),
        "--metrics-out", "/dev/null", *_input_args(workload),
    ]
    capture = run_capture(
        argv, store, f"logs/{safe}.stark-v-proof.{iteration}", env=_rust_env(),
    )
    _successful(capture, f"{workload.row_id}: Stark-V proof sample {iteration}")
    log = capture.stdout + b"\n" + capture.stderr
    clean = re.sub(r"\x1b\[[0-9;]*m", "", log.decode(errors="replace"))
    if "Proof verified successfully" not in clean:
        raise MatrixRunError(f"{workload.row_id}: Stark-V proof did not verify")
    phases = parse_phase_seconds(log.decode(errors="replace"))
    return _sample(
        capture,
        iteration=iteration,
        warmup=warmup,
        order_position=order_position,
        cycles=_cycles_from_log(log),
        phases={
            "execution": phases["execution_seconds"],
            "prove": phases["prove_seconds"],
            "verify": phases["verify_seconds"],
        },
        evidence=None,
    )


def _artifact_public_data(
    proof_path: Path,
    workload: model.Workload,
    candidate: dict[str, Any],
    admission: riscv_cli_admission.Admission,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = contract.strict_json_file(proof_path, f"{workload.row_id} proof artifact")
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        raise MatrixRunError(f"{workload.row_id}: artifact provenance is missing")
    witness = require_public_sha256(
        provenance.get("witness_layout_sha256"), "artifact witness layout",
    )
    public = parse_proof_artifact_public_data(
        proof_path.read_text(encoding="utf-8"),
        candidate=candidate["commit"],
        candidate_dirty=candidate["dirty"],
        release_status=admission.release_status,
        witness_layout_sha256=witness,
        elf_sha256=workload.elf_sha256,
        input_sha256=workload.input_sha256,
    )
    _validate_public_input(public, workload, "candidate artifact")
    return public, payload


def _verify_artifact(
    candidate_cli: Path,
    proof_path: Path,
    proof_payload: dict[str, Any],
    benchmark_report: dict[str, Any],
    candidate: dict[str, Any],
    workload: model.Workload,
    store: EvidenceStore,
    admission: riscv_cli_admission.Admission,
) -> tuple[dict[str, Any], dict[str, Any]]:
    safe = _safe_id(workload.row_id)
    statement = benchmark_report["statement_sha256"]
    argv = [
        str(candidate_cli), "verify", "--artifact", str(proof_path),
        "--elf", str(ROOT / workload.elf_rel),
        "--protocol", "functional", "--expect-statement-digest", statement,
    ]
    capture = run_capture(argv, store, f"logs/{safe}.candidate-verify")
    _successful(capture, f"{workload.row_id}: independent candidate verification")
    receipt = _strict_json(capture.stdout, f"{workload.row_id} verify receipt")
    proof_hex = proof_payload.get("proof_bytes_hex")
    if not isinstance(proof_hex, str):
        raise MatrixRunError(f"{workload.row_id}: artifact proof bytes are missing")
    try:
        proof_bytes = bytes.fromhex(proof_hex)
    except ValueError as error:
        raise MatrixRunError(f"{workload.row_id}: artifact proof bytes are invalid") from error
    staged_contracts.validate_verify_receipt(
        receipt,
        expected_status=admission.release_status,
        policy="functional",
        statement_sha256=statement,
        proof_bytes=proof_bytes,
        transcript_state_blake2s=benchmark_report["transcript_state_blake2s"],
        expected_commit=candidate["commit"],
        expected_dirty=candidate["dirty"],
        executable_sha256=candidate["executables"]["riscv_cpu"]["sha256"],
    )
    receipt_rel = f"verify-receipts/{safe}.verify.json"
    receipt_identity = store.write(receipt_rel, capture.stdout)
    return receipt, receipt_identity


def run_proof_timing(
    row_index: int,
    workload: model.Workload,
    candidate_cli: Path,
    timing_binary: Path,
    candidate: dict[str, Any],
    oracle_public: dict[str, Any],
    store: EvidenceStore,
    warmups: int,
    samples: int,
    admission: riscv_cli_admission.Admission,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    candidate_samples: list[dict[str, Any]] = []
    rust_samples: list[dict[str, Any]] = []
    orders: list[list[str]] = []
    reports: list[dict[str, Any]] = []
    final_proof: Path | None = None
    final_report_identity: dict[str, Any] | None = None
    total = warmups + samples
    for iteration in range(total):
        order = ["candidate", "stark_v"] if (row_index + iteration) % 2 == 0 else ["stark_v", "candidate"]
        orders.append(order)
        retain = iteration == total - 1
        for position, lane in enumerate(order):
            if lane == "candidate":
                sample, report, proof, report_identity = _run_candidate_proof_sample(
                    candidate_cli, workload, candidate, store, iteration,
                    iteration < warmups, position, retain, admission,
                )
                candidate_samples.append(sample)
                reports.append(report)
                if proof is not None:
                    final_proof = proof
                    final_report_identity = report_identity
            else:
                rust_samples.append(_run_rust_proof_sample(
                    timing_binary, workload, store, iteration,
                    iteration < warmups, position,
                ))
    candidate_samples.sort(key=lambda item: item["iteration"])
    rust_samples.sort(key=lambda item: item["iteration"])
    reports_by_iteration = sorted(
        zip(candidate_samples, reports), key=lambda pair: pair[0]["iteration"],
    )
    reports = [pair[1] for pair in reports_by_iteration]
    cycles = oracle_public["clock"]
    if any(sample["cycles"] != cycles for sample in [*candidate_samples, *rust_samples]):
        raise MatrixRunError(f"{workload.row_id}: proof timing cycle parity failed")
    for field in ("statement_sha256", "transcript_state_blake2s", "artifact_sha256"):
        if len({report[field] for report in reports}) != 1:
            raise MatrixRunError(f"{workload.row_id}: candidate {field} is nondeterministic")
    timing = _timing_report(
        "prove_verify", warmups, samples, orders, candidate_samples, rust_samples,
    )
    if (os.cpu_count() or 1) > 1 and timing["summary"]["stark_v_median_cpu_wall_ratio"] < MIN_RUST_PARALLELISM:
        raise MatrixRunError(
            f"{workload.row_id}: Stark-V timing lane looks serial "
            f"({timing['summary']['stark_v_median_cpu_wall_ratio']:.2f} < {MIN_RUST_PARALLELISM})"
        )
    if final_proof is None or final_report_identity is None:
        raise MatrixRunError(f"{workload.row_id}: final candidate proof was not retained")
    artifact_identity = file_identity(
        final_proof,
        path_label=str(final_proof.relative_to(store.root)),
    )
    final_report = reports[-1]
    if artifact_identity["sha256"] != final_report["artifact_sha256"]:
        raise MatrixRunError(f"{workload.row_id}: retained artifact digest differs from report")
    public, proof_payload = _artifact_public_data(
        final_proof, workload, candidate, admission,
    )
    if public != oracle_public:
        semantic_parity(oracle_public, public)
    _receipt, receipt_identity = _verify_artifact(
        candidate_cli, final_proof, proof_payload, final_report, candidate,
        workload, store, admission,
    )
    witness = proof_payload["provenance"]["witness_layout_sha256"]
    proof = {
        "artifact": artifact_identity,
        "benchmark_report": final_report_identity,
        "verification_receipt": receipt_identity,
        "statement_sha256": final_report["statement_sha256"],
        "transcript_state_blake2s": final_report["transcript_state_blake2s"],
        "witness_layout_sha256": witness,
        "verified": True,
    }
    candidate_semantics = _semantic_summary(
        public, artifact_identity, candidate_samples[-1]["duration_ns"],
    )
    return timing, proof, candidate_semantics


def _candidate_diagnostic_public(
    capture: Capture,
    workload: model.Workload,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Bind one ``riscv-trace-dump`` sample to the candidate that must have run it.

    This is where this harness answers the trace-dumper provenance question, and
    it is why it does not also call the CSP harness's
    ``build_identity.read_trace_provenance``: `parse_public_values_diagnostic`
    holds *every* sample -- not one preflight probe -- to the candidate commit,
    the worktree's own dirty flag, the pinned Sail oracle commit, the witness
    layout digest, and the digests of the exact ELF and input this row measures.
    That is a strict superset of the CSP gate's commit-and-dirty check, applied
    per sample rather than once, so adding the CSP gate here would add a weaker
    second copy of a check that already runs (issue #152 item 6b).

    The one difference is deliberate: the CSP gate hard-refuses a dirty build,
    while this binds the dumper's dirty flag to the candidate identity, which is
    what lets ``--allow-dirty`` local diagnostics run while still refusing a
    binary that does not match the tree it claims.
    """
    raw = capture.stdout.decode("utf-8")
    payload = json.loads(raw, object_pairs_hook=strict_object)
    provenance = payload.get("provenance") if isinstance(payload, dict) else None
    if not isinstance(provenance, dict):
        raise MatrixRunError(f"{workload.row_id}: diagnostic provenance is missing")
    witness = require_public_sha256(
        provenance.get("witness_layout_sha256"), "diagnostic witness layout",
    )
    public = parse_public_values_diagnostic(
        raw,
        candidate=candidate["commit"],
        candidate_dirty=candidate["dirty"],
        witness_layout_sha256=witness,
        elf_sha256=workload.elf_sha256,
        input_sha256=workload.input_sha256,
    )
    _validate_public_input(public, workload, "candidate diagnostic")
    return public


def _run_candidate_execution_sample(
    trace_cli: Path,
    workload: model.Workload,
    candidate: dict[str, Any],
    oracle_public: dict[str, Any],
    store: EvidenceStore,
    iteration: int,
    warmup: bool,
    order_position: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    safe = _safe_id(workload.row_id)
    argv = [
        str(trace_cli), "--public-values", str(ROOT / workload.elf_rel),
        "--max-steps", str(workload.max_steps), *_input_args(workload),
    ]
    capture = run_capture(argv, store, f"logs/{safe}.candidate-execution.{iteration}")
    _successful(capture, f"{workload.row_id}: candidate execution sample {iteration}")
    public = _candidate_diagnostic_public(capture, workload, candidate)
    semantic_parity(oracle_public, public)
    sample = _sample(
        capture,
        iteration=iteration,
        warmup=warmup,
        order_position=order_position,
        cycles=public["clock"],
        phases={"execution": capture.duration_ns / 1_000_000_000},
        evidence=None,
    )
    return sample, public


def _run_rust_execution_sample(
    timing_binary: Path,
    workload: model.Workload,
    store: EvidenceStore,
    iteration: int,
    warmup: bool,
    order_position: int,
) -> dict[str, Any]:
    safe = _safe_id(workload.row_id)
    argv = [
        str(timing_binary), "run", "--elf", str(ROOT / workload.elf_rel),
        "--metrics-out", "/dev/null", *_input_args(workload),
    ]
    capture = run_capture(
        argv, store, f"logs/{safe}.stark-v-execution.{iteration}", env=_rust_env(),
    )
    _successful(capture, f"{workload.row_id}: Stark-V execution sample {iteration}")
    return _sample(
        capture,
        iteration=iteration,
        warmup=warmup,
        order_position=order_position,
        cycles=_cycles_from_log(capture.stdout + b"\n" + capture.stderr),
        phases={"execution": capture.duration_ns / 1_000_000_000},
        evidence=None,
    )


def run_execution_timing(
    row_index: int,
    workload: model.Workload,
    trace_cli: Path,
    timing_binary: Path,
    candidate: dict[str, Any],
    oracle_public: dict[str, Any],
    store: EvidenceStore,
    warmups: int,
    samples: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_samples: list[dict[str, Any]] = []
    candidate_public: list[dict[str, Any]] = []
    rust_samples: list[dict[str, Any]] = []
    orders: list[list[str]] = []
    for iteration in range(warmups + samples):
        order = ["candidate", "stark_v"] if (row_index + iteration) % 2 == 0 else ["stark_v", "candidate"]
        orders.append(order)
        for position, lane in enumerate(order):
            if lane == "candidate":
                sample, public = _run_candidate_execution_sample(
                    trace_cli, workload, candidate, oracle_public, store,
                    iteration, iteration < warmups, position,
                )
                candidate_samples.append(sample)
                candidate_public.append(public)
            else:
                rust_samples.append(_run_rust_execution_sample(
                    timing_binary, workload, store, iteration,
                    iteration < warmups, position,
                ))
    candidate_samples.sort(key=lambda item: item["iteration"])
    rust_samples.sort(key=lambda item: item["iteration"])
    cycles = oracle_public["clock"]
    if any(sample["cycles"] != cycles for sample in [*candidate_samples, *rust_samples]):
        raise MatrixRunError(f"{workload.row_id}: execution timing cycle parity failed")
    if any(public != oracle_public for public in candidate_public):
        raise MatrixRunError(f"{workload.row_id}: candidate semantics changed between samples")
    timing = _timing_report(
        "execution", warmups, samples, orders, candidate_samples, rust_samples,
    )
    measured = candidate_samples[warmups:][0]
    measured_public = candidate_public[warmups]
    candidate_semantics = _semantic_summary(
        measured_public, measured["stdout"], measured["duration_ns"],
    )
    return timing, candidate_semantics


def run_expected_rejection(
    candidate_cli: Path,
    workload: model.Workload,
    store: EvidenceStore,
    admission: riscv_cli_admission.Admission,
) -> dict[str, Any]:
    safe = _safe_id(workload.row_id)
    with tempfile.TemporaryDirectory(prefix=f"{safe}.", dir=store.root) as directory:
        temporary = Path(directory)
        proof_path = temporary / "proof.json"
        report_path = temporary / "report.json"
        argv = [
            str(candidate_cli), "prove", "--elf", str(ROOT / workload.elf_rel),
            "--backend", "cpu", "--protocol", "functional", *admission.arguments,
            "--output", str(proof_path), "--report-out", str(report_path),
            *_input_args(workload),
        ]
        capture = run_capture(argv, store, f"logs/{safe}.candidate-rejection")
        residue = sorted(path.name for path in temporary.iterdir())
        rejection = {
            "status": "pass",
            "error": "UnsupportedProofFamily",
            "stage": "statement_validation_before_first_commitment",
            "limitation": "stark-v-signed-mulh",
            "returncode": capture.returncode,
            "stdout_empty": capture.stdout == b"",
            "stderr_exact": capture.stderr == UNSUPPORTED_PROOF_FAMILY_STDERR,
            "proof_artifact_published": proof_path.exists(),
            "report_published": report_path.exists(),
            "temporary_residue": residue,
            "duration_ns": capture.duration_ns,
            "stdout": capture.stdout_identity,
            "stderr": capture.stderr_identity,
        }
    if (
        rejection["returncode"] != 1
        or not rejection["stdout_empty"]
        or not rejection["stderr_exact"]
        or rejection["proof_artifact_published"]
        or rejection["report_published"]
        or rejection["temporary_residue"]
    ):
        raise MatrixRunError(f"{workload.row_id}: exact typed precommit rejection drifted")
    return rejection


def _empty_row(workload: model.Workload) -> dict[str, Any]:
    return {
        "id": workload.row_id,
        "suite": workload.suite,
        "class": workload.row_class,
        "status": "failed",
        "fixture": workload.fixture,
        "metal": METAL,
        "oracle_semantics": None,
        "candidate_semantics": None,
        "semantic_parity": None,
        "timing": None,
        "proof": None,
        "rejection": None,
        "error": None,
    }


def run_row(
    index: int,
    workload: model.Workload,
    *,
    candidate_cli: Path,
    trace_cli: Path,
    cp11: Path,
    timing_binary: Path,
    candidate: dict[str, Any],
    store: EvidenceStore,
    warmups: int,
    samples: int,
    admission: riscv_cli_admission.Admission,
) -> dict[str, Any]:
    row = _empty_row(workload)
    try:
        oracle_public, oracle_summary = run_oracle_semantics(cp11, workload, store)
        row["oracle_semantics"] = oracle_summary
        if workload.row_class == "proof":
            timing, proof, candidate_summary = run_proof_timing(
                index, workload, candidate_cli, timing_binary, candidate,
                oracle_public, store, warmups, samples,
                admission,
            )
            row["timing"] = timing
            row["proof"] = proof
        else:
            timing, candidate_summary = run_execution_timing(
                index, workload, trace_cli, timing_binary, candidate,
                oracle_public, store, warmups, samples,
            )
            row["timing"] = timing
            if workload.row_class == "expected_rejection":
                row["rejection"] = run_expected_rejection(
                    candidate_cli, workload, store, admission,
                )
        row["candidate_semantics"] = candidate_summary
        candidate_public_digest = candidate_summary["public_data_sha256"]
        oracle_digest = canonical_digest(oracle_public)
        if candidate_public_digest != oracle_digest:
            raise MatrixRunError(f"{workload.row_id}: candidate summary lost semantic parity")
        row["semantic_parity"] = {
            "status": "pass",
            "fields": list(PUBLIC_DATA_FIELDS),
            "mismatches": [],
            "public_data_sha256": oracle_digest,
        }
        row["status"] = "ok"
    except (
        MatrixRunError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        staged_contracts.ContractError,
    ) as error:
        row["error"] = str(error) or type(error).__name__
    return row


def _selection(
    all_workloads: list[model.Workload], selected: list[model.Workload],
) -> dict[str, Any]:
    counts = {
        name: sum(workload.row_class == name for workload in selected)
        for name in model.FULL_COUNTS
    }
    complete = len(selected) == len(all_workloads) and all(
        left.row_id == right.row_id for left, right in zip(selected, all_workloads)
    )
    return {
        "mode": "full" if complete else "filtered",
        "complete": complete,
        "expected_full_counts": model.FULL_COUNTS,
        "selected_counts": counts,
        "expected_full_row_count": len(all_workloads),
        "selected_row_count": len(selected),
        "row_ids": [workload.row_id for workload in selected],
    }


def produce(
    *,
    stark_v_source: Path,
    artifact_dir: Path,
    report_out: Path,
    candidate_cli: Path = DEFAULT_CANDIDATE_CLI,
    trace_cli: Path = DEFAULT_TRACE_CLI,
    cache_dir: Path | None = None,
    warmups: int = 1,
    samples: int = 3,
    selected_ids: list[str] | None = None,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    if not 0 <= warmups <= 10 or not 1 <= samples <= 21:
        raise MatrixRunError("warmups must be 0..10 and samples must be 1..21")
    all_workloads, fixtures = model.load_workloads(ROOT)
    by_id = {workload.row_id: workload for workload in all_workloads}
    if selected_ids:
        unknown = sorted(set(selected_ids) - set(by_id))
        if unknown:
            raise MatrixRunError(f"unknown matrix row IDs: {', '.join(unknown)}")
        wanted = set(selected_ids)
        selected = [workload for workload in all_workloads if workload.row_id in wanted]
    else:
        selected = all_workloads
    if not selected:
        raise MatrixRunError("matrix selection is empty")
    candidate_cli = candidate_cli.resolve(strict=True)
    trace_cli = trace_cli.resolve(strict=True)
    admission = riscv_cli_admission.resolve(candidate_cli, cwd=ROOT)
    candidate = candidate_identity(candidate_cli, trace_cli, allow_dirty=allow_dirty)
    # Captured before the first sample so an operator sees a throttled host while
    # the run is still worth aborting, not after 32 rows of it. The evidence rides
    # in the shared host block, where `contract.validate_host_environment` admits
    # it and re-derives the verdict from it (issue #152 item 6c).
    power = power_evidence_block()
    if not power["admissible"]:
        print(f"[power] {'; '.join(power['reasons'])}", flush=True)
    store = EvidenceStore(artifact_dir)
    cp11, timing_binary, oracle = prepare_oracle(stark_v_source, cache_dir, store)
    started = time.monotonic_ns()
    rows: list[dict[str, Any]] = []
    for index, workload in enumerate(selected):
        print(f"riscv matrix [{index + 1}/{len(selected)}] {workload.row_id}", flush=True)
        row = run_row(
            index,
            workload,
            candidate_cli=candidate_cli,
            trace_cli=trace_cli,
            cp11=cp11,
            timing_binary=timing_binary,
            candidate=candidate,
            store=store,
            warmups=warmups,
            samples=samples,
            admission=admission,
        )
        rows.append(row)
        print(f"  {row['status']}{': ' + row['error'] if row['error'] else ''}", flush=True)
    duration = max(1, time.monotonic_ns() - started)
    failures = sum(row["status"] == "failed" for row in rows)
    selection = _selection(all_workloads, selected)
    final_candidate = candidate_identity(candidate_cli, trace_cli, allow_dirty=allow_dirty)
    if final_candidate != candidate:
        raise MatrixRunError("candidate source or executable identity changed during the matrix run")
    final_workloads, final_fixtures = model.load_workloads(ROOT)
    if final_workloads != all_workloads or final_fixtures != fixtures:
        raise MatrixRunError("fixture identities changed during the matrix run")
    if file_identity(cp11)["sha256"] != oracle["correctness"]["executable_sha256"]:
        raise MatrixRunError(
            "legacy Stark-V execution comparator changed during the matrix run"
        )
    if file_identity(timing_binary)["sha256"] != oracle["timing"]["executable"]["sha256"]:
        raise MatrixRunError("Stark-V timing executable changed during the matrix run")
    report = {
        "schema": contract.SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": "PASS" if failures == 0 else "FAIL",
        "evidence_class": contract.EVIDENCE_CLASS,
        "promotion_eligible": False,
        "duration_ns": duration,
        "candidate": candidate,
        "oracle": oracle,
        "fixtures": fixtures,
        "protocol": PROTOCOL,
        "metal": METAL,
        "host_environment": collect_host_environment(
            stark_v_source.resolve(), power_conditions=power,
        ),
        "timing_policy": {
            "clock": "time.monotonic_ns",
            "pairing": "alternating_candidate_and_stark_v_order_per_external_sample",
            "candidate_proof_sampling": "one_verified_proof_per_external_sample",
            "stark_v_phase_source": "bench_cli_tracing_timestamps",
            "warmups_excluded_from_summary": True,
            "rust_feature_required": "parallel",
            "min_stark_v_cpu_wall_ratio_on_multicore_proof_rows": MIN_RUST_PARALLELISM,
            "environment": {"stark_v": {"RUST_LOG": "info"}, "candidate": "inherited"},
        },
        "selection": selection,
        "artifact_root": str(store.root),
        "rows": rows,
        "summary": {
            "row_count": len(rows),
            "ok_count": len(rows) - failures,
            "failure_count": failures,
            "class_counts": selection["selected_counts"],
        },
    }
    contract.validate_report(
        report,
        expected_row_ids=[workload.row_id for workload in selected],
    )
    contract.validate_artifact_tree(report, store.root)
    report_out = report_out.resolve()
    report_out.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_out.with_name(f".{report_out.name}.{os.getpid()}.tmp")
    temporary.write_bytes(json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    os.replace(temporary, report_out)
    return report
