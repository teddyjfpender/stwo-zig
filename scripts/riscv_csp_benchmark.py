#!/usr/bin/env python3
"""Run the pinned EthProofs CSP suite through the RISC-V CPU product.

The ordinary benchmark is self-contained: committed inputs and RV32IM guest
ELFs are authenticated by ``vectors/riscv_csp/manifest-v2.json``.  Passing
``--audit-csp-source`` additionally checks an external checkout of the pinned
CSP repository and regenerates every canonical input from the pinned upstream
generators.

The CSP-compatible proving duration is execution + witness construction + proof
generation.  Verification is reported separately.  The production CLI still
self-verifies every sample before publication; its internal stage timers keep
that mandatory verification out of the proving-duration metric.
"""

from __future__ import annotations

import argparse
import datetime as dt
import inspect
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import riscv_cli_admission  # noqa: E402
from scripts.riscv_csp_benchmark_lib.contract import (  # noqa: E402
    BACKENDS,
    BenchmarkError,
    CANONICAL_SIZES,
    Case,
    DEFAULT_CLI,
    DEFAULT_REPORT,
    DEFAULT_TRACE_CLI,
    HEX_32,
    HEX_40,
    MANIFEST,
    MAX_CAPTURE_BYTES,
    NegativeCase,
    SECURE_PCS_CONFIG,
    TARGET_ORDER,
    TARGET_SIZES,
    _strict_object,
    load_json,
    sha256_bytes,
    sha256_file,
    validate_manifest,
)
from scripts.riscv_csp_benchmark_lib.host import (  # noqa: E402
    collect_host,
    official_host_match,
)
from scripts.riscv_csp_benchmark_lib.source_audit import (  # noqa: E402
    audit_csp_source,
)
from scripts.riscv_csp_benchmark_lib.validation import (  # noqa: E402
    validate_artifact,
    validate_benchmark_report,
    validate_verify_receipt,
)


SCHEMA = "stwo_riscv_csp_benchmark_v2"
MAX_EXECUTION_STEPS = 10_000_000


def _run(
    argv: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(value) for value in argv]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=None if env is None else dict(env),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BenchmarkError(f"cannot run {command[0]}: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace")[-2000:]
        stdout = completed.stdout.decode("utf-8", "replace")[-2000:]
        raise BenchmarkError(
            f"command exited {completed.returncode}: {' '.join(command)}\n"
            f"{stderr or stdout}"
        )
    return completed


def _git_output(*args: str, cwd: Path = ROOT) -> str:
    return _run(["git", *args], cwd=cwd, timeout=30).stdout.decode().strip()


def _command_text(argv: Sequence[str], *, cwd: Path = ROOT) -> str:
    return _run(argv, cwd=cwd, timeout=30).stdout.decode("utf-8", "replace").strip()


def reconstruct_public_output(public_values: Mapping[str, Any]) -> bytes:
    if public_values.get("schema") != "riscv-public-values-diagnostic-v1":
        raise BenchmarkError("public-values diagnostic schema drifted")
    public_data = public_values.get("public_data")
    if not isinstance(public_data, dict):
        raise BenchmarkError("public-values diagnostic has no public_data object")
    io = public_data.get("io_entries")
    if not isinstance(io, dict):
        raise BenchmarkError("public-values diagnostic has no io_entries object")
    output_len = io.get("output_len")
    output_len_addr = io.get("output_len_addr")
    output_data_addr = io.get("output_data_addr")
    words = io.get("output_words")
    if (
        not isinstance(output_len, int)
        or isinstance(output_len, bool)
        or output_len < 0
        or not isinstance(output_len_addr, int)
        or not isinstance(output_data_addr, int)
        or not isinstance(words, list)
        or not words
    ):
        raise BenchmarkError("public output framing is invalid")
    length_word = words[0]
    if (
        not isinstance(length_word, dict)
        or length_word.get("addr") != output_len_addr
        or length_word.get("value") != output_len
    ):
        raise BenchmarkError("public output length word is invalid")
    expected_data_words = (output_len + 3) // 4
    if len(words) != expected_data_words + 1:
        raise BenchmarkError("public output word count is invalid")
    encoded = bytearray()
    for index, word in enumerate(words[1:]):
        if (
            not isinstance(word, dict)
            or word.get("addr") != output_data_addr + index * 4
            or not isinstance(word.get("value"), int)
            or isinstance(word.get("value"), bool)
            or not 0 <= word["value"] <= 0xFFFF_FFFF
        ):
            raise BenchmarkError("public output word is invalid")
        encoded.extend(struct.pack("<I", word["value"]))
    if any(encoded[output_len:]):
        raise BenchmarkError("public output padding is nonzero")
    return bytes(encoded[:output_len])


def _execute_guest(
    *,
    label: str,
    guest_path: Path,
    input_path: Path,
    expected_digest: str,
    expected_cycles: int,
    trace_cli: Path,
    timeout: int,
) -> dict[str, Any]:
    completed = _run(
        [
            trace_cli,
            "--public-values",
            guest_path,
            "--input",
            input_path,
            "--max-steps",
            str(MAX_EXECUTION_STEPS),
        ],
        timeout=timeout,
    )
    if len(completed.stdout) > MAX_CAPTURE_BYTES:
        raise BenchmarkError(f"{label}: public values are oversized")
    try:
        public_values = json.loads(completed.stdout, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"{label}: invalid public-values JSON") from error
    output = reconstruct_public_output(public_values)
    if output.hex() != expected_digest:
        raise BenchmarkError(f"{label}: digest mismatch")
    public_data = public_values["public_data"]
    cycles = public_data.get("clock")
    if cycles != expected_cycles:
        raise BenchmarkError(
            f"{label}: cycles={cycles}, expected={expected_cycles}"
        )
    return {
        "cycles": cycles,
        "output_digest": output.hex(),
        "public_values_sha256": sha256_bytes(completed.stdout),
    }


def execute_case(case: Case, trace_cli: Path, timeout: int) -> dict[str, Any]:
    return _execute_guest(
        label=f"{case.target}/{case.input_size}",
        guest_path=case.guest_path,
        input_path=case.input_path,
        expected_digest=case.expected_digest,
        expected_cycles=case.expected_cycles,
        trace_cli=trace_cli,
        timeout=timeout,
    )


def execute_negative_case(
    case: NegativeCase,
    trace_cli: Path,
    timeout: int,
) -> dict[str, Any]:
    evidence = _execute_guest(
        label=f"negative/{case.name}",
        guest_path=case.guest_path,
        input_path=case.input_path,
        expected_digest=case.expected_digest,
        expected_cycles=case.expected_cycles,
        trace_cli=trace_cli,
        timeout=timeout,
    )
    return {
        "name": case.name,
        "target": case.target,
        "status": "rejected_as_expected",
        "input_sha256": case.input_sha256,
        "output_digest": evidence["output_digest"],
        "cycles": evidence["cycles"],
        "public_values_sha256": evidence["public_values_sha256"],
    }


def _phase_seconds(report: Mapping[str, Any]) -> tuple[float, float]:
    phase_names = (
        "mean_execution_seconds",
        "mean_witness_seconds",
        "mean_proving_seconds",
        "mean_verification_seconds",
    )
    phases: dict[str, float] = {}
    for name in phase_names:
        value = report.get(name)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value < 0
        ):
            raise BenchmarkError(f"benchmark report has invalid {name}")
        phases[name] = float(value)
    prove = (
        phases["mean_execution_seconds"]
        + phases["mean_witness_seconds"]
        + phases["mean_proving_seconds"]
    )
    return prove, phases["mean_verification_seconds"]


def _peak_memory(report: Mapping[str, Any]) -> tuple[int | None, str]:
    resources = report.get("resources")
    if not isinstance(resources, dict):
        return None, "benchmark report has no resources object"
    if resources.get("availability") != "available":
        reason = resources.get("unavailable_reason")
        return None, str(reason or "resource telemetry unavailable")
    after = resources.get("after_verified_samples")
    if not isinstance(after, dict):
        return None, "resource telemetry has no after-samples snapshot"
    value = after.get("lifetime_max_phys_footprint_bytes")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None, "resource telemetry has no positive peak footprint"
    return value, str(resources.get("source") or "unknown")


def benchmark_case(
    case: Case,
    cli: Path,
    trace_cli: Path,
    *,
    backend: str,
    warmups: int,
    samples: int,
    timeout: int,
    admission: riscv_cli_admission.Admission,
    env: Mapping[str, str],
    work_dir: Path,
) -> tuple[dict[str, Any], str]:
    execution = execute_case(case, trace_cli, timeout)
    stem = f"{case.target}_{case.input_size}"
    bench_path = work_dir / f"{stem}.bench.json"
    artifact_path = work_dir / f"{stem}.proof.json"
    command = [
        cli,
        "bench",
        "--elf",
        case.guest_path,
        "--input",
        case.input_path,
        "--backend",
        BACKENDS[backend].cli_value,
        "--protocol",
        "secure",
        *admission.arguments,
        "--warmups",
        str(warmups),
        "--samples",
        str(samples),
        "--proof-out",
        artifact_path,
        "--report-out",
        bench_path,
    ]
    wall_start = time.monotonic_ns()
    completed = _run(command, env=env, timeout=timeout)
    wall_duration_ns = time.monotonic_ns() - wall_start
    report = load_json(bench_path)
    if not isinstance(report, dict):
        raise BenchmarkError(f"{case.target}/{case.input_size}: report is not an object")
    implementation_commit = validate_benchmark_report(
        report,
        case,
        warmups=warmups,
        samples=samples,
        admission=admission,
    )
    artifact = load_json(artifact_path)
    if not isinstance(artifact, dict):
        raise BenchmarkError(f"{case.target}/{case.input_size}: artifact is not an object")
    proof_bytes, proof_sha256 = validate_artifact(
        artifact,
        case,
        admission=admission,
        expected_backend=BACKENDS[backend].artifact_backend,
    )
    artifact_sha256 = sha256_file(artifact_path)
    if report.get("artifact_sha256") != artifact_sha256:
        raise BenchmarkError(f"{case.target}/{case.input_size}: artifact digest drifted")

    statement_digest = report["statement_sha256"]
    verify_start = time.monotonic_ns()
    verify = _run(
        [
            cli,
            "verify",
            "--artifact",
            artifact_path,
            "--elf",
            case.guest_path,
            "--protocol",
            "secure",
            "--expect-statement-digest",
            statement_digest,
        ],
        env=env,
        timeout=timeout,
    )
    retained_verify_wall_ns = time.monotonic_ns() - verify_start
    try:
        receipt = json.loads(verify.stdout, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: retained-proof receipt is invalid"
        ) from error
    if not isinstance(receipt, dict):
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: retained-proof receipt is not an object"
        )
    validate_verify_receipt(
        receipt,
        case,
        statement_digest=statement_digest,
        proof_bytes=proof_bytes,
        proof_sha256=proof_sha256,
        implementation_commit=implementation_commit,
    )

    prove_seconds, verify_seconds = _phase_seconds(report)
    peak_memory, memory_source = _peak_memory(report)
    sample_seconds = report.get("sample_seconds")
    if (
        not isinstance(sample_seconds, list)
        or len(sample_seconds) != samples
        or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value <= 0
            for value in sample_seconds
        )
    ):
        raise BenchmarkError(f"{case.target}/{case.input_size}: sample series drifted")
    row = {
        "system": "stwo-zig-riscv",
        "backend": backend,
        "target": case.target,
        "input_size": case.input_size,
        "proof_duration": round(prove_seconds * 1_000_000_000),
        "verify_duration": round(verify_seconds * 1_000_000_000),
        "cycles": execution["cycles"],
        "proof_size": len(proof_bytes),
        "preprocessing_size": case.guest_bytes,
        "num_constraints": 0,
        "peak_memory": peak_memory,
        "uses_precompile": case.uses_precompile,
        "evidence": {
            "status": "verified",
            "input_sha256": case.input_sha256,
            "guest_sha256": case.guest_sha256,
            "output_digest": execution["output_digest"],
            "expected_output_digest": case.expected_digest,
            "public_values_sha256": execution["public_values_sha256"],
            "statement_sha256": statement_digest,
            "proof_sha256": proof_sha256,
            "artifact_sha256": artifact_sha256,
            "artifact_bytes": artifact_path.stat().st_size,
            "retained_verify_wall_ns": retained_verify_wall_ns,
            "retained_verify_receipt": receipt,
        },
        "timing": {
            "source": "production CLI internal stage timers",
            "proof_definition": "execution + witness + proof generation",
            "verify_definition": "production proof verification",
            "mean_execution_seconds": report["mean_execution_seconds"],
            "mean_witness_seconds": report["mean_witness_seconds"],
            "mean_proving_seconds": report["mean_proving_seconds"],
            "mean_verification_seconds": report["mean_verification_seconds"],
            "median_end_to_end_seconds": report["median_seconds"],
            "verified_end_to_end_sample_seconds": sample_seconds,
            "outer_command_wall_ns": wall_duration_ns,
        },
        "memory": {
            "source": memory_source,
            "scope": "self-process lifetime peak across verified samples",
            "includes_mandatory_self_verification": True,
        },
        "protocol": {
            "name": "secure",
            "pcs_config": SECURE_PCS_CONFIG,
        },
        "prover_log_sha256": sha256_bytes(completed.stdout + completed.stderr),
    }
    return row, implementation_commit


def _parse_csv(raw: str, allowed: Iterable[str], label: str) -> tuple[str, ...]:
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    allowed_set = set(allowed)
    if not values or len(set(values)) != len(values) or any(v not in allowed_set for v in values):
        raise BenchmarkError(f"invalid {label}: {raw!r}")
    return values


def _parse_sizes(raw: str) -> tuple[int, ...]:
    try:
        sizes = tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as error:
        raise BenchmarkError(f"invalid sizes: {raw!r}") from error
    if (
        not sizes
        or len(set(sizes)) != len(sizes)
        or any(size not in CANONICAL_SIZES for size in sizes)
    ):
        raise BenchmarkError(f"invalid sizes: {raw!r}")
    return sizes


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise BenchmarkError(f"temporary report already exists: {temporary}")
    try:
        with temporary.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _summary(
    rows: Sequence[Mapping[str, Any]],
    negative_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "row_count": len(rows),
        "target_count": len({row["target"] for row in rows}),
        "all_outputs_match": all(
            row["evidence"]["output_digest"]
            == row["evidence"]["expected_output_digest"]
            for row in rows
        ),
        "all_proofs_verified": all(
            row["evidence"]["status"] == "verified" for row in rows
        ),
        "all_peak_memory_available": all(row["peak_memory"] is not None for row in rows),
        "all_negative_fixtures_rejected": all(
            item["status"] == "rejected_as_expected"
            for item in negative_evidence
        ),
    }


def _resolve_backend_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    """Resolve the product CLI and report output for the selected backend.

    Explicit ``--cli`` / ``--report-out`` always win; the defaults come from
    the backend table so a Metal run can never silently overwrite the
    committed CPU evidence file.
    """
    spec = BACKENDS[args.backend]
    cli = args.cli if args.cli is not None else spec.default_cli
    report_out = (
        args.report_out if args.report_out is not None else spec.default_report
    )
    return cli.resolve(), report_out.resolve()


def _resolve_admission(cli: Path, backend: str) -> riscv_cli_admission.Admission:
    """Authenticate the product registry of the executable about to run.

    ``riscv_cli_admission`` is a shared module owned by another change; until
    it accepts a ``backend`` parameter, CPU admission is byte-for-byte the
    historical call and any non-CPU backend fails closed rather than being
    admitted through the CPU-only registry contract.
    """
    parameters = inspect.signature(riscv_cli_admission.resolve).parameters
    if "backend" in parameters:
        return riscv_cli_admission.resolve(cli, cwd=ROOT, backend=backend)
    if backend == "cpu":
        return riscv_cli_admission.resolve(cli, cwd=ROOT)
    raise BenchmarkError(
        f"riscv_cli_admission cannot authenticate a {backend} product "
        "registry yet; refusing to admit a non-CPU backend through the "
        "CPU-only registry contract"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--backend", choices=tuple(BACKENDS), default="cpu")
    parser.add_argument("--cli", type=Path, default=None)
    parser.add_argument("--trace-cli", type=Path, default=DEFAULT_TRACE_CLI)
    parser.add_argument("--report-out", type=Path, default=None)
    parser.add_argument("--targets", default=",".join(TARGET_ORDER))
    parser.add_argument("--sizes", default=",".join(str(v) for v in CANONICAL_SIZES))
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--audit-csp-source", type=Path)
    args = parser.parse_args(argv)

    if not 0 <= args.warmups <= 10:
        raise BenchmarkError("--warmups must be between 0 and 10")
    if not 1 <= args.samples <= 21:
        raise BenchmarkError("--samples must be between 1 and 21")
    if args.workers is not None and not 1 <= args.workers <= 32:
        raise BenchmarkError("--workers must be between 1 and 32")
    if args.timeout <= 0:
        raise BenchmarkError("--timeout must be positive")

    targets = _parse_csv(args.targets, TARGET_ORDER, "targets")
    sizes = _parse_sizes(args.sizes)
    manifest, all_cases, all_negative_cases = validate_manifest(
        args.manifest.resolve()
    )
    selected = [
        case
        for case in all_cases
        if case.target in targets and case.input_size in sizes
    ]
    if not selected:
        raise BenchmarkError("benchmark selection is empty")

    spec = BACKENDS[args.backend]
    cli, report_out = _resolve_backend_paths(args)
    trace_cli = args.trace_cli.resolve()
    for label, executable in (("RISC-V product", cli), ("trace diagnostic", trace_cli)):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            hint = (
                " (the Metal product CLI must be built on a macOS host: "
                "`zig build stwo-riscv-metal -Doptimize=ReleaseFast`)"
                if executable == cli and args.backend == "metal"
                else ""
            )
            raise BenchmarkError(
                f"{label} executable is missing: {executable}{hint}"
            )
    admission = _resolve_admission(cli, args.backend)
    source_audit = (
        audit_csp_source(manifest, args.audit_csp_source)
        if args.audit_csp_source
        else {"status": "not_requested"}
    )
    selected_negative = [
        case for case in all_negative_cases if case.target in targets
    ]
    negative_evidence: list[dict[str, Any]] = []
    for case in selected_negative:
        print(f"[negative] {case.name}: execute and reject", flush=True)
        negative_evidence.append(
            execute_negative_case(case, trace_cli, args.timeout)
        )

    host = collect_host()
    host_matches, host_mismatch = official_host_match(host, backend=args.backend)
    if spec.requires_gpu and not (host.get("gpu") or {}).get("name"):
        raise BenchmarkError(
            f"{args.backend} benchmark requires GPU identity capture "
            "(system_profiler SPDisplaysDataType); refusing to record "
            "GPU-dependent timings without GPU identity"
        )
    env = os.environ.copy()
    environment_overrides: dict[str, str] = {}
    if args.workers is not None:
        for name in ("STWO_ZIG_WORKERS", "STWO_ZIG_MERKLE_WORKERS"):
            env[name] = str(args.workers)
            environment_overrides[name] = str(args.workers)
    else:
        for name in ("STWO_ZIG_WORKERS", "STWO_ZIG_MERKLE_WORKERS"):
            if name in env:
                environment_overrides[name] = env[name]

    rows: list[dict[str, Any]] = []
    commits: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="stwo-riscv-csp-") as temporary:
        work_dir = Path(temporary)
        for index, case in enumerate(selected, start=1):
            print(
                f"[{index}/{len(selected)}] {case.target}/{case.input_size}: "
                f"execute, prove, verify",
                flush=True,
            )
            row, commit = benchmark_case(
                case,
                cli,
                trace_cli,
                backend=args.backend,
                warmups=args.warmups,
                samples=args.samples,
                timeout=args.timeout,
                admission=admission,
                env=env,
                work_dir=work_dir,
            )
            commits.add(commit)
            rows.append(row)
            print(
                f"  prove={row['proof_duration'] / 1e9:.3f}s "
                f"verify={row['verify_duration'] / 1e9:.3f}s "
                f"proof={row['proof_size'] / 1024:.1f}KiB "
                f"rss={row['peak_memory'] / 1024**3:.2f}GiB"
                if row["peak_memory"] is not None
                else
                f"  prove={row['proof_duration'] / 1e9:.3f}s "
                f"verify={row['verify_duration'] / 1e9:.3f}s "
                f"proof={row['proof_size'] / 1024:.1f}KiB rss=unavailable",
                flush=True,
            )
    if len(commits) != 1:
        raise BenchmarkError(f"rows used multiple implementation commits: {sorted(commits)}")
    measurement_commit = commits.pop()
    repository_head = _git_output("rev-parse", "HEAD")
    if repository_head != measurement_commit:
        raise BenchmarkError(
            f"binary commit {measurement_commit} differs from repository HEAD {repository_head}"
        )

    complete_matrix = (
        targets == TARGET_ORDER
        and sizes == CANONICAL_SIZES
        and len(rows) == sum(len(values) for values in TARGET_SIZES.values())
    )
    memory_available = all(row["peak_memory"] is not None for row in rows)
    official_comparable = host_matches and complete_matrix and memory_available
    limitations = [
        "The secure profile's 96-bit total is heuristic pending the external "
        "PCS/FRI/Fiat-Shamir accounting review.",
        "Peak footprint includes mandatory self-verification; proving dominates "
        "the observed peak, but this is conservative relative to CSP's prove-only "
        "memory process.",
        "No result is uploaded to EthProofs by this command.",
    ]
    if not host_matches:
        limitations.append(
            "This host differs from CSP's AWS mac2.metal Apple M1/8-core/16-GiB "
            "publication host, so timings are host-qualified and not directly "
            "rankable against published EthProofs rows."
        )
    if args.backend != "cpu":
        limitations.append(
            f"Rows were produced with the {args.backend} backend; "
            "GPU-dependent timings are qualified by host.gpu, and the "
            "committed CPU report remains the canonical CSP evidence."
        )

    captured_at = dt.datetime.now(dt.timezone.utc).astimezone().isoformat()
    report = {
        "schema": SCHEMA,
        "captured_at": captured_at,
        "measurement_commit": measurement_commit,
        "repository_head": repository_head,
        "suite_manifest": str(args.manifest.resolve().relative_to(ROOT)),
        "suite_manifest_sha256": sha256_file(args.manifest.resolve()),
        "upstream": manifest["upstream"],
        "source_audit": source_audit,
        "system": {
            "id": "stwo-zig-riscv",
            "proving_system": "Circle STARK",
            "field_curve": "M31",
            "iop": "Circle FRI",
            "pcs": "Circle-PCS",
            "arithm": "AIR",
            "is_zk": False,
            "is_zkvm": True,
            "security_bits": 96,
            "security_status": "heuristic_pending_external_review",
            "is_pq": True,
            "is_maintained": True,
            "is_audited": "not_audited",
            "isa": "RISC-V RV32IM",
        },
        "security": {
            "profile": "secure",
            "pcs_config": SECURE_PCS_CONFIG,
            "csp_minimum_bits": 96,
            "eligibility": "parameter_threshold_met_accounting_review_pending",
        },
        "methodology": {
            "canonical_inputs": True,
            "canonical_sizes": list(CANONICAL_SIZES),
            "target_sizes": {
                target: list(TARGET_SIZES[target]) for target in TARGET_ORDER
            },
            "uses_precompile": False,
            "proof_duration": "mean execution + witness + proof generation",
            "verify_duration": "mean production verification",
            "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
            "preprocessing_size": "retained RV32IM ELF bytes",
            "peak_memory": "production process lifetime physical-footprint peak",
            "num_constraints": "0 means not exposed; cycles are authoritative",
            "official_csp_host": {
                "provider": "AWS",
                "instance": "mac2.metal",
                "cpu": "Apple M1",
                "logical_cpu_count": 8,
                "memory_bytes": 16 * 1024 * 1024 * 1024,
                "gpu": {"chip": "Apple M1", "core_count": 8},
            },
        },
        "host": host,
        "host_matches_official_csp": host_matches,
        "host_mismatch_reasons": host_mismatch,
        "result_class": (
            "official-host-comparable"
            if official_comparable
            else "host-qualified-non-comparable"
        ),
        "run": {
            "backend": args.backend,
            "targets": list(targets),
            "sizes": list(sizes),
            "warmups": args.warmups,
            "samples": args.samples,
            "workers": args.workers,
            "environment_overrides": environment_overrides,
            "complete_matrix": complete_matrix,
            "release_status": admission.release_status,
            "experimental": admission.experimental,
        },
        "identities": {
            "prover_executable": str(cli.relative_to(ROOT)),
            "prover_executable_sha256": sha256_file(cli),
            "trace_executable": str(trace_cli.relative_to(ROOT)),
            "trace_executable_sha256": sha256_file(trace_cli),
            "zig_version": _command_text(["zig", "version"]),
        },
        "coverage": {
            "supported_targets": list(TARGET_ORDER),
            "unsupported_targets": manifest["unsupported_targets"],
        },
        "limitations": limitations,
        "negative_validation": negative_evidence,
        "summary": _summary(rows, negative_evidence),
        "measurements": rows,
    }
    _atomic_write_json(report_out, report)
    print(f"report: {report_out}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
