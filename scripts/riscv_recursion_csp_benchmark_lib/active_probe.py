"""Fail-closed collector for the active recursive-FRI outer proof gate.

This gate exercises one fixed smoke-test guest.  It is valuable evidence that
the active outer prover ran and independently verified, but it is not an
ETHProof CSP workload and does not publish canonical recursive proof bytes.
Consequently its observations are never promoted to CSP speedup ratios.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .codec import (
    EvidenceError,
    content_digest,
    seal_document,
    sha256_bytes,
    verify_document_seal,
)
from .contract import (
    MAX_SAMPLES,
    SCHEMA_VERSION,
    exact_object,
    expect_commit,
    expect_digest,
    expect_positive_int,
)


ACTIVE_PROBE_SCHEMA = "stwo.riscv.recursion-active-outer-probe.v2"
ACTIVE_PROBE_CLASSIFICATION = "verified_non_csp_gate_not_comparison_evidence"
MAX_ATTEMPT_LOG_BYTES = 512 * 1024
PROBE_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "plan_digest",
        "cohort_id",
        "status",
        "comparison_eligible",
        "unavailable_reason",
        "captured_at",
        "repository",
        "invocation",
        "sampling",
        "attempts",
        "summary",
        "limitations",
        "canonical_digest",
    }
)
PROBE_REPOSITORY_KEYS = frozenset(
    {
        "head",
        "implementation_dirty",
        "status_sha256",
        "tracked_diff_sha256",
        "source_manifest_sha256",
        "source_file_count",
        "source_evidence",
    }
)
PROBE_SOURCE_KEYS = frozenset({"path", "sha256"})
PROBE_INVOCATION_KEYS = frozenset(
    {
        "argv",
        "working_directory",
        "environment_overrides",
        "sanitized_environment_keys",
        "zig_executable_sha256",
        "timeout_seconds",
    }
)
PROBE_SAMPLING_KEYS = frozenset(
    {
        "warmups_excluded",
        "measured_samples",
        "fresh_process_per_attempt",
        "automatic_retries",
        "outlier_drops",
    }
)
PROBE_ATTEMPT_KEYS = frozenset(
    {
        "return_code",
        "timed_out",
        "command_wall_ns",
        "combined_log_sha256",
        "combined_log_bytes",
        "combined_log_utf8",
        "diagnostic_tail",
        "status",
        "reason",
        "observation",
        "ordinal",
        "classification",
    }
)
PROBE_SUMMARY_KEYS = frozenset(
    {
        "base_prove_ns",
        "base_verify_ns",
        "outer_prove_ns",
        "outer_assembly_ns",
        "outer_stark_prove_ns",
        "outer_verify_ns",
        "command_wall_ns",
        "outer_poseidon2_permutations",
        "outer_proof_size_estimate_bytes",
        "canonical_recursive_proof_bytes",
        "peak_rss_bytes",
    }
)
PROBE_SOURCE_PATHS = (
    Path("src/tests/riscv/recursion_poseidon_leaf_test.zig"),
    Path("src/integrations/riscv_cpu/recursive_fri_outer.zig"),
    Path("build_support/products/riscv_cpu.zig"),
)

OUTER_RE = re.compile(
    rb"(?m)^\s*active FRI outer proof: "
    rb"logs\([^\r\n]+\)="
    rb"(?P<logs>[0-9]+(?:/[0-9]+){16}) "
    rb"columns=(?P<preprocessed>[0-9]+)\+(?P<main>[0-9]+)\+"
    rb"(?P<interaction>[0-9]+) constraints=(?P<constraints>[0-9]+) "
    rb"proof_estimate=(?P<proof_estimate>[0-9]+) "
    rb"prove_ns=(?P<prove_ns>[0-9]+) assembly_ns=(?P<assembly_ns>[0-9]+) "
    rb"stark_prove_ns=(?P<stark_prove_ns>[0-9]+) "
    rb"verify_ns=(?P<verify_ns>[0-9]+) "
    rb"poseidon_calls=(?P<poseidon_calls>[0-9]+) "
    rb"workers=(?P<workers>[0-9]+) draws=(?P<draws>[0-9]+) "
    rb"mutations=(?P<mutations>[0-9]+)/(?P<mutation_total>[0-9]+)\s*$"
)
A1_RE = re.compile(
    rb"(?m)^\s*A1_REAL [^\r\n]* proof_estimate=(?P<proof_estimate>[0-9]+) "
    rb"postcard=(?P<postcard_bytes>[0-9]+) [^\r\n]* "
    rb"prove_ns=(?P<prove_ns>[0-9]+) "
    rb"serialize_ns=(?P<serialize_ns>[0-9]+) "
    rb"ingress_ns=(?P<ingress_ns>[0-9]+) "
    rb"decode_ns=(?P<decode_ns>[0-9]+) "
    rb"verify_ns=(?P<verify_ns>[0-9]+) total_ns=(?P<total_ns>[0-9]+) "
    rb"counters=(?P<counters>true|false) peak_bytes=(?P<peak_bytes>[0-9]+) "
    rb"cpu_ns=(?P<cpu_ns>[0-9]+) energy_nj=(?P<energy_nj>[0-9]+) "
    rb"instructions=(?P<instructions>[0-9]+) cycles=(?P<cycles>[0-9]+)\s*$"
)
ROSTER_RE = re.compile(
    rb"(?m)^\s*universal roster=(?P<roster>[0-9]+)/36 "
    rb"active_verifier=(?P<verifier>[0-9]+) active_provider=(?P<provider>[0-9]+)\s*$"
)


def _one_match(pattern: re.Pattern[bytes], output: bytes, label: str) -> re.Match[bytes]:
    matches = list(pattern.finditer(output))
    if len(matches) != 1:
        raise EvidenceError(f"active outer output requires exactly one {label} record")
    return matches[0]


def _positive_fields(match: re.Match[bytes], label: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for key, raw in match.groupdict().items():
        if raw is None or key in {"logs", "counters"}:
            continue
        value = int(raw)
        values[key] = value
        expect_positive_int(
            value,
            f"{label}.{key}",
            allow_zero=key
            in {"peak_bytes", "cpu_ns", "energy_nj", "instructions", "cycles"},
        )
    return values


def parse_active_outer_output(output: bytes, *, requested_workers: int) -> dict[str, Any]:
    """Parse one successful gate output without accepting partial/prose evidence."""

    if len(output) > MAX_ATTEMPT_LOG_BYTES:
        raise EvidenceError("active outer output exceeds the bounded log size")
    if b"active FRI outer stage: failed=" in output:
        raise EvidenceError("active outer output contains an explicit failure record")
    if output.count(b"All 1 tests passed.") != 1:
        raise EvidenceError("active outer output has no unique Zig test-pass summary")
    if output.count(b"active FRI outer stage: capture=ok") != 1:
        raise EvidenceError("active outer output has no unique authenticated capture record")

    outer_match = _one_match(OUTER_RE, output, "outer proof")
    base_match = _one_match(A1_RE, output, "native leaf")
    roster_match = _one_match(ROSTER_RE, output, "universal roster")
    outer = _positive_fields(outer_match, "outer")
    base = _positive_fields(base_match, "base")
    roster = _positive_fields(roster_match, "roster")

    logs_raw = outer_match.group("logs")
    if logs_raw is None:
        raise EvidenceError("active outer output omitted its log-size vector")
    logs = [int(item) for item in logs_raw.split(b"/")]
    if len(logs) != 17 or any(value <= 0 for value in logs):
        raise EvidenceError("active outer log-size vector is invalid")
    if outer["workers"] != requested_workers:
        raise EvidenceError("active outer worker count differs from the invocation")
    if outer["mutations"] != 5 or outer["mutation_total"] != 5:
        raise EvidenceError("active outer mutation fleet did not reject all five cases")
    if roster != {"roster": 36, "verifier": 34, "provider": 2}:
        raise EvidenceError("active outer roster is not the complete 36-row schedule")
    if outer["prove_ns"] < outer["assembly_ns"] + outer["stark_prove_ns"]:
        raise EvidenceError("active outer prove time is smaller than its timed subphases")
    if base_match.group("counters") not in {b"true", b"false"}:
        raise EvidenceError("native resource-counter availability is invalid")

    return {
        "base": base,
        "outer": {**outer, "log_sizes": logs},
        "roster": roster,
        "canonical_recursive_artifact_available": False,
        "canonical_recursive_artifact_unavailable_reason": (
            "the active test reports an in-memory proof size estimate but does not "
            "serialize and retain a canonical recursive proof artifact"
        ),
        "ethproof_csp_workload": False,
    }


def _bounded_log(path: Path, label: str) -> bytes:
    size = path.stat().st_size
    if size > MAX_ATTEMPT_LOG_BYTES:
        raise EvidenceError(f"{label} exceeds the bounded log size")
    return path.read_bytes()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git_output(repo_root: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"cannot capture repository identity: {detail}")
    return process.stdout


def _repository_identity(repo_root: Path) -> dict[str, Any]:
    head_raw = _git_output(repo_root, "rev-parse", "--verify", "HEAD").strip()
    try:
        head = head_raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("repository HEAD is not ASCII") from error
    expect_commit(head, "active outer repository HEAD")
    status = _git_output(
        repo_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    tracked_diff = _git_output(
        repo_root,
        "diff",
        "--no-ext-diff",
        "--binary",
        "HEAD",
        "--",
    )
    sources = []
    for relative in PROBE_SOURCE_PATHS:
        source = repo_root / relative
        if not source.is_file():
            raise EvidenceError(f"active outer source is missing: {relative}")
        sources.append({"path": relative.as_posix(), "sha256": _sha256_file(source)})
    manifest_paths = [
        path
        for path in (repo_root / "src").rglob("*.zig")
        if path.is_file()
    ]
    manifest_paths.extend(
        path
        for path in (repo_root / "build_support").rglob("*.zig")
        if path.is_file()
    )
    for relative in (Path("build.zig"), Path("build.zig.zon")):
        path = repo_root / relative
        if path.is_file():
            manifest_paths.append(path)
    manifest = [
        {
            "path": path.relative_to(repo_root).as_posix(),
            "sha256": _sha256_file(path),
        }
        for path in sorted(set(manifest_paths))
    ]
    if not manifest:
        raise EvidenceError("active outer source manifest is empty")
    return {
        "head": head,
        "implementation_dirty": bool(status),
        "status_sha256": sha256_bytes(status),
        "tracked_diff_sha256": sha256_bytes(tracked_diff),
        "source_manifest_sha256": content_digest(manifest),
        "source_file_count": len(manifest),
        "source_evidence": sources,
    }


def _run_attempt(
    *,
    repo_root: Path,
    argv: list[str],
    environment: dict[str, str],
    timeout_seconds: int,
    requested_workers: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="stwo-active-outer-") as temporary:
        output_path = Path(temporary) / "combined.log"
        started_ns = time.monotonic_ns()
        timed_out = False
        with output_path.open("wb") as output:
            process = subprocess.Popen(
                argv,
                cwd=repo_root,
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    return_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    return_code = process.wait()
        wall_ns = time.monotonic_ns() - started_ns
        output_size = output_path.stat().st_size
        if output_size > MAX_ATTEMPT_LOG_BYTES:
            with output_path.open("rb") as source:
                source.seek(max(0, output_size - 4096))
                tail = source.read().decode("utf-8", errors="replace")
            return {
                "return_code": return_code,
                "timed_out": timed_out,
                "command_wall_ns": wall_ns,
                "combined_log_sha256": _sha256_file(output_path),
                "combined_log_bytes": output_size,
                "combined_log_utf8": None,
                "diagnostic_tail": tail,
                "status": "unavailable",
                "reason": "active outer output exceeds the bounded log size",
                "observation": None,
            }
        raw = _bounded_log(output_path, "active outer attempt output")

    result: dict[str, Any] = {
        "return_code": return_code,
        "timed_out": timed_out,
        "command_wall_ns": wall_ns,
        "combined_log_sha256": sha256_bytes(raw),
        "combined_log_bytes": len(raw),
        "combined_log_utf8": None,
        "diagnostic_tail": None,
        "status": "unavailable",
        "reason": None,
        "observation": None,
    }
    if timed_out:
        result["reason"] = f"active outer command exceeded {timeout_seconds} seconds"
        result["diagnostic_tail"] = raw[-4096:].decode("utf-8", errors="replace")
        return result
    if return_code != 0:
        result["reason"] = f"active outer command exited with status {return_code}"
        result["diagnostic_tail"] = raw[-4096:].decode("utf-8", errors="replace")
        return result
    try:
        decoded_log = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        result["reason"] = "active outer output is not UTF-8"
        result["diagnostic_tail"] = raw[-4096:].decode("utf-8", errors="replace")
        return result
    try:
        result["observation"] = parse_active_outer_output(
            raw,
            requested_workers=requested_workers,
        )
    except EvidenceError as error:
        result["reason"] = str(error)
        result["diagnostic_tail"] = raw[-4096:].decode("utf-8", errors="replace")
        return result
    result["status"] = "verified"
    result["combined_log_utf8"] = decoded_log
    return result


def _mean(values: list[int]) -> int:
    return (sum(values) + len(values) // 2) // len(values)


def collect_active_outer_probe(
    plan: dict[str, Any],
    *,
    repo_root: Path,
    zig_executable: Path,
    workers: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run the active gate in fresh processes and return a sealed observation."""

    from .pipeline import validate_plan  # Avoid a module initialization cycle.

    validate_plan(plan, repo_root=repo_root)
    workers = expect_positive_int(workers, "active outer workers")
    if workers > 32:
        raise EvidenceError("active outer workers exceeds the prover's bounded maximum")
    timeout_seconds = expect_positive_int(timeout_seconds, "active outer timeout")
    warmups = expect_positive_int(plan["native_run"].get("warmups"), "plan warmups")
    samples = expect_positive_int(plan["native_run"].get("samples"), "plan samples")
    if warmups > MAX_SAMPLES or not 3 <= samples <= MAX_SAMPLES:
        raise EvidenceError("plan sampling schedule is outside the probe bounds")

    captured_at = dt.datetime.now(dt.timezone.utc).isoformat()
    repository = _repository_identity(repo_root)
    zig = zig_executable.resolve(strict=True)
    if not zig.is_file():
        raise EvidenceError("active outer Zig executable is not a regular file")
    argv = [
        str(zig),
        "build",
        "test-riscv-recursion-poseidon-leaf",
        "-Doptimize=ReleaseFast",
    ]
    environment = os.environ.copy()
    sanitized_keys = (
        "STWO_RECURSION_FRI_FRONTIER_BLOWUP",
        "STWO_RECURSION_DIAGNOSE_COMPOSITION",
        "STWO_RECURSION_OUTER_STAGE_TELEMETRY",
        "STWO_RECURSION_PUBLIC_SEMANTIC_DIAGNOSTIC",
    )
    for key in sanitized_keys:
        environment.pop(key, None)
    environment.update(
        {
            "STWO_RECURSION_ACTIVE_FRI_OUTER": "1",
            "STWO_RECURSION_OUTER_WORKERS": str(workers),
            "NO_COLOR": "1",
        }
    )
    attempts: list[dict[str, Any]] = []
    expected_count = warmups + samples
    failure_reason: str | None = None
    for ordinal in range(expected_count):
        attempt = _run_attempt(
            repo_root=repo_root,
            argv=argv,
            environment=environment,
            timeout_seconds=timeout_seconds,
            requested_workers=workers,
        )
        attempt.update(
            {
                "ordinal": ordinal,
                "classification": (
                    "excluded_warmup" if ordinal < warmups else "measured"
                ),
            }
        )
        attempts.append(attempt)
        if attempt["status"] != "verified":
            failure_reason = attempt["reason"]
            break

    complete = len(attempts) == expected_count and failure_reason is None
    measured = [
        attempt
        for attempt in attempts
        if attempt["classification"] == "measured"
        and attempt["status"] == "verified"
    ]
    summary: dict[str, Any] | None = None
    if complete:
        observations = [attempt["observation"] for attempt in measured]
        invariant_paths = (
            ("outer", "proof_estimate"),
            ("outer", "poseidon_calls"),
            ("outer", "workers"),
            ("outer", "draws"),
        )
        for section, key in invariant_paths:
            values = {observation[section][key] for observation in observations}
            if len(values) != 1:
                complete = False
                failure_reason = f"measured active outer {section}.{key} drifted"
                break
        if complete:
            summary = {
                "base_prove_ns": _mean(
                    [observation["base"]["prove_ns"] for observation in observations]
                ),
                "base_verify_ns": _mean(
                    [observation["base"]["verify_ns"] for observation in observations]
                ),
                "outer_prove_ns": _mean(
                    [observation["outer"]["prove_ns"] for observation in observations]
                ),
                "outer_assembly_ns": _mean(
                    [observation["outer"]["assembly_ns"] for observation in observations]
                ),
                "outer_stark_prove_ns": _mean(
                    [
                        observation["outer"]["stark_prove_ns"]
                        for observation in observations
                    ]
                ),
                "outer_verify_ns": _mean(
                    [observation["outer"]["verify_ns"] for observation in observations]
                ),
                "command_wall_ns": _mean(
                    [attempt["command_wall_ns"] for attempt in measured]
                ),
                "outer_poseidon2_permutations": observations[0]["outer"][
                    "poseidon_calls"
                ],
                "outer_proof_size_estimate_bytes": observations[0]["outer"][
                    "proof_estimate"
                ],
                "canonical_recursive_proof_bytes": None,
                "peak_rss_bytes": None,
            }

    if _repository_identity(repo_root) != repository:
        raise EvidenceError("repository identity changed while the active probe was running")

    unsigned = {
        "schema": ACTIVE_PROBE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "classification": ACTIVE_PROBE_CLASSIFICATION,
        "plan_digest": plan["canonical_digest"],
        "cohort_id": plan["cohort_id"],
        "status": "verified_non_csp_probe" if complete else "unavailable",
        "comparison_eligible": False,
        "unavailable_reason": None if complete else failure_reason,
        "captured_at": captured_at,
        "repository": repository,
        "invocation": {
            "argv": argv,
            "working_directory": ".",
            "environment_overrides": {
                "STWO_RECURSION_ACTIVE_FRI_OUTER": "1",
                "STWO_RECURSION_OUTER_WORKERS": str(workers),
                "NO_COLOR": "1",
            },
            "sanitized_environment_keys": list(sanitized_keys),
            "zig_executable_sha256": _sha256_file(zig),
            "timeout_seconds": timeout_seconds,
        },
        "sampling": {
            "warmups_excluded": warmups,
            "measured_samples": samples,
            "fresh_process_per_attempt": True,
            "automatic_retries": 0,
            "outlier_drops": 0,
        },
        "attempts": attempts,
        "summary": summary,
        "limitations": [
            "The gate uses one fixed smoke-test guest, not an ETHProof CSP workload.",
            (
                "The repository was dirty; exact status, tracked-diff, and active-source "
                "digests are retained, but the probe remains an engineering diagnostic."
                if repository["implementation_dirty"]
                else "The probe ran from a clean repository identity."
            ),
            (
                "The outer proof is independently verified but only an in-memory size "
                "estimate is emitted; canonical recursive proof bytes remain unavailable."
            ),
            (
                "The command wall clock includes Zig build orchestration and is retained "
                "for diagnostics only, never compared with native internal timers."
            ),
            (
                "The emitted native peak precedes the active outer proof; comparable "
                "full-process peak RSS therefore remains unavailable."
            ),
        ],
    }
    sealed = seal_document(unsigned)
    return validate_active_outer_probe(sealed, plan=plan)


def validate_active_outer_probe(
    probe: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a sealed probe without importing validation on the hot collector path."""

    from .active_probe_validation import validate_active_outer_probe as validate

    return validate(probe, plan=plan)
