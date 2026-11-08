"""Bounded execution, append-only capture, and atomic evidence publication."""

from __future__ import annotations

import os
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from .codec import atomic_write, canonical_bytes, content_digest, sha256_bytes, sha256_file
from .model import EvidenceError
from .session import attempt_chain_seed

try:
    from scripts.process_resources_lib import measurement_command, measurement_environment, parse_process_resources
except ModuleNotFoundError:
    from process_resources_lib import measurement_command, measurement_environment, parse_process_resources


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    wall_seconds: float
    peak_rss_bytes: int
    proof: bytes | None = None
    verifier: bytes | None = None
    timing: bytes | None = None
    resource_evidence: bytes | None = None
    failure_class: str | None = None
    timed_out: bool = False
    infrastructure_failure: bool = False


class Executor(Protocol):
    def run(self, command: dict[str, Any], artifact_path: Path, timeout_seconds: float) -> ExecutionResult: ...


class SubprocessExecutor:
    """No-shell production executor with an explicit proof/oracle evidence hook."""

    def __init__(self, evidence_hook: Callable[[dict[str, Any], Path, bytes], dict[str, bytes]] | None = None):
        self.evidence_hook = evidence_hook

    def run(self, command: dict[str, Any], artifact_path: Path, timeout_seconds: float) -> ExecutionResult:
        report_path = artifact_path.with_suffix(".report.json")
        argv = [
            str(artifact_path) if item == "$ARTIFACT_PATH" else
            str(report_path) if item == "$REPORT_PATH" else item
            for item in command["argv"]
        ]
        measured_argv, measurement = measurement_command(argv, required=True)
        environment = measurement_environment(command["environment"])
        started = time.monotonic()
        process = subprocess.Popen(
            measured_argv, cwd=command["cwd"], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
        wall = time.monotonic() - started
        resources = parse_process_resources(stderr, measurement, require_peak_rss=True)
        rss = int(resources["peak_rss_kib"]) * 1024
        proof = artifact_path.read_bytes() if artifact_path.is_file() else None
        evidence = (
            self.evidence_hook(command, artifact_path, stdout)
            if self.evidence_hook and process.returncode == 0 and not timed_out else {}
        )
        return ExecutionResult(
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            wall_seconds=wall,
            peak_rss_bytes=max(1, rss),
            proof=proof,
            verifier=evidence.get("verifier"),
            timing=evidence.get("timing"),
            resource_evidence=evidence.get("resource"),
            failure_class="timeout" if timed_out else None,
            timed_out=timed_out,
        )


class NativeProofEvidenceHook:
    """Convert one verified Native report plus the pinned Rust oracle into raw evidence."""

    def __init__(
        self,
        rust_oracle_binary: Path,
        timeout_seconds: float,
        oracle_runner: Callable[[Path, Path, float], dict[str, Any]],
    ):
        self.rust_oracle_binary = rust_oracle_binary
        self.timeout_seconds = timeout_seconds
        self.oracle_runner = oracle_runner

    def __call__(self, command: dict[str, Any], artifact_path: Path, stdout: bytes) -> dict[str, bytes]:
        if command["phase"] != "proof-request":
            return {}
        try:
            report_path = artifact_path.with_suffix(".report.json")
            report = json.loads(report_path.read_bytes() if report_path.is_file() else stdout)
            proof = report["proof"]
            samples = report["timing"]["samples"]
            digest = proof["samples"][0]["sha256"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise EvidenceError("Native proof command did not emit a supported report") from error
        if proof["verified_samples"] != 1 or proof["all_samples_byte_identical"] is not True:
            raise EvidenceError("Native proof report lacks local verification")
        oracle = self.oracle_runner(
            self.rust_oracle_binary, artifact_path, self.timeout_seconds,
        )
        if oracle.get("verified") is not True:
            raise EvidenceError("pinned Rust Stwo oracle did not verify the proof")
        telemetry = report.get("backend_telemetry")
        dispatches = 0 if telemetry is None else int(telemetry["total_metal_dispatches"])
        fallbacks = 0 if telemetry is None else int(telemetry["total_cpu_fallbacks"])
        sample = samples[0]
        return {
            "verifier": canonical_bytes({
                "schema": "proof-verifier-v1", "local_verified": True,
                "rust_oracle_verified": True, "canonical_proof_sha256": digest,
                "metal_device_dispatches": dispatches,
                "metal_fallback_count": fallbacks,
            }),
            "timing": canonical_bytes({
                "schema": "proof-timing-v1",
                "prove_seconds": sample["prove_seconds"],
                "request_seconds": sample["request_seconds"],
            }),
        }


@dataclass(frozen=True)
class CapturedHost:
    attempts: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    attempt_ledger_artifact: str
    attempt_journal_artifact: str
    terminal_attempt_sha256: str
    attempt_count: int


class HostCaptureController:
    """Execute one authenticated host plan while retaining every attempt."""

    def __init__(
        self,
        *,
        plan: dict[str, Any],
        plan_sha256: str,
        staging_root: Path,
        executor: Executor,
        timeout_seconds: float = 3600.0,
    ):
        self.plan = plan
        self.plan_sha256 = plan_sha256
        self.root = staging_root
        self.executor = executor
        self.timeout_seconds = timeout_seconds
        self.role = plan["host_role"]
        self.commands = {command["id"]: command for command in plan["commands"]}
        self.artifacts: list[dict[str, Any]] = []
        self.attempts: list[dict[str, Any]] = []
        self.previous = attempt_chain_seed(self.role, plan, plan_sha256)
        self.journal = self.root / "journals" / f"{self.role}.jsonl"
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        if self.journal.exists():
            raise EvidenceError("capture journal already exists")

    def _artifact(self, identifier: str, kind: str, content: bytes) -> str:
        digest = sha256_bytes(content)
        relative = f"artifacts/{kind}/{digest}-{identifier}"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise EvidenceError("capture artifact path collision")
        path.write_bytes(content)
        self.artifacts.append({
            "id": identifier, "path": relative, "kind": kind,
            "sha256": digest, "bytes": len(content),
        })
        return identifier

    def run_attempt(self, request: dict[str, Any]) -> dict[str, Any]:
        required = {"command_id", "stage", "workload_id", "round_index", "order_position"}
        if not isinstance(request, dict) or set(request) != required:
            raise EvidenceError("capture request fields drifted")
        command = self.commands.get(request["command_id"])
        if command is None:
            raise EvidenceError("capture request command is not planned")
        sequence = len(self.attempts) + 1
        artifact_path = self.root / "work" / f"{self.role}-{sequence}.proof"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        started = time.time_ns()
        try:
            result = self.executor.run(command, artifact_path, self.timeout_seconds)
        except Exception as error:  # Controller retains infrastructure exceptions.
            result = ExecutionResult(
                exit_code=255, stdout=b"", stderr=str(error).encode("utf-8"),
                wall_seconds=0.0, peak_rss_bytes=1,
                failure_class=type(error).__name__, infrastructure_failure=True,
            )
        ended = time.time_ns()
        prefix = f"{self.role}-{sequence}"
        refs: dict[str, str | None] = {
            "stdout": self._artifact(f"{prefix}-stdout", "stdout", result.stdout),
            "stderr": self._artifact(f"{prefix}-stderr", "stderr", result.stderr),
            "proof": None, "verifier": None, "timing": None, "resource": None,
        }
        if result.proof is not None:
            refs["proof"] = self._artifact(f"{prefix}-proof", "proof", result.proof)
        if result.verifier is not None:
            refs["verifier"] = self._artifact(f"{prefix}-verifier", "verifier", result.verifier)
        timing = result.timing or canonical_bytes({
            "schema": "process-timing-v1", "wall_seconds": result.wall_seconds,
        })
        resources = result.resource_evidence or canonical_bytes({
            "schema": "process-resource-v1", "peak_rss_bytes": result.peak_rss_bytes,
        })
        refs["timing"] = self._artifact(f"{prefix}-timing", "timing", timing)
        refs["resource"] = self._artifact(f"{prefix}-resource", "resource", resources)
        status = (
            "timed_out" if result.timed_out else
            "success" if result.exit_code == 0 else
            "infrastructure_failure" if result.infrastructure_failure else "failed"
        )
        attempt = {
            "sequence": sequence,
            "host_role": self.role,
            "command_id": command["id"],
            "stage": request["stage"],
            "arm": command["arm"],
            "workload_id": request["workload_id"],
            "round_index": request["round_index"],
            "order_position": request["order_position"],
            "status": status,
            "failure_class": None if status == "success" else (result.failure_class or "nonzero-exit"),
            "started_at_unix_ns": started,
            "ended_at_unix_ns": max(ended, started + 1),
            "exit_code": result.exit_code,
            "artifacts": refs,
            "previous_attempt_sha256": self.previous,
        }
        attempt["attempt_sha256"] = sha256_bytes(canonical_bytes(attempt))
        self.previous = attempt["attempt_sha256"]
        with self.journal.open("ab") as handle:
            handle.write(canonical_bytes(attempt))
            handle.flush()
            os.fsync(handle.fileno())
        self.attempts.append(attempt)
        return attempt

    def seal(self) -> CapturedHost:
        if not self.attempts:
            raise EvidenceError("cannot seal an empty capture")
        ledger_id = f"{self.role}-attempt-ledger"
        self._artifact(ledger_id, "attempt-ledger", canonical_bytes({
            "schema": "build-monorepo-performance-attempt-ledger-v1",
            "attempts": self.attempts,
        }))
        journal_id = f"{self.role}-attempt-journal"
        self._artifact(journal_id, "attempt-journal", self.journal.read_bytes())
        return CapturedHost(
            attempts=list(self.attempts), artifacts=list(self.artifacts),
            attempt_ledger_artifact=ledger_id, attempt_journal_artifact=journal_id,
            terminal_attempt_sha256=self.previous, attempt_count=len(self.attempts),
        )


def publish_capture(
    *,
    staging_root: Path,
    publication_root: Path,
    receipt: dict[str, Any],
    artifacts: list[dict[str, Any]],
    validate: Callable[[Path, Path], Any],
) -> tuple[Path, Path]:
    """Atomically publish a content-addressed raw tree, then a validated receipt."""
    bundle = {
        "schema": "build-monorepo-performance-raw-bundle-v1",
        "schema_version": 1,
        "artifacts": artifacts,
    }
    bundle["content_sha256"] = content_digest(bundle)
    receipt = {**receipt, "raw_bundle": bundle}
    receipt["content_sha256"] = content_digest(receipt)
    raw_destination = publication_root / "raw" / bundle["content_sha256"]
    raw_destination.parent.mkdir(parents=True, exist_ok=True)
    if raw_destination.exists():
        raise EvidenceError("raw bundle content address already exists")
    os.replace(staging_root, raw_destination)
    temporary = publication_root / ".validation" / f"{receipt['content_sha256']}.json"
    atomic_write(temporary, receipt)
    try:
        validate(temporary, raw_destination)
        final = publication_root / "receipts" / f"{receipt['content_sha256']}.json"
        final.parent.mkdir(parents=True, exist_ok=True)
        os.link(temporary, final)
    finally:
        temporary.unlink(missing_ok=True)
    return raw_destination, final
