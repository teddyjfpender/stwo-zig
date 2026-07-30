"""Execution and evidence capture for the active Sail-backed RISC-V gate."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from .contract import repository_contract_errors, sha256_file


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_BASE = ROOT / "zig-out/release-evidence/riscv/runs"
MAX_CAPTURE_CHARS = 16_384
DEFAULT_COMMAND_TIMEOUT_SECONDS = 3_600.0
HEARTBEAT_SECONDS = 30.0
HOSTED_NO_DEVICE_ALLOWANCE = "STWO_ZIG_ALLOW_EXPLICIT_NO_METAL_DEVICE"


def command_plan(
    *,
    strict: bool,
    phase: str,
    formal_workspace: Path | None,
    candidate: str,
    evidence_dir: Path,
    host_system: str | None = None,
) -> list[list[str]]:
    python = sys.executable
    cli_evidence = evidence_dir / "cli"
    commands = [
        ["zig", "fmt", "--check", "build.zig", "src", "tools"],
        [python, "scripts/check_upstream_pins.py"],
        [python, "scripts/check_source_conformance.py"],
        [python, "scripts/check_riscv_release_contract.py", "--all", "--phase", phase],
        [python, "scripts/check_riscv_release_contract.py", "--structure"],
        [python, "scripts/check_riscv_release_contract.py", "--core-purity"],
        [python, "scripts/check_riscv_release_contract.py", "--frontend-layering"],
    ]
    if (platform.system() if host_system is None else host_system) == "Darwin":
        commands.append(
            ["zig", "build", "metal-eval-prepare", "-Doptimize=ReleaseFast"]
        )
    commands.extend(
        [
            [
                python,
                "-m",
                "unittest",
                "discover",
                "-s",
                "scripts/tests",
                "-p",
                "test_*.py",
            ],
            [
                python,
                "scripts/riscv_staged_smoke.py",
                "--phase",
                phase,
                "--evidence-dir",
                str(cli_evidence),
            ],
        ]
    )
    if strict:
        if formal_workspace is None:
            raise ValueError("--strict requires --formal-workspace")
        workspace = formal_workspace.resolve()
        sail_binary = workspace / "source/sail-riscv/build/c_emulator/sail_riscv_sim"
        spike_binary = workspace / "install/spike/bin/spike"
        corpus_report = evidence_dir / "formal-corpus.json"
        arch_workdir = evidence_dir / "arch-test"
        commands.extend(
            [
                ["zig", "build", "release-gate-strict", "-Doptimize=ReleaseFast"],
                [
                    python,
                    "scripts/riscv_formal_tools.py",
                    "verify",
                    "--workspace",
                    str(workspace),
                ],
                [
                    python,
                    "scripts/riscv_trace_vectors.py",
                    "--sail-bin",
                    str(sail_binary),
                    "--spike-bin",
                    str(spike_binary),
                    "--formal-report",
                    str(corpus_report),
                ],
                [
                    python,
                    "scripts/riscv_arch_tests.py",
                    "build",
                    "--formal-workspace",
                    str(workspace),
                    "--workdir",
                    str(arch_workdir),
                ],
                [
                    python,
                    "scripts/riscv_arch_tests.py",
                    "audit",
                    "--formal-workspace",
                    str(workspace),
                    "--workdir",
                    str(arch_workdir),
                ],
            ]
        )
        if (platform.system() if host_system is None else host_system) == "Darwin":
            # riscv_arch_tests.py runs this binary as
            # `<bin> --elf X --production --profile`, which is the *benchmark*
            # CLI's argv shape. `stwo-zig-riscv-metal` used to be that program;
            # it is now the production proof CLI
            # (`prove|bench|verify|applications`) and rejects that argv with
            # UnknownCommand. `riscv-metal-bench` is the same benchmark program
            # under its own name, so the audit must point at it.
            commands[-1].extend(
                ["--metal-bin", "zig-out/bin/riscv-metal-bench"]
            )
    else:
        commands.append(["zig", "build", "release-gate", "-Doptimize=ReleaseFast"])
    return commands


def git_status(root: Path = ROOT) -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _capture(
    command: list[str],
    root: Path = ROOT,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, object]:
    started_at = time.time_ns()
    started = time.monotonic_ns()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                subprocess.run,
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            while True:
                try:
                    completed = future.result(timeout=HEARTBEAT_SECONDS)
                    break
                except concurrent.futures.TimeoutError:
                    elapsed = (time.monotonic_ns() - started) / 1_000_000_000
                    print(
                        f"  still running ({elapsed:.0f}s): {shlex.join(command)}",
                        flush=True,
                    )
        code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as error:
        code = 124
        stdout = _text(error.stdout)
        stderr = _text(error.stderr) + f"\ncommand timed out after {timeout_seconds:g}s"
        timed_out = True
    except OSError as error:
        code = 127
        stdout = ""
        stderr = str(error)
        timed_out = False
    combined = f"{stdout}\n{stderr}"
    skipped = sum(int(match) for match in re.findall(r"\b(\d+) skipped\b", combined))
    skipped += sum(int(match) for match in re.findall(r"\bskipped=(\d+)\b", combined))
    return {
        "command": command,
        "command_shell": shlex.join(command),
        "exit_code": code,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "started_at_unix_ns": started_at,
        "duration_ns": time.monotonic_ns() - started,
        "skipped_tests": skipped,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        "stdout_tail": stdout[-MAX_CAPTURE_CHARS:],
        "stderr_tail": stderr[-MAX_CAPTURE_CHARS:],
    }


def _tool_versions(root: Path = ROOT) -> dict[str, str]:
    versions: dict[str, str] = {}
    for name, command in {
        "git": ["git", "--version"],
        "zig": ["zig", "version"],
        "python": [sys.executable, "--version"],
        "rustc": ["rustc", "--version"],
    }.items():
        result = _capture(command, root, 30.0)
        text = f"{result['stdout_tail']}\n{result['stderr_tail']}".strip()
        versions[name] = text if result["exit_code"] == 0 else "unavailable"
    return versions


def _artifact_digests(root: Path, evidence_dir: Path) -> dict[str, str]:
    paths = (
        "conformance/2026-07-26-riscv-sail-contract.md",
        "conformance/riscv/formal-corpus-evidence.json",
        "conformance/divergence-log.md",
        "soundness/SAIL_AIR_COMPOSITION.md",
        "src/tests/riscv/malicious_witness_test.zig",
        "autoresearch/MANIFEST.json",
    )
    digests = {path: sha256_file(root / path) for path in paths if (root / path).is_file()}
    if evidence_dir.is_dir():
        for artifact in sorted(evidence_dir.rglob("*")):
            if artifact.is_file() and artifact.name != "release-gate.json":
                relative = artifact.relative_to(root).as_posix()
                digests[relative] = sha256_file(artifact)
    return digests


def _write_report_atomic(path: Path, report: dict[str, object]) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def run_gate(
    commands: list[list[str]],
    *,
    phase: str,
    candidate: str,
    evidence_dir: Path,
    report_out: Path,
    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    root: Path = ROOT,
    runner: Callable[[list[str], Path], dict[str, object]] = _capture,
) -> int:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(f"riscv release gate: evidence directory already exists: {evidence_dir}", file=sys.stderr)
        return 1
    started = time.time_ns()
    monotonic_started = time.monotonic_ns()
    records: list[dict[str, object]] = []
    initial_status = git_status(root)
    failures = []
    if initial_status:
        failures.append("initial repository is dirty")
    if HOSTED_NO_DEVICE_ALLOWANCE in os.environ:
        failures.append(
            f"forbidden hosted-only environment variable is set: {HOSTED_NO_DEVICE_ALLOWANCE}"
        )

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != candidate:
        failures.append(f"candidate {candidate} does not match HEAD {head}")
    failures.extend(repository_contract_errors(root, phase))

    if not failures:
        for index, command in enumerate(commands, start=1):
            print(
                f"[{index}/{len(commands)}] START {shlex.join(command)}",
                flush=True,
            )
            record = runner(command, root)
            records.append(record)
            if record["exit_code"] != 0:
                print(
                    f"[{index}/{len(commands)}] FAIL "
                    f"{record.get('duration_ns', 0) / 1_000_000_000:.3f}s",
                    flush=True,
                )
                failures.append(f"command failed: {record['command_shell']}")
                break
            if record.get("skipped_tests", 0) != 0:
                print(
                    f"[{index}/{len(commands)}] FAIL skipped required tests",
                    flush=True,
                )
                failures.append(f"required tests were skipped: {record['command_shell']}")
                break
            print(
                f"[{index}/{len(commands)}] PASS "
                f"{record.get('duration_ns', 0) / 1_000_000_000:.3f}s",
                flush=True,
            )

    final_status = git_status(root)
    if final_status:
        failures.append("final repository is dirty")
    report = {
        "schema": "riscv-release-gate-evidence-v1",
        "status": "PASS" if not failures else "FAIL",
        "phase": phase,
        "candidate_commit": candidate,
        "started_at_unix_ns": started,
        "duration_ns": time.monotonic_ns() - monotonic_started,
        "command_timeout_seconds": command_timeout_seconds,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "node": platform.node(),
            "ci": bool(os.environ.get("CI")),
            "hosted_no_device_allowance_present": HOSTED_NO_DEVICE_ALLOWANCE in os.environ,
        },
        "toolchains": _tool_versions(root),
        "git": {
            "head": head,
            "initial_porcelain": initial_status,
            "final_porcelain": final_status,
        },
        "commands": records,
        "artifact_sha256": _artifact_digests(root, evidence_dir),
        "failures": failures,
    }
    _write_report_atomic(report_out, report)
    for failure in failures:
        print(f"riscv release gate: {failure}", file=sys.stderr)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run and record the Sail-backed RISC-V release gate"
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--phase", choices=("candidate", "promoted"), required=True)
    parser.add_argument("--formal-workspace", type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument(
        "--command-timeout-seconds",
        type=float,
        default=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    args = parser.parse_args(argv)
    if args.command_timeout_seconds <= 0:
        parser.error("--command-timeout-seconds must be positive")
    evidence_dir = args.evidence_dir
    if evidence_dir is None:
        evidence_dir = EVIDENCE_BASE / f"{args.candidate}-{time.time_ns()}"
    elif not evidence_dir.is_absolute():
        evidence_dir = ROOT / evidence_dir
    evidence_dir = evidence_dir.resolve()
    if not evidence_dir.is_relative_to(EVIDENCE_BASE.resolve()):
        parser.error(f"--evidence-dir must be below {EVIDENCE_BASE.relative_to(ROOT)}")
    report_out = evidence_dir / "release-gate.json"
    try:
        commands = command_plan(
            strict=args.strict,
            phase=args.phase,
            formal_workspace=args.formal_workspace,
            candidate=args.candidate,
            evidence_dir=evidence_dir,
        )
    except ValueError as error:
        parser.error(str(error))
    return run_gate(
        commands,
        phase=args.phase,
        candidate=args.candidate,
        evidence_dir=evidence_dir,
        report_out=report_out,
        command_timeout_seconds=args.command_timeout_seconds,
        runner=lambda command, root: _capture(
            command,
            root,
            args.command_timeout_seconds,
        ),
    )
