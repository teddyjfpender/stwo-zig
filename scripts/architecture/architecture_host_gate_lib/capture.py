"""Bounded subprocess and file evidence capture for architecture phases."""

from __future__ import annotations

import hashlib
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


SKIP_PATTERNS = (
    re.compile(r"\b(\d+)(?: tests?)? skipped\b", re.IGNORECASE),
    re.compile(r"\bskipped=(\d+)\b", re.IGNORECASE),
)

CHILD_ENVIRONMENT = (
    "DEVELOPER_DIR",
    "LANG",
    "LC_ALL",
    "PATH",
    "SDKROOT",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def skipped_tests(stdout: bytes, stderr: bytes) -> int:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    return sum(int(match) for pattern in SKIP_PATTERNS for match in pattern.findall(text))


def child_environment(
    home: Path, source: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = os.environ if source is None else source
    filtered = {
        name: environment[name] for name in CHILD_ENVIRONMENT if name in environment
    }
    filtered.update({
        "HOME": str(home),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(home / "tmp"),
        "XDG_CACHE_HOME": str(home / "cache"),
    })
    return filtered


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(argv: list[str], root: Path, timeout: float) -> tuple[int, bytes, bytes, int]:
    started = time.monotonic_ns()
    try:
        with tempfile.TemporaryDirectory(prefix="stwo-architecture-candidate-") as raw_home:
            home = Path(raw_home)
            (home / "tmp").mkdir()
            (home / "cache").mkdir()
            process = subprocess.Popen(
                argv,
                cwd=root,
                env=child_environment(home),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                code = process.returncode
            except subprocess.TimeoutExpired:
                terminate_process_group(process)
                stdout, stderr = process.communicate()
                stderr += f"\ntimed out after {timeout:g}s".encode()
                code = 124
            finally:
                terminate_process_group(process)
        return code, stdout, stderr, time.monotonic_ns() - started
    except OSError as error:
        return 127, b"", str(error).encode(), time.monotonic_ns() - started


def capture_command(
    *,
    ordinal: int,
    command_id: str,
    phase: str,
    argv: list[str],
    root: Path,
    log_dir: Path,
    timeout: float,
    executor: Callable[[list[str], Path, float], tuple[int, bytes, bytes, int]] = run,
) -> tuple[dict[str, Any], Path]:
    code, stdout, stderr, duration_ns = executor(argv, root, timeout)
    stdout_path = log_dir / f"{ordinal:03d}-{command_id}.stdout"
    stderr_path = log_dir / f"{ordinal:03d}-{command_id}.stderr"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    record = {
        "ordinal": ordinal,
        "phase": phase,
        "argv": argv,
        "duration_ms": duration_ns // 1_000_000,
        "exit_code": code,
        "skipped_tests": skipped_tests(stdout, stderr),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
    }
    return record, stdout_path
