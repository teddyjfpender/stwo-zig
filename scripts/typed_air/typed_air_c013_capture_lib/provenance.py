"""Clean-source, host, and immutable artifact identity collection."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from .codec import exact_object, sha256_file
from .model import CaptureError, ENVIRONMENT


def _command(command: Sequence[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureError(f"provenance command failed to launch: {command[0]}") from error
    if result.returncode != 0 or result.stderr:
        raise CaptureError(
            f"provenance command failed: {list(command)!r}, "
            f"exit={result.returncode}, stderr={result.stderr[:160]!r}"
        )
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise CaptureError("provenance command returned non-UTF-8") from error
    if not value:
        raise CaptureError("provenance command returned no value")
    return value


def source_identity(repository: Path) -> dict[str, object]:
    root = repository.resolve()
    commit = _command(("git", "rev-parse", "HEAD"), root)
    tree = _command(("git", "rev-parse", "HEAD^{tree}"), root)
    try:
        result = subprocess.run(
            ("git", "status", "--porcelain=v1", "--untracked-files=all"),
            cwd=root,
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureError("could not inspect capture-source cleanliness") from error
    if result.returncode != 0 or result.stderr:
        raise CaptureError("git status failed during capture admission")
    try:
        status = result.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise CaptureError("git status returned non-UTF-8 paths") from error
    if status:
        raise CaptureError("C-013 capture planning requires a clean Git snapshot")
    return {
        "repository": "https://github.com/teddyjfpender/stwo-zig",
        "commit": commit,
        "tree": tree,
        "clean": True,
        "status_porcelain": [],
    }


def _sysctl(name: str) -> str | None:
    executable = shutil.which("sysctl")
    if executable is None:
        return None
    try:
        result = subprocess.run(
            (executable, "-n", name),
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip() or None


def _linux_physical_cores() -> tuple[str | None, int | None]:
    path = Path("/proc/cpuinfo")
    if not path.is_file():
        return None, None
    model: str | None = None
    cores: set[tuple[str, str]] = set()
    for block in path.read_text(encoding="utf-8", errors="replace").split("\n\n"):
        fields = dict(
            line.partition(":")[::2]
            for line in block.splitlines()
            if ":" in line
        )
        normalized = {key.strip(): value.strip() for key, value in fields.items()}
        model = model or normalized.get("model name") or normalized.get("Hardware")
        package = normalized.get("physical id")
        core = normalized.get("core id")
        if package is not None and core is not None:
            cores.add((package, core))
    return model, len(cores) or None


def host_identity(power_state: str) -> dict[str, object]:
    declaration = power_state.strip()
    if (
        not declaration
        or len(declaration) > 256
        or declaration.casefold() in {"unknown", "undeclared", "n/a"}
        or any(ord(character) < 32 for character in declaration)
    ):
        raise CaptureError("power-state declaration must be explicit printable text")
    logical = os.cpu_count()
    if logical is None or logical <= 0:
        raise CaptureError("logical CPU count is unavailable")
    system = platform.system()
    if system == "Darwin":
        model = _sysctl("machdep.cpu.brand_string") or _sysctl("hw.model")
        physical_text = _sysctl("hw.physicalcpu")
        memory_text = _sysctl("hw.memsize")
        physical = int(physical_text) if physical_text else None
        memory = int(memory_text) if memory_text else None
    elif system == "Linux":
        model, physical = _linux_physical_cores()
        try:
            memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError):
            memory = None
    else:
        raise CaptureError(f"unsupported C-013 host OS: {system or 'unknown'}")
    if not model or physical is None or physical <= 0 or memory is None or memory <= 0:
        raise CaptureError("host CPU, physical-core, or memory identity is unavailable")
    return {
        "os": system,
        "os_version": platform.version(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "cpu_model": model,
        "logical_cores": logical,
        "physical_cores": physical,
        "memory_bytes": memory,
        "power_state": {
            "operator_declaration": declaration,
            "machine_verified": False,
        },
    }


def validate_host_identity(value: object) -> dict[str, object]:
    host = exact_object(
        value,
        {
            "os",
            "os_version",
            "kernel_release",
            "machine",
            "cpu_model",
            "logical_cores",
            "physical_cores",
            "memory_bytes",
            "power_state",
        },
        "capture host",
    )
    for key in ("os", "os_version", "kernel_release", "machine", "cpu_model"):
        if type(host[key]) is not str or not host[key]:
            raise CaptureError(f"capture host {key} is empty")
    for key in ("logical_cores", "physical_cores", "memory_bytes"):
        if type(host[key]) is not int or host[key] <= 0:
            raise CaptureError(f"capture host {key} is invalid")
    power = exact_object(
        host["power_state"],
        {"operator_declaration", "machine_verified"},
        "capture power state",
    )
    if type(power["operator_declaration"]) is not str or not power["operator_declaration"]:
        raise CaptureError("capture power-state declaration is empty")
    if power["machine_verified"] is not False:
        raise CaptureError("unsupported machine-verified power adapter")
    return host


def artifact_identity(path: Path, *, executable: bool) -> dict[str, object]:
    resolved = path.resolve()
    if not resolved.is_file():
        raise CaptureError(f"capture artifact is missing: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise CaptureError(f"capture executable is not executable: {resolved}")
    size, digest = sha256_file(resolved)
    if size <= 0:
        raise CaptureError(f"capture artifact is empty: {resolved}")
    return {"path": str(resolved), "bytes": size, "sha256": digest}


def run_tool(path: Path, repository: Path, timeout: float = 60.0) -> bytes:
    try:
        result = subprocess.run(
            (str(path.resolve()),),
            cwd=repository.resolve(),
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureError("C-013 corpus-manifest tool failed to run") from error
    if result.returncode != 0 or result.stderr:
        raise CaptureError(
            f"C-013 corpus-manifest tool failed: exit={result.returncode}, "
            f"stderr={result.stderr[:160]!r}"
        )
    if result.stdout.count(b"\n") != 1 or not result.stdout.endswith(b"\n"):
        raise CaptureError("C-013 corpus tool must emit exactly one JSON line")
    return result.stdout
