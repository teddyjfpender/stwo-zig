"""Host, repository, source-closure, and executable evidence for H-010."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path

from .source_closure import (
    ClosureError,
    Manifest,
    NamedImport,
    inspect_sources,
)

from .contract import ARTIFACT_DIGEST


ARTIFACT_PATH = Path(
    "design/typed-air/artifacts/h009-poseidon2-cost-v1/frontier.stwairm"
)
SOURCE_MANIFEST = Manifest(
    product="h010-authenticated-poseidon-layout-runner-v1",
    entry_roots=("src/frontends/riscv/poseidon_layout_benchmark_tool.zig",),
    named_imports=(
        NamedImport("stwo_backend_contracts", "src/backend/mod.zig"),
        NamedImport("stwo_core", "src/core/mod.zig"),
        NamedImport("stwo_prover_api", "src/prover_api/mod.zig"),
        NamedImport("stwo_prover_engine", "src/prover/mod.zig"),
        NamedImport(
            "typed_air_h009_artifacts",
            "design/typed-air/artifacts/h009_embedded.zig",
        ),
        NamedImport(
            "typed_air_h010_artifacts",
            "design/typed-air/artifacts/h010_embedded.zig",
        ),
    ),
    generated_imports=frozenset(
        {"std", "builtin", "build_options", "build_identity", "product_identity"}
    ),
    allowed_prefixes=("src", "design/typed-air/artifacts"),
)


class ProvenanceError(RuntimeError):
    """Required report provenance cannot be collected unambiguously."""


def _command_text(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProvenanceError(f"could not run provenance command {command[0]!r}") from error
    if completed.returncode != 0 or completed.stderr:
        raise ProvenanceError(
            f"provenance command failed: {command!r}, exit={completed.returncode}, "
            f"stderr={completed.stderr[:160]!r}"
        )
    try:
        result = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise ProvenanceError(f"provenance command returned non-UTF-8: {command!r}") from error
    if not result:
        raise ProvenanceError(f"provenance command returned no value: {command!r}")
    return result


def _sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _git(repository: Path) -> dict[str, object]:
    commit = _command_text(["git", "rev-parse", "HEAD"], cwd=repository)
    tree = _command_text(["git", "rev-parse", "HEAD^{tree}"], cwd=repository)
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repository,
            env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProvenanceError("could not inspect repository cleanliness") from error
    if completed.returncode != 0 or completed.stderr:
        raise ProvenanceError("git status failed while collecting repository identity")
    try:
        status = completed.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ProvenanceError("git status returned non-UTF-8 paths") from error
    return {
        "commit": commit,
        "tree": tree,
        "clean": not status,
        "status_porcelain": status,
    }


def _sysctl(name: str) -> str | None:
    binary = shutil.which("sysctl")
    if binary is None:
        return None
    try:
        completed = subprocess.run(
            [binary, "-n", name],
            env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="replace").strip() or None


def _linux_cpu_info() -> tuple[str | None, int | None]:
    path = Path("/proc/cpuinfo")
    if not path.is_file():
        return None, None
    blocks = path.read_text(encoding="utf-8", errors="replace").split("\n\n")
    model: str | None = None
    physical: set[tuple[str, str]] = set()
    for block in blocks:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        model = model or fields.get("model name") or fields.get("Hardware")
        package = fields.get("physical id")
        core = fields.get("core id")
        if package is not None and core is not None:
            physical.add((package, core))
    return model, len(physical) or None


def _host(power_state: str) -> dict[str, object]:
    logical = os.cpu_count()
    if logical is None or logical <= 0:
        raise ProvenanceError("logical CPU count is unavailable")
    system = platform.system()
    if system == "Darwin":
        cpu_model = _sysctl("machdep.cpu.brand_string") or _sysctl("hw.model")
        physical_raw = _sysctl("hw.physicalcpu")
        memory_raw = _sysctl("hw.memsize")
        physical = int(physical_raw) if physical_raw is not None else None
        memory = int(memory_raw) if memory_raw is not None else None
    elif system == "Linux":
        cpu_model, physical = _linux_cpu_info()
        try:
            memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError):
            memory = None
    else:
        raise ProvenanceError(f"unsupported benchmark host OS: {system or 'unknown'}")
    if not cpu_model:
        cpu_model = platform.processor() or None
    if not cpu_model or physical is None or physical <= 0:
        raise ProvenanceError("CPU model or physical core count is unavailable")
    if memory is None or memory <= 0:
        raise ProvenanceError("physical memory size is unavailable")
    target_arch = platform.machine()
    zig_arch = {"arm64": "aarch64", "x86_64": "x86_64"}.get(
        target_arch, target_arch
    )
    zig_os = {"Darwin": "macos", "Linux": "linux"}[system]
    return {
        "target_arch": target_arch,
        "expected_native_target_prefix": f"{zig_arch}-{zig_os}-",
        "os": system,
        "os_version": platform.version(),
        "kernel_release": platform.release(),
        "cpu_model": cpu_model,
        "logical_cores": logical,
        "physical_cores": physical,
        "memory_bytes": memory,
        "power_state": {
            "operator_declaration": power_state,
            "machine_verified": False,
        },
    }


def _source_closure(repository: Path) -> dict[str, object]:
    try:
        graph = inspect_sources(repository, SOURCE_MANIFEST)
    except (ClosureError, OSError, UnicodeError) as error:
        raise ProvenanceError(f"could not resolve H-010 source closure: {error}") from error
    return {
        "manifest": SOURCE_MANIFEST.canonical(),
        "manifest_sha256": SOURCE_MANIFEST.digest(),
        "source_count": len(graph.sources),
        "content_sha256": graph.source_digest(),
        "sources": list(graph.relative_sources()),
    }


def gather_provenance(
    repository: Path,
    executable: Path,
    power_state: str,
) -> dict[str, object]:
    """Collect every non-sample identity required by the H-010 report."""

    repository = repository.resolve()
    executable = executable.resolve()
    artifact = repository / ARTIFACT_PATH
    if not artifact.is_file():
        raise ProvenanceError(f"H-009 artifact is missing: {artifact}")
    artifact_bytes, artifact_digest = _sha256_file(artifact)
    if artifact_digest != ARTIFACT_DIGEST:
        raise ProvenanceError("H-009 artifact digest does not match the protocol pin")
    executable_bytes, executable_digest = _sha256_file(executable)
    zig = shutil.which("zig")
    if zig is None:
        raise ProvenanceError("zig is unavailable for compiler-version admission")
    host_zig_version = _command_text([zig, "version"])
    host = _host(power_state)
    return {
        "repository": _git(repository),
        "source_closure": _source_closure(repository),
        "executable": {
            "path": str(executable),
            "bytes": executable_bytes,
            "sha256": executable_digest,
        },
        "artifact": {
            "path": str(ARTIFACT_PATH),
            "bytes": artifact_bytes,
            "sha256": artifact_digest,
        },
        "host": host,
        "build_expectation": {
            "zig_version": host_zig_version,
            "optimization_mode": "ReleaseFast",
            "target_prefix": host["expected_native_target_prefix"],
            "allocator": "libc-c-allocator",
            "monotonic_clock": "std.time.Timer",
        },
        "environment_allowlist": {
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        },
        "worker_count": 1,
        "clock_adapter": "std.time.Timer",
        "rss_adapter": "getrusage(RUSAGE_SELF).ru_maxrss",
    }
