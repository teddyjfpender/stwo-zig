"""Host evidence and CSP publication-host classification."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from typing import Any, Mapping


def _sysctl(name: str) -> str | None:
    try:
        value = subprocess.run(
            ["sysctl", "-n", name],
            capture_output=True,
            check=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if value.returncode == 0 and value.stdout.strip():
        return value.stdout.strip()
    return None


def _pmset(*arguments: str) -> list[str]:
    """Return ``pmset`` output lines, empty when the tool is unavailable."""
    try:
        completed = subprocess.run(
            ["pmset", *arguments],
            capture_output=True,
            check=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return completed.stdout.splitlines()


def _power_evidence() -> tuple[str | None, bool | None]:
    """Capture power source and low-power state, fail-soft to ``None``.

    Battery power throttles sustained multi-core CPU work on Apple Silicon
    while leaving the GPU largely unaffected, so it inflates every CPU-vs-GPU
    ratio.  Per-sample variance stays small under throttling, so a stable
    looking run is not evidence of a valid one and this must be recorded.
    Hosts without ``pmset`` degrade to unknown rather than failing.
    """
    source: str | None = None
    for line in _pmset("-g", "batt"):
        if line.startswith("Now drawing from '") and line.endswith("'"):
            source = line.split("'")[1] or None
            break
    low_power_mode: bool | None = None
    for line in _pmset("-g"):
        fields = line.split()
        if len(fields) == 2 and fields[0] == "powermode" and fields[1].isdigit():
            low_power_mode = int(fields[1]) == 1
            break
    return source, low_power_mode


def _gpu_evidence() -> dict[str, Any]:
    """Capture GPU identity, fail-soft to all-``None`` fields.

    The field schema is identical across backends so that the report's
    ``host`` block has one shape; whether missing identity is fatal is the
    caller's per-backend decision.
    """
    empty: dict[str, Any] = {
        "name": None,
        "core_count": None,
        "metal_support": None,
        "unified_memory": None,
    }
    try:
        completed = subprocess.run(
            ["system_profiler", "SPDisplaysDataType", "-json"],
            capture_output=True,
            check=False,
            timeout=15,
            text=True,
        )
        if completed.returncode != 0:
            return empty
        displays = json.loads(completed.stdout)["SPDisplaysDataType"]
        if not isinstance(displays, list):
            return empty
        entries = [item for item in displays if isinstance(item, dict)]
        if not entries:
            return empty
        entry = next(
            (
                item
                for item in entries
                if item.get("sppci_bus") == "spdisplays_builtin"
            ),
            entries[0],
        )
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        return empty

    raw_name = entry.get("sppci_model") or entry.get("_name")
    name = raw_name if isinstance(raw_name, str) and raw_name else None
    raw_cores = entry.get("sppci_cores")
    if isinstance(raw_cores, int) and not isinstance(raw_cores, bool):
        core_count: int | None = raw_cores
    elif isinstance(raw_cores, str) and raw_cores.isdigit():
        core_count = int(raw_cores)
    else:
        core_count = None
    raw_metal = entry.get("spdisplays_mtlgpufamilysupport") or entry.get(
        "sppci_metalfamily"
    )
    metal_support = raw_metal if isinstance(raw_metal, str) and raw_metal else None
    unified_memory = (
        True
        if platform.machine() == "arm64"
        and name is not None
        and name.startswith("Apple")
        else None
    )
    return {
        "name": name,
        "core_count": core_count,
        "metal_support": metal_support,
        "unified_memory": unified_memory,
    }


def collect_host() -> dict[str, Any]:
    cpu = _sysctl("machdep.cpu.brand_string") or platform.processor() or "unknown"
    memory_raw = _sysctl("hw.memsize")
    memory = int(memory_raw) if memory_raw and memory_raw.isdigit() else None
    power_source, low_power_mode = _power_evidence()
    return {
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] or platform.release(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": cpu,
        "logical_cpu_count": os.cpu_count(),
        "memory_bytes": memory,
        "gpu": _gpu_evidence(),
        "power_source": power_source,
        "low_power_mode": low_power_mode,
        "python": platform.python_version(),
    }


def official_host_match(
    host: Mapping[str, Any],
    *,
    backend: str = "cpu",
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if host.get("cpu") != "Apple M1":
        reasons.append("CSP publication host requires Apple M1")
    if host.get("logical_cpu_count") != 8:
        reasons.append("CSP publication host requires 8 logical CPUs")
    if host.get("memory_bytes") != 16 * 1024 * 1024 * 1024:
        reasons.append("CSP publication host requires 16 GiB RAM")
    if backend == "metal":
        raw_gpu = host.get("gpu")
        gpu: Mapping[str, Any] = raw_gpu if isinstance(raw_gpu, Mapping) else {}
        if gpu.get("name") != "Apple M1":
            reasons.append("CSP publication host requires an Apple M1 GPU")
        if gpu.get("core_count") != 8:
            reasons.append("CSP publication host requires 8 GPU cores")
        metal_support = gpu.get("metal_support")
        if not isinstance(metal_support, str) or not metal_support:
            reasons.append(
                "CSP publication host requires Metal support evidence"
            )
    return not reasons, reasons


def power_conditions_admissible(
    host: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Decide whether the run's power conditions can carry published timings.

    Kept separate from ``official_host_match`` because this is a property of
    the run, not of the hardware: the official host on battery and a foreign
    host on AC are different defects and must not collapse into one reason
    list.  Both feed the report's single ``result_class`` notion.
    """
    reasons: list[str] = []
    source = host.get("power_source")
    if source != "AC Power":
        reasons.append(
            "CSP-comparable timings require AC power (observed: "
            f"{source or 'no power-source evidence'})"
        )
    low_power_mode = host.get("low_power_mode")
    if low_power_mode is not False:
        reasons.append(
            "CSP-comparable timings require low power mode disabled "
            f"(observed: {'enabled' if low_power_mode else 'no evidence'})"
        )
    return not reasons, reasons


def classify_result(
    *,
    host_matches: bool,
    power_admissible: bool,
    complete_matrix: bool,
    memory_available: bool,
) -> str:
    """Classify a run for publication against the CSP publication host.

    Throttled runs get their own class ahead of the host comparison: a
    battery-captured run is not merely host-qualified, it is not a valid
    measurement of anything and must never be read as one.
    """
    if not power_admissible:
        return "power-condition-non-publishable"
    if host_matches and complete_matrix and memory_available:
        return "official-host-comparable"
    return "host-qualified-non-comparable"
