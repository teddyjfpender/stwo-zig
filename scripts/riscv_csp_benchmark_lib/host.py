"""Host evidence and CSP publication-host classification."""

from __future__ import annotations

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


def collect_host() -> dict[str, Any]:
    cpu = _sysctl("machdep.cpu.brand_string") or platform.processor() or "unknown"
    memory_raw = _sysctl("hw.memsize")
    memory = int(memory_raw) if memory_raw and memory_raw.isdigit() else None
    return {
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] or platform.release(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": cpu,
        "logical_cpu_count": os.cpu_count(),
        "memory_bytes": memory,
        "python": platform.python_version(),
    }


def official_host_match(host: Mapping[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if host.get("cpu") != "Apple M1":
        reasons.append("CSP publication host requires Apple M1")
    if host.get("logical_cpu_count") != 8:
        reasons.append("CSP publication host requires 8 logical CPUs")
    if host.get("memory_bytes") != 16 * 1024 * 1024 * 1024:
        reasons.append("CSP publication host requires 16 GiB RAM")
    return not reasons, reasons
