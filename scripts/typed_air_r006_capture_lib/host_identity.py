"""Machine-observed host identity required by normative R-006 plans."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from scripts.riscv_csp_benchmark_lib.host import power_evidence

from .model import ENVIRONMENT, CaptureError


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
    return result.stdout.decode("utf-8", errors="replace").strip()


def _linux_host() -> tuple[str | None, int | None, int | None]:
    cpuinfo = Path("/proc/cpuinfo")
    model: str | None = None
    cores: set[tuple[str, str]] = set()
    if cpuinfo.is_file():
        for block in cpuinfo.read_text(
            encoding="utf-8", errors="replace"
        ).split("\n\n"):
            fields = {}
            for line in block.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    fields[key.strip()] = value.strip()
            model = model or fields.get("model name") or fields.get("Hardware")
            if "physical id" in fields and "core id" in fields:
                cores.add((fields["physical id"], fields["core id"]))
    try:
        memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        memory = None
    return model, len(cores) or None, memory


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
        model, physical, memory = _linux_host()
    else:
        raise CaptureError(f"unsupported R-006 host OS: {system or 'unknown'}")
    if not model or not physical or not memory:
        raise CaptureError("host CPU, physical-core, or memory identity is unavailable")
    power_source, low_power_mode = power_evidence()
    if not power_source or low_power_mode is not False:
        raise CaptureError(
            "R-006 normative capture requires a machine-observed stable power source "
            "and low power mode off; "
            f"observed power={power_source or 'unavailable'}, "
            f"low_power_mode={low_power_mode!r}"
        )
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
            "machine_verified": True,
            "power_source": power_source,
            "low_power_mode": low_power_mode,
        },
    }
