"""Host environment and quiet-state admission for native CSP A/B evidence."""

from __future__ import annotations

import datetime as dt
import os
import re
import statistics
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.riscv_csp_ab_benchmark_lib import contract
from scripts.riscv_csp_benchmark_lib.host import (
    collect_host,
    power_conditions_admissible,
)

from .workspace import _run


QUIET_SAMPLE_COUNT = 3
QUIET_MIN_IDLE_PERCENT = 90.0
QUIET_MEDIAN_IDLE_PERCENT = 95.0
QUIET_MAX_NORMALIZED_LOAD_1M = 0.20


def benchmark_environment(
    inherited: Mapping[str, str], workers: int
) -> tuple[dict[str, str], dict[str, Any]]:
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 32:
        raise contract.ABError("workers must be between 1 and 32")
    environment = dict(inherited)
    removed = sorted(name for name in environment if name.startswith("STWO_"))
    for name in removed:
        environment.pop(name, None)
    for name in ("ZIG_LOCAL_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR"):
        environment.pop(name, None)
    fixed = {
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "STWO_ZIG_MERKLE_WORKERS": str(workers),
        "STWO_ZIG_WORKERS": str(workers),
        "TZ": "UTC",
    }
    environment.update(fixed)
    return environment, {
        "policy": "native_ab_sanitized_v1",
        "removed_stwo_names": removed,
        "removed_zig_cache_names": sorted(
            name
            for name in ("ZIG_LOCAL_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR")
            if name in inherited
        ),
        "fixed": fixed,
        "arm_cache_isolation": {
            "local": ".zig-cache",
            "global": ".zig-cache/ab-global",
            "prefix": "zig-out/native-ab",
        },
        "secret_values_recorded": False,
    }


def _darwin_quiet_samples(sample_count: int) -> tuple[list[float], list[float], dict[str, Any]]:
    # The first `top` sample is a warm-up view.  Only the following fixed-window
    # samples enter the preflight decision.
    completed = _run(
        ["top", "-l", str(sample_count + 1), "-n", "0", "-s", "1"],
        cwd=contract.ROOT,
        timeout=sample_count + 20,
        check=False,
    )
    output = completed.stdout.decode("utf-8", "replace")
    idle = [
        float(value)
        for value in re.findall(r"CPU usage:.*?([0-9]+(?:\.[0-9]+)?)% idle", output)
    ][-sample_count:]
    loads = [
        float(value)
        for value in re.findall(r"Load Avg: ([0-9]+(?:\.[0-9]+)?)", output)
    ][-sample_count:]
    thermal = _run(
        ["pmset", "-g", "therm"],
        cwd=contract.ROOT,
        timeout=10,
        check=False,
    )
    thermal_text = thermal.stdout.decode("utf-8", "replace").strip()
    thermal_lines = [line.strip() for line in thermal_text.splitlines() if line.strip()]
    thermal_clear = (
        thermal.returncode == 0
        and len(thermal_lines) >= 2
        and all(line.startswith("Note: No ") for line in thermal_lines)
    )
    pressure = _run(
        ["sysctl", "-n", "kern.thermal_pressure"],
        cwd=contract.ROOT,
        timeout=10,
        check=False,
    )
    return idle, loads, {
        "provider": "darwin_top_pmset_v1",
        "thermal_clear": thermal_clear,
        "thermal_output_sha256": contract.sha256_bytes(thermal.stdout),
        "thermal_line_count": len(thermal_lines),
        "kernel_thermal_pressure": (
            pressure.stdout.decode("utf-8", "replace").strip()
            if pressure.returncode == 0
            else None
        ),
    }


def _linux_quiet_samples(sample_count: int) -> tuple[list[float], list[float], dict[str, Any]]:
    def cpu_ticks() -> tuple[int, int]:
        try:
            fields = (Path("/proc/stat").read_text(encoding="ascii").splitlines()[0]).split()[1:]
            values = [int(value) for value in fields]
        except (OSError, ValueError, IndexError) as error:
            raise contract.ABError(f"cannot sample Linux CPU idle state: {error}") from error
        idle_ticks = values[3] + (values[4] if len(values) > 4 else 0)
        return idle_ticks, sum(values)

    idle: list[float] = []
    loads: list[float] = []
    prior_idle, prior_total = cpu_ticks()
    for _ in range(sample_count):
        time.sleep(1)
        next_idle, next_total = cpu_ticks()
        delta_total = next_total - prior_total
        delta_idle = next_idle - prior_idle
        if delta_total <= 0:
            raise contract.ABError("Linux CPU tick counter did not advance")
        idle.append(delta_idle / delta_total * 100.0)
        loads.append(os.getloadavg()[0])
        prior_idle, prior_total = next_idle, next_total
    return idle, loads, {
        "provider": "linux_proc_stat_v1",
        "thermal_clear": False,
        "thermal_output_sha256": contract.sha256_bytes(b"unavailable"),
        "thermal_line_count": 0,
        "kernel_thermal_pressure": None,
    }


def classify_quiet_host(
    *,
    idle_percent: Sequence[float],
    load_1m: Sequence[float],
    logical_cpu_count: int,
    thermal: Mapping[str, Any],
    power_admissible: bool,
    power_reasons: Sequence[str],
    enforce_load_threshold: bool = True,
) -> dict[str, Any]:
    reasons = list(power_reasons)
    if len(idle_percent) != QUIET_SAMPLE_COUNT or len(load_1m) != QUIET_SAMPLE_COUNT:
        reasons.append("quiet-host sampler did not return the required three observations")
    if not idle_percent or min(idle_percent) < QUIET_MIN_IDLE_PERCENT:
        reasons.append(
            f"minimum CPU idle is below {QUIET_MIN_IDLE_PERCENT:.0f}%"
        )
    if not idle_percent or statistics.median(idle_percent) < QUIET_MEDIAN_IDLE_PERCENT:
        reasons.append(
            f"median CPU idle is below {QUIET_MEDIAN_IDLE_PERCENT:.0f}%"
        )
    normalized_loads = [value / logical_cpu_count for value in load_1m]
    if enforce_load_threshold and (
        not normalized_loads
        or max(normalized_loads) > QUIET_MAX_NORMALIZED_LOAD_1M
    ):
        reasons.append(
            "one-minute load exceeds 0.20 per logical CPU"
        )
    if thermal.get("thermal_clear") is not True:
        reasons.append("macOS thermal/performance-warning state is not certified clear")
    return {
        "schema": "stwo_native_ab_quiet_host_preflight_v1",
        "admissible": not reasons,
        "reasons": reasons,
        "power_admissible": power_admissible,
        "policy": (
            "publishable_initial_or_post_build_v1"
            if enforce_load_threshold
            else "paired_steady_state_v1"
        ),
        "thresholds": {
            "sample_count": QUIET_SAMPLE_COUNT,
            "sample_interval_seconds": 1,
            "minimum_idle_percent": QUIET_MIN_IDLE_PERCENT,
            "median_idle_percent": QUIET_MEDIAN_IDLE_PERCENT,
            "maximum_normalized_load_1m": QUIET_MAX_NORMALIZED_LOAD_1M,
            "load_threshold_enforced": enforce_load_threshold,
            "thermal_warning_state": "clear",
        },
        "observed": {
            "idle_percent": list(idle_percent),
            "load_1m": list(load_1m),
            "normalized_load_1m": normalized_loads,
            "minimum_idle_percent": min(idle_percent) if idle_percent else None,
            "median_idle_percent": statistics.median(idle_percent) if idle_percent else None,
            "maximum_normalized_load_1m": max(normalized_loads) if normalized_loads else None,
            "thermal": dict(thermal),
        },
    }


def quiet_host_preflight(
    host: Mapping[str, Any], *, enforce_load_threshold: bool = True
) -> dict[str, Any]:
    logical = host.get("logical_cpu_count")
    if isinstance(logical, bool) or not isinstance(logical, int) or logical <= 0:
        raise contract.ABError("quiet-host preflight requires a logical CPU count")
    power_admissible, power_reasons = power_conditions_admissible(host)
    system = host.get("os")
    if system == "Darwin":
        idle, loads, thermal = _darwin_quiet_samples(QUIET_SAMPLE_COUNT)
    elif system == "Linux":
        idle, loads, thermal = _linux_quiet_samples(QUIET_SAMPLE_COUNT)
    else:
        idle, loads, thermal = [], [], {
            "provider": "unsupported_host_v1",
            "thermal_clear": False,
            "thermal_output_sha256": contract.sha256_bytes(b"unavailable"),
            "thermal_line_count": 0,
            "kernel_thermal_pressure": None,
        }
    return classify_quiet_host(
        idle_percent=idle,
        load_1m=loads,
        logical_cpu_count=logical,
        thermal=thermal,
        power_admissible=power_admissible,
        power_reasons=power_reasons,
        enforce_load_threshold=enforce_load_threshold,
    )


def bounded_quiet_gate(
    expected_host: Mapping[str, Any],
    *,
    label: str,
    enforce_load_threshold: bool,
    max_attempts: int,
    retry_seconds: int,
) -> dict[str, Any]:
    if max_attempts <= 0 or retry_seconds < 0:
        raise contract.ABError("quiet-gate retry bounds are invalid")
    attempts: list[dict[str, Any]] = []
    started = time.monotonic()
    for index in range(max_attempts):
        live_host = collect_host()
        observation = quiet_host_preflight(
            live_host,
            enforce_load_threshold=enforce_load_threshold,
        )
        host_matches = live_host == expected_host
        if not host_matches:
            observation = dict(observation)
            observation["admissible"] = False
            observation["reasons"] = [
                *observation["reasons"],
                "live host or power evidence differs from the sealed plan",
            ]
        attempts.append(
            {
                "ordinal": index,
                "captured_at": _now(),
                "host_matches_plan": host_matches,
                "observation": observation,
            }
        )
        print(
            f"[quiet gate] {label}: attempt {index + 1}/{max_attempts} "
            f"{'admitted' if observation['admissible'] else 'busy'}",
            flush=True,
        )
        if observation["admissible"]:
            break
        if index + 1 < max_attempts:
            time.sleep(retry_seconds)
    final = attempts[-1]["observation"]
    return contract.attach_seal(
        {
            "schema": "stwo_native_ab_bounded_quiet_gate_v1",
            "label": label,
            "admissible": final["admissible"],
            "reasons": final["reasons"],
            "enforce_load_threshold": enforce_load_threshold,
            "max_attempts": max_attempts,
            "retry_seconds": retry_seconds,
            "elapsed_seconds": time.monotonic() - started,
            "attempts": attempts,
        }
    )


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
