"""Bounded host, toolchain, load, and thermal evidence for Native matrices."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .model import RUST_ORACLE_TOOLCHAIN


HOST_SCHEMA = "native_matrix_host_environment_v1"
SNAPSHOT_SCHEMA = "native_matrix_host_load_v1"
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


CommandRunner = Callable[[tuple[str, ...]], CommandResult]


def _run(argv: tuple[str, ...]) -> CommandResult:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return CommandResult(127, "", str(error))
    stdout = completed.stdout[:MAX_COMMAND_OUTPUT_BYTES]
    stderr = completed.stderr[:MAX_COMMAND_OUTPUT_BYTES]
    return CommandResult(completed.returncode, stdout, stderr)


def _value(runner: CommandRunner, *argv: str) -> str | None:
    result = runner(tuple(argv))
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _lines(runner: CommandRunner, *argv: str) -> list[str]:
    value = _value(runner, *argv)
    return [] if value is None else [line.strip() for line in value.splitlines() if line.strip()]


def _system_profile(runner: CommandRunner) -> tuple[dict[str, object], dict[str, object]]:
    hardware: dict[str, object] = {
        "machine_model": None,
        "machine_name": None,
        "chip": None,
        "physical_memory": None,
    }
    metal_device: dict[str, object] = {
        "name": None,
        "gpu_cores": None,
        "metal_family": None,
    }
    raw = _value(
        runner,
        "system_profiler",
        "SPHardwareDataType",
        "SPDisplaysDataType",
        "-json",
        "-detailLevel",
        "mini",
    )
    if raw is None:
        return hardware, metal_device
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return hardware, metal_device
    hardware_rows = document.get("SPHardwareDataType", [])
    if isinstance(hardware_rows, list) and hardware_rows and isinstance(hardware_rows[0], dict):
        row = hardware_rows[0]
        hardware = {
            "machine_model": row.get("machine_model"),
            "machine_name": row.get("machine_name"),
            "chip": row.get("chip_type"),
            "physical_memory": row.get("physical_memory"),
        }
    display_rows = document.get("SPDisplaysDataType", [])
    if isinstance(display_rows, list) and display_rows and isinstance(display_rows[0], dict):
        row = display_rows[0]
        metal_device = {
            "name": row.get("sppci_model") or row.get("_name"),
            "gpu_cores": row.get("sppci_cores"),
            "metal_family": row.get("spdisplays_mtlgpufamilysupport"),
        }
    return hardware, metal_device


def _tool_path(runner: CommandRunner, name: str) -> str | None:
    value = _value(runner, "xcrun", "--find", name)
    return str(Path(value).resolve()) if value is not None else None


def collect_static(
    metal_runtime: str,
    runner: CommandRunner = _run,
) -> dict[str, object]:
    """Collect immutable host identity once, without serial numbers or user data."""

    hardware, metal_device = _system_profile(runner)
    product_version = _value(runner, "sw_vers", "-productVersion")
    build_version = _value(runner, "sw_vers", "-buildVersion")
    developer_dir = _value(runner, "xcode-select", "-p")
    xcode_version = _lines(runner, "xcodebuild", "-version")
    metal_path = _tool_path(runner, "metal")
    metallib_path = _tool_path(runner, "metallib")
    sdk_version = _value(runner, "xcrun", "--sdk", "macosx", "--show-sdk-version")
    zig_version = _value(runner, "zig", "version")
    rust_version = _value(runner, "rustc", f"+{RUST_ORACLE_TOOLCHAIN}", "--version")

    blockers: list[str] = []
    required = {
        "os_product_version": product_version,
        "os_build_version": build_version,
        "hardware.machine_model": hardware["machine_model"],
        "hardware.chip": hardware["chip"],
        "metal_device.name": metal_device["name"],
        "metal_device.metal_family": metal_device["metal_family"],
        "toolchain.developer_dir": developer_dir,
        "toolchain.macos_sdk_version": sdk_version,
        "toolchain.zig_version": zig_version,
        "toolchain.rust_version": rust_version,
    }
    blockers.extend(f"missing_{name}" for name, value in required.items() if value is None)
    if metal_runtime == "authenticated-aot":
        if not xcode_version:
            blockers.append("missing_toolchain.xcode_version")
        if metal_path is None:
            blockers.append("missing_toolchain.metal_compiler")
        if metallib_path is None:
            blockers.append("missing_toolchain.metallib_linker")

    return {
        "schema": HOST_SCHEMA,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "os_product_version": product_version,
            "os_build_version": build_version,
        },
        "hardware": {
            **hardware,
            "logical_cpu_count": os.cpu_count(),
        },
        "metal_device": metal_device,
        "toolchain": {
            "developer_dir": developer_dir,
            "xcode_version": xcode_version or None,
            "macos_sdk_version": sdk_version,
            "metal_compiler_path": metal_path,
            "metallib_linker_path": metallib_path,
            "runtime_compiler": (
                "authenticated_offline_metallib"
                if metal_runtime == "authenticated-aot"
                else "Metal.framework_source_jit_bound_to_os_build"
            ),
            "zig_version": zig_version,
            "rust_toolchain": RUST_ORACLE_TOOLCHAIN,
            "rust_version": rust_version,
        },
        "randomness": {
            "external_seed": None,
            "input_policy": "canonical_workload_descriptor_and_fixed_statement",
            "proof_policy": "deterministic_transcript_no_external_random_seed",
        },
        "complete": not blockers,
        "blockers": blockers,
    }


def collect_load(runner: CommandRunner = _run) -> dict[str, object]:
    """Capture a small start/end load snapshot around the sequential matrix."""

    cpu_count = os.cpu_count()
    try:
        load = os.getloadavg()
    except OSError:
        load = (0.0, 0.0, 0.0)
    thermal = _lines(runner, "pmset", "-g", "therm")
    battery = _lines(runner, "pmset", "-g", "batt")
    power_source = None
    if battery and "'" in battery[0]:
        power_source = battery[0].split("'", 2)[1]
    blockers = [] if thermal else ["missing_thermal_status"]
    return {
        "schema": SNAPSHOT_SCHEMA,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "load_average": {
            "one_minute": load[0],
            "five_minutes": load[1],
            "fifteen_minutes": load[2],
            "one_minute_per_logical_cpu": (
                load[0] / cpu_count if cpu_count is not None and cpu_count > 0 else None
            ),
        },
        "thermal_status": thermal,
        "power_source": power_source,
        "timezone": datetime.now().astimezone().tzname(),
        "complete": not blockers,
        "blockers": blockers,
    }


def validate_environment(value: object, metal_runtime: str) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("schema") != HOST_SCHEMA:
        raise ValueError("host environment has an invalid schema")
    if value.get("complete") is not True or value.get("blockers") != []:
        raise ValueError("host environment provenance is incomplete")
    toolchain = value.get("toolchain")
    if not isinstance(toolchain, dict):
        raise ValueError("host environment toolchain is missing")
    if metal_runtime == "authenticated-aot" and not all(
        toolchain.get(field)
        for field in ("xcode_version", "metal_compiler_path", "metallib_linker_path")
    ):
        raise ValueError("authenticated AOT provenance lacks the offline Metal toolchain")
    return value


def validate_load(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError("host load snapshot has an invalid schema")
    if value.get("complete") is not True or value.get("blockers") != []:
        raise ValueError("host load snapshot is incomplete")
    loads = value.get("load_average")
    if not isinstance(loads, dict):
        raise ValueError("host load snapshot lacks load averages")
    for name in ("one_minute", "five_minutes", "fifteen_minutes"):
        number = loads.get(name)
        if isinstance(number, bool) or not isinstance(number, (int, float)) or number < 0:
            raise ValueError(f"host load snapshot {name} is invalid")
    return value
