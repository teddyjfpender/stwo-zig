"""OS-explicit `/usr/bin/time` command and output contract."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any


TIME_BINARY = Path("/usr/bin/time")
DARWIN_MEASUREMENT = "darwin_usr_bin_time_l_v1"
GNU_LINUX_MEASUREMENT = "gnu_usr_bin_time_v_v1"
WALL_CLOCK_MEASUREMENT = "wall_clock_only_v1"

DARWIN_MAX_RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)
GNU_MAX_RSS_RE = re.compile(
    r"^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$",
    re.MULTILINE,
)
DARWIN_INSTRUCTIONS_RE = re.compile(r"^\s*(\d+)\s+instructions retired\s*$", re.MULTILINE)
DARWIN_CYCLES_RE = re.compile(r"^\s*(\d+)\s+cycles elapsed\s*$", re.MULTILINE)
DARWIN_PEAK_FOOTPRINT_RE = re.compile(
    r"^\s*(\d+)\s+peak memory footprint\s*$",
    re.MULTILINE,
)


class ResourceMeasurementError(RuntimeError):
    """The host cannot produce or parse the declared resource measurement."""


def measurement_for_platform(
    *,
    platform: str | None = None,
    time_binary: Path = TIME_BINARY,
    required: bool = False,
) -> str:
    host = sys.platform if platform is None else platform
    if not time_binary.is_file():
        if required:
            raise ResourceMeasurementError(
                f"resource measurement binary is missing: {time_binary}"
            )
        return WALL_CLOCK_MEASUREMENT
    if host == "darwin":
        return DARWIN_MEASUREMENT
    if host.startswith("linux"):
        return GNU_LINUX_MEASUREMENT
    if required:
        raise ResourceMeasurementError(f"peak RSS measurement is unsupported on {host}")
    return WALL_CLOCK_MEASUREMENT


def measurement_command(
    command: list[str],
    *,
    platform: str | None = None,
    time_binary: Path = TIME_BINARY,
    required: bool = False,
) -> tuple[list[str], str]:
    measurement = measurement_for_platform(
        platform=platform,
        time_binary=time_binary,
        required=required,
    )
    if measurement == DARWIN_MEASUREMENT:
        return [str(time_binary), "-l", *command], measurement
    if measurement == GNU_LINUX_MEASUREMENT:
        return [str(time_binary), "-v", *command], measurement
    return list(command), measurement


def measurement_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    if extra:
        environment.update(extra)
    environment["LC_ALL"] = "C"
    return environment


def _single_metric(pattern: re.Pattern[str], output: str, name: str) -> int | None:
    matches = pattern.findall(output)
    if len(matches) > 1:
        raise ResourceMeasurementError(f"resource output reports {name} more than once")
    return int(matches[0]) if matches else None


def parse_process_resources(
    stderr: bytes | str,
    measurement: str,
    *,
    require_peak_rss: bool = True,
) -> dict[str, Any]:
    output = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
    if measurement == DARWIN_MEASUREMENT:
        raw_rss = _single_metric(DARWIN_MAX_RSS_RE, output, "peak RSS")
        peak_rss_kib = (raw_rss + 1023) // 1024 if raw_rss is not None else None
        instructions = _single_metric(DARWIN_INSTRUCTIONS_RE, output, "instructions")
        cycles = _single_metric(DARWIN_CYCLES_RE, output, "cycles")
        footprint = _single_metric(DARWIN_PEAK_FOOTPRINT_RE, output, "peak footprint")
    elif measurement == GNU_LINUX_MEASUREMENT:
        peak_rss_kib = _single_metric(GNU_MAX_RSS_RE, output, "peak RSS")
        instructions = None
        cycles = None
        footprint = None
    elif measurement == WALL_CLOCK_MEASUREMENT:
        peak_rss_kib = None
        instructions = None
        cycles = None
        footprint = None
    else:
        raise ResourceMeasurementError(
            f"unsupported process-resource measurement: {measurement}"
        )

    if require_peak_rss and (peak_rss_kib is None or peak_rss_kib <= 0):
        raise ResourceMeasurementError(
            f"resource measurement {measurement} did not report one positive peak RSS"
        )
    return {
        "measurement": measurement,
        "measurement_locale": "C",
        "normalized_unit": "KiB",
        "peak_rss_kib": peak_rss_kib,
        "instructions_retired": instructions,
        "cycles_elapsed": cycles,
        "peak_memory_footprint_bytes": footprint,
    }


def collector_label(measurement: str, *, sample: bool = False) -> str:
    base = {
        DARWIN_MEASUREMENT: "time -l",
        GNU_LINUX_MEASUREMENT: "time -v",
        WALL_CLOCK_MEASUREMENT: "wall-clock-only",
    }.get(measurement)
    if base is None:
        raise ResourceMeasurementError(f"unsupported collector label: {measurement}")
    return f"{base} + sample" if sample else base
