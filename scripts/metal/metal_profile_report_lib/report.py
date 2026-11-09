"""Aggregate stwo-zig's opt-in Metal NDJSON telemetry into a hot-path report."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

EVENT_SCHEMA = "stwo-metal-profile-v1"
REPORT_SCHEMA = "stwo-metal-profile-report-v1"


class ProfileError(ValueError):
    pass


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ProfileError(f"{field} must be finite and non-negative")
    return result


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProfileError(f"{field} must be a non-negative integer")
    return value


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProfileError(f"{path}:{line_number}: invalid JSON: {error.msg}") from error
        if not isinstance(event, dict):
            raise ProfileError(f"{path}:{line_number}: event must be an object")
        if event.get("schema") != EVENT_SCHEMA:
            raise ProfileError(f"{path}:{line_number}: unsupported event schema")
        events.append(event)
    if not events:
        raise ProfileError(f"{path}: profile is empty")
    return events


def _percentile(values: Iterable[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _rounded(value: float) -> float:
    return round(value, 6)


def _aggregate_rows(samples: dict[str, list[dict[str, Any]]], denominator: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, entries in samples.items():
        gpu_values = [entry["gpu_ms"] for entry in entries if entry.get("gpu_ms") is not None]
        total_gpu_ms = sum(gpu_values)
        row: dict[str, Any] = {
            "name": name,
            "count": len(entries),
            "timed_count": len(gpu_values),
            "total_gpu_ms": _rounded(total_gpu_ms),
            "gpu_percent": _rounded(total_gpu_ms * 100.0 / denominator) if denominator else 0.0,
            "p50_gpu_ms": _rounded(_percentile(gpu_values, 0.50)),
            "p95_gpu_ms": _rounded(_percentile(gpu_values, 0.95)),
            "max_gpu_ms": _rounded(max(gpu_values, default=0.0)),
        }
        for field in (
            "encode_cpu_ms",
            "commit_cpu_ms",
            "wait_cpu_ms",
            "dispatches",
            "grid_threads",
            "inline_bytes",
            "blit_bytes",
        ):
            total = sum(entry.get(field, 0) for entry in entries)
            row[f"total_{field}"] = _rounded(total) if field.endswith("_ms") else total
        row["max_bound_buffer_capacity_bytes"] = max(
            (entry.get("bound_buffer_capacity_bytes", 0) for entry in entries), default=0
        )
        rows.append(row)
    rows.sort(key=lambda row: (-row["total_gpu_ms"], row["name"]))
    return rows


def build_report(events: list[dict[str, Any]]) -> dict[str, Any]:
    metadata = [event for event in events if event.get("type") == "metadata"]
    if len(metadata) != 1:
        raise ProfileError("profile must contain exactly one metadata event")
    encoder_timestamps_requested = metadata[0].get("encoder_timestamps_requested")
    encoder_timestamps_enabled = metadata[0].get("encoder_timestamps_enabled")
    if not isinstance(encoder_timestamps_requested, bool) or not isinstance(
        encoder_timestamps_enabled, bool
    ):
        raise ProfileError("metadata must declare encoder timestamp request and enablement")
    counter_configuration_errors = int(
        encoder_timestamps_requested and not encoder_timestamps_enabled
    )
    commands = [event for event in events if event.get("type") == "command_buffer"]
    if not commands:
        raise ProfileError("profile contains no command_buffer events")

    command_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    kernel_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    command_gpu_total = 0.0
    encoder_gpu_total = 0.0
    unattributed_total = 0.0
    error_count = 0
    overflow_count = 0
    allocation_error_count = 0
    timing_inconsistent_count = 0
    max_encoder_command_excess_ms = 0.0
    encoder_count = 0
    untimed_encoder_count = 0

    for index, command in enumerate(commands):
        prefix = f"command_buffer[{index}]"
        operation = command.get("operation")
        if not isinstance(operation, str) or not operation:
            raise ProfileError(f"{prefix}.operation must be a non-empty string")
        command_gpu = _number(command.get("gpu_ms"), f"{prefix}.gpu_ms")
        encoded_encoder_gpu = _number(
            command.get("encoder_gpu_ms", 0.0), f"{prefix}.encoder_gpu_ms"
        )
        unattributed = _number(
            command.get("unattributed_gpu_ms", 0.0), f"{prefix}.unattributed_gpu_ms"
        )
        sample = {
            "gpu_ms": command_gpu,
            "encode_cpu_ms": _number(command.get("encode_cpu_ms", 0.0), f"{prefix}.encode_cpu_ms"),
            "commit_cpu_ms": _number(command.get("commit_cpu_ms", 0.0), f"{prefix}.commit_cpu_ms"),
            "wait_cpu_ms": _number(command.get("wait_cpu_ms", 0.0), f"{prefix}.wait_cpu_ms"),
        }
        command_samples[operation].append(sample)
        command_gpu_total += command_gpu
        if command.get("status") == "error" or command.get("error") is not None:
            error_count += 1
        if command.get("counter_overflow") is True:
            overflow_count += 1
        counter_allocation_error = command.get("counter_allocation_error")
        if counter_allocation_error is not None:
            if not isinstance(counter_allocation_error, str) or not counter_allocation_error:
                raise ProfileError(f"{prefix}.counter_allocation_error must be a non-empty string")
            allocation_error_count += 1

        encoders = command.get("encoders")
        if not isinstance(encoders, list):
            raise ProfileError(f"{prefix}.encoders must be an array")
        derived_encoder_gpu = 0.0
        for encoder_index, encoder in enumerate(encoders):
            encoder_prefix = f"{prefix}.encoders[{encoder_index}]"
            if not isinstance(encoder, dict):
                raise ProfileError(f"{encoder_prefix} must be an object")
            kind = encoder.get("kind")
            pipelines = encoder.get("pipelines")
            if kind not in ("compute", "blit") or not isinstance(pipelines, list):
                raise ProfileError(f"{encoder_prefix} has invalid kind or pipelines")
            if not all(isinstance(name, str) and name for name in pipelines):
                raise ProfileError(f"{encoder_prefix}.pipelines contains an invalid name")
            name = "+".join(pipelines) if pipelines else kind
            gpu_ms = encoder.get("gpu_ms")
            if gpu_ms is not None:
                gpu_ms = _number(gpu_ms, f"{encoder_prefix}.gpu_ms")
                derived_encoder_gpu += gpu_ms
            else:
                untimed_encoder_count += 1
            kernel_samples[name].append(
                {
                    "gpu_ms": gpu_ms,
                    "dispatches": _integer(encoder.get("dispatches", 0), f"{encoder_prefix}.dispatches"),
                    "grid_threads": _integer(encoder.get("grid_threads", 0), f"{encoder_prefix}.grid_threads"),
                    "bound_buffer_capacity_bytes": _integer(
                        encoder.get("bound_buffer_capacity_bytes", 0),
                        f"{encoder_prefix}.bound_buffer_capacity_bytes",
                    ),
                    "inline_bytes": _integer(encoder.get("inline_bytes", 0), f"{encoder_prefix}.inline_bytes"),
                    "blit_bytes": _integer(encoder.get("blit_bytes", 0), f"{encoder_prefix}.blit_bytes"),
                }
            )
            encoder_count += 1
        if not math.isclose(
            encoded_encoder_gpu, derived_encoder_gpu, rel_tol=1e-9, abs_tol=1e-6
        ):
            raise ProfileError(f"{prefix}.encoder_gpu_ms does not match encoder samples")
        expected_unattributed = max(0.0, command_gpu - encoded_encoder_gpu)
        if not math.isclose(unattributed, expected_unattributed, rel_tol=1e-9, abs_tol=1e-6):
            raise ProfileError(f"{prefix}.unattributed_gpu_ms is inconsistent")
        encoder_gpu_total += derived_encoder_gpu
        unattributed_total += unattributed
        encoder_excess = derived_encoder_gpu - command_gpu
        max_encoder_command_excess_ms = max(max_encoder_command_excess_ms, encoder_excess)
        if encoder_excess > max(0.05, command_gpu * 0.10):
            timing_inconsistent_count += 1

    command_rows = _aggregate_rows(command_samples, command_gpu_total)
    kernel_rows = _aggregate_rows(kernel_samples, encoder_gpu_total)
    return {
        "schema": REPORT_SCHEMA,
        "source_schema": EVENT_SCHEMA,
        "metadata": metadata[0],
        "summary": {
            "command_buffers": len(commands),
            "encoders": encoder_count,
            "untimed_encoders": untimed_encoder_count,
            "command_errors": error_count,
            "counter_overflows": overflow_count,
            "counter_allocation_errors": allocation_error_count,
            "counter_configuration_errors": counter_configuration_errors,
            "encoder_timestamps_enabled": encoder_timestamps_enabled,
            "timing_inconsistent_commands": timing_inconsistent_count,
            "max_encoder_command_excess_ms": _rounded(max(0.0, max_encoder_command_excess_ms)),
            "command_gpu_ms": _rounded(command_gpu_total),
            "encoder_gpu_ms": _rounded(encoder_gpu_total),
            "unattributed_gpu_ms": _rounded(unattributed_total),
            "encode_cpu_ms": _rounded(sum(row["total_encode_cpu_ms"] for row in command_rows)),
            "commit_cpu_ms": _rounded(sum(row["total_commit_cpu_ms"] for row in command_rows)),
            "wait_cpu_ms": _rounded(sum(row["total_wait_cpu_ms"] for row in command_rows)),
        },
        "commands": command_rows,
        "kernels": kernel_rows,
    }


def _human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            return f"{amount:.1f}{unit}"
        amount /= 1024.0
    raise AssertionError("unreachable")


def format_text(report: dict[str, Any], top: int) -> str:
    metadata = report["metadata"]
    summary = report["summary"]
    lines = [
        f"Metal profile: {metadata.get('device', 'unknown device')}",
        (
            f"commands={summary['command_buffers']} encoders={summary['encoders']} "
            f"command_gpu={summary['command_gpu_ms']:.3f}ms "
            f"encoder_gpu={summary['encoder_gpu_ms']:.3f}ms "
            f"unattributed={summary['unattributed_gpu_ms']:.3f}ms"
        ),
        (
            f"host encode={summary['encode_cpu_ms']:.3f}ms "
            f"commit={summary['commit_cpu_ms']:.3f}ms wait={summary['wait_cpu_ms']:.3f}ms "
            f"errors={summary['command_errors']} untimed={summary['untimed_encoders']} "
            f"counter_overflows={summary['counter_overflows']} "
            f"counter_alloc_errors={summary['counter_allocation_errors']} "
            f"counter_config_errors={summary['counter_configuration_errors']} "
            f"timing_inconsistent={summary['timing_inconsistent_commands']}"
        ),
        "",
        "Top command-buffer operations",
        "GPU ms    Share   Count  p50 ms   p95 ms   Wait ms   Name",
    ]
    for row in report["commands"][:top]:
        lines.append(
            f"{row['total_gpu_ms']:8.3f}  {row['gpu_percent']:6.2f}%  {row['count']:5d}  "
            f"{row['p50_gpu_ms']:7.3f}  {row['p95_gpu_ms']:7.3f}  "
            f"{row['total_wait_cpu_ms']:8.3f}  {row['name']}"
        )
    encoder_heading = (
        "Top encoder/kernel hot paths"
        if summary["encoder_timestamps_enabled"]
        else "Encoder/kernel dispatch inventory (GPU timing disabled)"
    )
    lines.extend(
        [
            "",
            encoder_heading,
            "GPU ms    Share   Count  p50 ms   p95 ms   Dispatches  Max bound  Name",
        ]
    )
    for row in report["kernels"][:top]:
        lines.append(
            f"{row['total_gpu_ms']:8.3f}  {row['gpu_percent']:6.2f}%  {row['count']:5d}  "
            f"{row['p50_gpu_ms']:7.3f}  {row['p95_gpu_ms']:7.3f}  "
            f"{row['total_dispatches']:10d}  {_human_bytes(row['max_bound_buffer_capacity_bytes']):>9}  "
            f"{row['name']}"
        )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path, help="runtime NDJSON from STWO_ZIG_METAL_PROFILE_OUT")
    parser.add_argument("--json-out", type=Path, help="write the complete aggregate report as JSON")
    parser.add_argument("--top", type=int, default=20, help="rows in each text ranking (default: 20)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail when commands error, timestamp samples are missing, or counters overflow",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.top <= 0:
        raise ProfileError("--top must be positive")
    report = build_report(load_events(args.profile))
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(format_text(report, args.top))
    summary = report["summary"]
    if args.strict and (
        summary["command_errors"] > 0
        or (summary["encoder_timestamps_enabled"] and summary["untimed_encoders"] > 0)
        or summary["counter_overflows"] > 0
        or summary["counter_allocation_errors"] > 0
        or summary["counter_configuration_errors"] > 0
        or summary["timing_inconsistent_commands"] > 0
    ):
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProfileError) as error:
        print(f"metal_profile_report: {error}", file=sys.stderr)
        raise SystemExit(1)
