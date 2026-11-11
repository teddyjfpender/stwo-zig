"""Canonical workload identities and normalized performance metrics."""

from __future__ import annotations

import hashlib
import json
import statistics
from typing import Any, Dict


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def benchmark_workload_matrix_hash(report: Dict[str, Any]) -> str:
    existing = report.get("workload_matrix_hash")
    if isinstance(existing, str) and existing:
        return existing
    return canonical_hash(
        [
            {
                "name": str(workload.get("name", "unknown")),
                "example": str(workload.get("example", "unknown")),
                "params": workload.get("params", []),
            }
            for workload in report.get("workloads", [])
        ]
    )


def profile_workload_matrix_hash(report: Dict[str, Any]) -> str:
    existing = report.get("workload_matrix_hash")
    if isinstance(existing, str) and existing:
        return existing
    return canonical_hash(
        [
            {
                "runtime": str(profile.get("runtime", "unknown")),
                "workload": str(profile.get("workload", "unknown")),
                "example": str(profile.get("example", "unknown")),
                "command": profile.get("command", []),
            }
            for profile in report.get("profiles", [])
        ]
    )


def kernel_workload_matrix_hash(report: Dict[str, Any]) -> str:
    existing = report.get("workload_matrix_hash")
    if isinstance(existing, str) and existing:
        return existing
    return canonical_hash(
        [
            {
                "name": str(kernel.get("name", "unknown")),
                "log_size": int(kernel.get("log_size", 0)),
                "iterations": int(kernel.get("iterations", 0)),
            }
            for kernel in report.get("kernels", [])
        ]
    )


def workload_ratios(report: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for workload in report.get("workloads", []):
        name = str(workload.get("name", "unknown"))
        ratios = workload.get("ratios", {})
        prove_rss_ratio = ratios.get("zig_over_rust_peak_rss_kb")
        if prove_rss_ratio is None:
            rust_prove = (((workload.get("rust", {}) or {}).get("prove", {}) or {}).get("rss_peak_kb"))
            zig_prove = (((workload.get("zig", {}) or {}).get("prove", {}) or {}).get("rss_peak_kb"))
            if rust_prove not in (None, 0) and zig_prove is not None:
                prove_rss_ratio = float(zig_prove) / float(rust_prove)
        out[name] = {
            "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
            "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
            "zig_over_rust_proof_wire_bytes": float(ratios.get("zig_over_rust_proof_wire_bytes", 0.0)),
            "zig_over_rust_peak_rss_kb": float(prove_rss_ratio) if prove_rss_ratio is not None else 0.0,
        }
    return out


def benchmark_family_ratios(report: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for family in report.get("families", []):
        family_name = str(family.get("family", "unknown"))
        ratios = family.get("ratios", {})
        out[family_name] = {
            "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
            "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
            "zig_over_rust_peak_rss_kb": float(ratios.get("zig_over_rust_peak_rss_kb", 0.0)),
        }
    return out


def zig_profile_seconds(report: Dict[str, Any]) -> Dict[str, float]:
    return {
        str(profile.get("workload", "unknown")): float(
            profile.get("summary", {}).get("avg_seconds", 0.0)
        )
        for profile in report.get("profiles", [])
        if profile.get("runtime") == "zig"
    }


def kernel_avg_seconds(report: Dict[str, Any]) -> Dict[str, float]:
    return {
        str(kernel.get("name", "unknown")): float(
            kernel.get("summary", {}).get("avg_seconds", 0.0)
        )
        for kernel in report.get("kernels", [])
    }


def kernel_effective_seconds(report: Dict[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for kernel in report.get("kernels", []):
        name = str(kernel.get("name", "unknown"))
        summary = kernel.get("summary", {})
        samples_raw = summary.get("samples_seconds")
        if isinstance(samples_raw, list) and samples_raw:
            out[name] = float(statistics.median(float(sample) for sample in samples_raw))
        elif "median_seconds" in summary:
            out[name] = float(summary.get("median_seconds", 0.0))
        else:
            out[name] = float(summary.get("avg_seconds", 0.0))
    return out


def pct_delta(base: float, current: float) -> float:
    if base == 0.0:
        return 0.0
    return ((current - base) / base) * 100.0

