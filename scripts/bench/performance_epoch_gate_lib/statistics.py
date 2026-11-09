"""Authenticated adapter to the frozen autoresearch statistical authority."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from typing import Any

from .model import EvidenceError


def _module(root: Path, protocol: dict[str, Any]):
    expected = protocol["authority"]["stats_sha256"]
    path = root / protocol["authority"]["stats_path"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise EvidenceError("frozen statistics source digest mismatch")
    spec = importlib.util.spec_from_file_location("stwo_perf_epoch3_stats", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("cannot load frozen statistics source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workload_seed(workload_id: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{workload_id}:0".encode("utf-8")).digest()[:4], "big")


def first_order(workload_id: str) -> str:
    return "AB" if hashlib.sha256(workload_id.encode("utf-8")).digest()[0] & 1 == 0 else "BA"


def evaluate_workload(
    root: Path,
    protocol: dict[str, Any],
    workload_id: str,
    ratios: list[float],
) -> tuple[float, float, float]:
    authority = _module(root, protocol)
    policy = protocol["statistics"]
    estimate = authority.hodges_lehmann(ratios)
    lower, upper = authority.bootstrap_ci(
        ratios,
        level=policy["confidence_level"],
        iterations=policy["bootstrap_iterations"],
        seed=workload_seed(workload_id),
    )
    return estimate, lower, upper
