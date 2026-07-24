"""Native CUDA lifecycle and paired-benchmark controller."""

from .model import (
    COVERAGE_MATRIX,
    PROFILES,
    BenchmarkError,
    Settings,
    Workload,
)
from .runner import run_benchmark

__all__ = [
    "BenchmarkError",
    "COVERAGE_MATRIX",
    "PROFILES",
    "Settings",
    "Workload",
    "run_benchmark",
]
