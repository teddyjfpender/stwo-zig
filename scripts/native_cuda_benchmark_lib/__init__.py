"""Native CUDA lifecycle and paired-benchmark controller."""

from .model import (
    COVERAGE_MATRIX,
    PROFILES,
    BenchmarkError,
    Settings,
    SustainedShape,
    Workload,
)
from .runner import run_benchmark

__all__ = [
    "BenchmarkError",
    "COVERAGE_MATRIX",
    "PROFILES",
    "Settings",
    "SustainedShape",
    "Workload",
    "run_benchmark",
]
