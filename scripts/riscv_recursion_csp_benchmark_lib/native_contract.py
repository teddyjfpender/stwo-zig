"""Shared native-report constants for recursion CSP evidence."""

from decimal import Decimal

NATIVE_SCHEMAS = frozenset({"stwo_riscv_csp_benchmark_v4"})
NATIVE_TIMING_SOURCE = "production CLI internal stage timers"
MAX_PHASE_SECONDS = Decimal(86_400)
