"""Public API for the recursion/CSP measurement boundary."""

from .codec import (
    EvidenceError,
    atomic_write_new,
    canonical_bytes,
    decode_json,
    load_json,
)
from .active_probe import (
    collect_active_outer_probe,
    parse_active_outer_output,
    validate_active_outer_probe,
)
from .contract import validate_recursive_report
from .canonical_producer import (
    build_workload_request,
    collect_canonical_outer_report,
    validate_canonical_attempt,
)
from .pipeline import build_comparison, build_plan, validate_plan
from .shape_coverage import collect_shape_audit, validate_shape_audit

__all__ = [
    "EvidenceError",
    "atomic_write_new",
    "build_comparison",
    "build_plan",
    "build_workload_request",
    "canonical_bytes",
    "collect_active_outer_probe",
    "collect_canonical_outer_report",
    "collect_shape_audit",
    "decode_json",
    "load_json",
    "parse_active_outer_output",
    "validate_plan",
    "validate_active_outer_probe",
    "validate_canonical_attempt",
    "validate_recursive_report",
    "validate_shape_audit",
]
