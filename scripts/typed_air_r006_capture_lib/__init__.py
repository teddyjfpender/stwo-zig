"""Fail-closed R-006 worker-scaling capture authority."""

from .contract import PlanSettings, build_plan, load_plan, validate_plan, write_plan_new
from .controller import CaptureSettings, capture, validate_bundle
from .model import CaptureError
from .orchestration import (
    SmokeSettings,
    host_preflight,
    install_candidate,
    installed_v4_smoke,
    materialize_snapshot,
    validate_snapshot_receipt,
)
from .pair import (
    PAIR_ATTEMPTS,
    PairCaptureSettings,
    PairPlanSettings,
    build_pair_plan,
    capture_pair,
    load_pair_plan,
    validate_pair_bundle,
    validate_pair_plan,
    write_pair_plan_new,
)
from .reduction import evaluate_pair_scaling, validate_pair_reduction
from .preflight import validate_host_preflight

__all__ = [
    "CaptureError",
    "CaptureSettings",
    "PAIR_ATTEMPTS",
    "PairCaptureSettings",
    "PairPlanSettings",
    "PlanSettings",
    "SmokeSettings",
    "build_plan",
    "build_pair_plan",
    "capture",
    "capture_pair",
    "evaluate_pair_scaling",
    "load_plan",
    "load_pair_plan",
    "host_preflight",
    "install_candidate",
    "installed_v4_smoke",
    "materialize_snapshot",
    "validate_host_preflight",
    "validate_snapshot_receipt",
    "validate_bundle",
    "validate_pair_bundle",
    "validate_pair_plan",
    "validate_pair_reduction",
    "validate_plan",
    "write_plan_new",
    "write_pair_plan_new",
]
