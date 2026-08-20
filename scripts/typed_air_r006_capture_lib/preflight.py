"""Machine-observed R-006 host admission and independent receipt replay."""

from __future__ import annotations

import datetime as dt
import math
import statistics
from typing import Any, Mapping

from .codec import content_digest, exact_object
from .model import DIGEST_RE, UTC_RE, CaptureError


PREFLIGHT_SCHEMA = "stwo.typed-air.r006-host-preflight.v1"
PREFLIGHT_FIELDS = {
    "schema",
    "schema_version",
    "captured_at_utc",
    "admissible",
    "classification",
    "reasons",
    "host",
    "quiet_host",
    "requirements",
    "content_sha256",
}
PREFLIGHT_REQUIREMENTS = {
    "power_source": "AC Power",
    "low_power_mode": False,
    "thermal_warning_state": "clear",
    "minimum_idle_percent": 90.0,
    "median_idle_percent": 95.0,
    "maximum_normalized_load_1m": 0.20,
    "metal_identity_required": True,
}
HOST_FIELDS = {
    "os",
    "os_version",
    "kernel",
    "architecture",
    "host_architecture",
    "cpu",
    "logical_cpu_count",
    "memory_bytes",
    "gpu",
    "power_source",
    "low_power_mode",
    "python",
}
GPU_FIELDS = {"name", "core_count", "metal_support", "unified_memory"}
QUIET_FIELDS = {
    "schema",
    "admissible",
    "reasons",
    "power_admissible",
    "policy",
    "thresholds",
    "observed",
}
QUIET_THRESHOLD_FIELDS = {
    "sample_count",
    "sample_interval_seconds",
    "minimum_idle_percent",
    "median_idle_percent",
    "maximum_normalized_load_1m",
    "load_threshold_enforced",
    "thermal_warning_state",
}
QUIET_OBSERVED_FIELDS = {
    "idle_percent",
    "load_1m",
    "normalized_load_1m",
    "minimum_idle_percent",
    "median_idle_percent",
    "maximum_normalized_load_1m",
    "thermal",
}
THERMAL_FIELDS = {
    "provider",
    "thermal_clear",
    "thermal_output_sha256",
    "thermal_line_count",
    "kernel_thermal_pressure",
}


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _optional_text(value: Any, label: str) -> None:
    if value is not None and (type(value) is not str or not value):
        raise CaptureError(f"R-006 {label} must be nonempty text or null")


def _finite_samples(
    value: Any,
    label: str,
    *,
    minimum: float,
    maximum: float | None,
) -> list[float]:
    if type(value) is not list or len(value) > 3:
        raise CaptureError(f"R-006 {label} samples have invalid cardinality")
    if any(
        type(item) is not float
        or not math.isfinite(item)
        or item < minimum
        or (maximum is not None and item > maximum)
        for item in value
    ):
        raise CaptureError(f"R-006 {label} samples are malformed")
    return value


def _optional_finite_float(
    value: Any,
    label: str,
    *,
    minimum: float,
    maximum: float | None,
) -> None:
    if value is None:
        return
    if (
        type(value) is not float
        or not math.isfinite(value)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise CaptureError(f"R-006 {label} is malformed")


def _validate_host_evidence(value: Any) -> dict[str, Any]:
    host = exact_object(value, HOST_FIELDS, "R-006 host evidence")
    for name in ("os", "os_version", "kernel", "architecture", "cpu", "python"):
        if type(host[name]) is not str or not host[name]:
            raise CaptureError(f"R-006 host {name} must be nonempty text")
    _optional_text(host["host_architecture"], "host architecture")
    logical = host["logical_cpu_count"]
    if type(logical) is not int or logical <= 0:
        raise CaptureError("R-006 logical CPU count must be positive")
    memory = host["memory_bytes"]
    if memory is not None and (type(memory) is not int or memory <= 0):
        raise CaptureError("R-006 host memory must be positive or null")
    _optional_text(host["power_source"], "power source")
    if host["low_power_mode"] is not None and type(host["low_power_mode"]) is not bool:
        raise CaptureError("R-006 Low Power Mode evidence must be boolean or null")

    gpu = exact_object(host["gpu"], GPU_FIELDS, "R-006 GPU evidence")
    _optional_text(gpu["name"], "GPU name")
    cores = gpu["core_count"]
    if cores is not None and (type(cores) is not int or cores <= 0):
        raise CaptureError("R-006 GPU core count must be positive or null")
    _optional_text(gpu["metal_support"], "Metal support")
    if gpu["unified_memory"] is not None and type(gpu["unified_memory"]) is not bool:
        raise CaptureError("R-006 unified-memory evidence must be boolean or null")
    return host


def _validate_thermal_evidence(value: Any, host: Mapping[str, Any]) -> dict[str, Any]:
    thermal = exact_object(value, THERMAL_FIELDS, "R-006 thermal evidence")
    expected_provider = {
        "Darwin": "darwin_top_pmset_v1",
        "Linux": "linux_proc_stat_v1",
    }.get(host["os"], "unsupported_host_v1")
    if thermal["provider"] != expected_provider:
        raise CaptureError("R-006 thermal provider does not match the host OS")
    if type(thermal["thermal_clear"]) is not bool:
        raise CaptureError("R-006 thermal-clear evidence must be boolean")
    digest = thermal["thermal_output_sha256"]
    if type(digest) is not str or DIGEST_RE.fullmatch(digest) is None:
        raise CaptureError("R-006 thermal-output digest is malformed")
    line_count = thermal["thermal_line_count"]
    if type(line_count) is not int or line_count < 0:
        raise CaptureError("R-006 thermal line count is malformed")
    if thermal["thermal_clear"] and host["os"] == "Darwin" and line_count < 2:
        raise CaptureError("R-006 clear Darwin thermal evidence has too few lines")
    _optional_text(thermal["kernel_thermal_pressure"], "kernel thermal pressure")
    return thermal


def _validate_quiet_evidence(value: Any, host: Mapping[str, Any]) -> dict[str, Any]:
    quiet = exact_object(value, QUIET_FIELDS, "R-006 quiet-host evidence")
    if (
        quiet["schema"] != "stwo_native_ab_quiet_host_preflight_v1"
        or type(quiet["admissible"]) is not bool
        or type(quiet["power_admissible"]) is not bool
        or quiet["policy"] != "publishable_initial_or_post_build_v1"
    ):
        raise CaptureError("R-006 quiet-host authority changed")
    if type(quiet["reasons"]) is not list or any(
        type(reason) is not str or not reason for reason in quiet["reasons"]
    ):
        raise CaptureError("R-006 quiet-host reasons are malformed")
    thresholds = exact_object(
        quiet["thresholds"],
        QUIET_THRESHOLD_FIELDS,
        "R-006 quiet-host thresholds",
    )
    expected_thresholds = {
        "sample_count": 3,
        "sample_interval_seconds": 1,
        "minimum_idle_percent": PREFLIGHT_REQUIREMENTS["minimum_idle_percent"],
        "median_idle_percent": PREFLIGHT_REQUIREMENTS["median_idle_percent"],
        "maximum_normalized_load_1m": PREFLIGHT_REQUIREMENTS[
            "maximum_normalized_load_1m"
        ],
        "load_threshold_enforced": True,
        "thermal_warning_state": "clear",
    }
    if thresholds != expected_thresholds or any(
        type(thresholds[name]) is not type(expected)
        for name, expected in expected_thresholds.items()
    ):
        raise CaptureError("R-006 quiet-host thresholds changed")
    observed = exact_object(
        quiet["observed"],
        QUIET_OBSERVED_FIELDS,
        "R-006 quiet-host observations",
    )
    idle = _finite_samples(
        observed["idle_percent"],
        "idle",
        minimum=0.0,
        maximum=100.0,
    )
    loads = _finite_samples(
        observed["load_1m"],
        "load",
        minimum=0.0,
        maximum=None,
    )
    normalized_loads = _finite_samples(
        observed["normalized_load_1m"],
        "normalized load",
        minimum=0.0,
        maximum=None,
    )
    if len(idle) != len(loads) or len(loads) != len(normalized_loads):
        raise CaptureError("R-006 quiet-host sample vectors disagree")
    _optional_finite_float(
        observed["minimum_idle_percent"],
        "minimum idle summary",
        minimum=0.0,
        maximum=100.0,
    )
    _optional_finite_float(
        observed["median_idle_percent"],
        "median idle summary",
        minimum=0.0,
        maximum=100.0,
    )
    _optional_finite_float(
        observed["maximum_normalized_load_1m"],
        "maximum normalized-load summary",
        minimum=0.0,
        maximum=None,
    )
    thermal = _validate_thermal_evidence(observed["thermal"], host)
    power_reasons = _power_reasons(host)
    normalized = [value / host["logical_cpu_count"] for value in loads]
    reasons = list(power_reasons)
    if len(idle) != 3 or len(loads) != 3:
        reasons.append("quiet-host sampler did not return the required three observations")
    if not idle or min(idle) < PREFLIGHT_REQUIREMENTS["minimum_idle_percent"]:
        reasons.append("minimum CPU idle is below 90%")
    if not idle or statistics.median(idle) < PREFLIGHT_REQUIREMENTS["median_idle_percent"]:
        reasons.append("median CPU idle is below 95%")
    if (
        not normalized
        or max(normalized)
        > PREFLIGHT_REQUIREMENTS["maximum_normalized_load_1m"]
    ):
        reasons.append("one-minute load exceeds 0.20 per logical CPU")
    if thermal["thermal_clear"] is not True:
        reasons.append("macOS thermal/performance-warning state is not certified clear")
    expected = {
        "schema": "stwo_native_ab_quiet_host_preflight_v1",
        "admissible": not reasons,
        "reasons": reasons,
        "power_admissible": not power_reasons,
        "policy": "publishable_initial_or_post_build_v1",
        "thresholds": expected_thresholds,
        "observed": {
            "idle_percent": idle,
            "load_1m": loads,
            "normalized_load_1m": normalized,
            "minimum_idle_percent": min(idle) if idle else None,
            "median_idle_percent": statistics.median(idle) if idle else None,
            "maximum_normalized_load_1m": max(normalized) if normalized else None,
            "thermal": thermal,
        },
    }
    if quiet != expected:
        raise CaptureError(
            "R-006 quiet-host verdict is not independently derived from its samples"
        )
    return quiet


def _power_reasons(host: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    source = host["power_source"]
    if source != "AC Power":
        reasons.append(
            "CSP-comparable timings require AC power (observed: "
            f"{source or 'no power-source evidence'})"
        )
    low_power_mode = host["low_power_mode"]
    if low_power_mode is not False:
        reasons.append(
            "CSP-comparable timings require low power mode disabled "
            f"(observed: {'enabled' if low_power_mode else 'no evidence'})"
        )
    return reasons


def _preflight_reasons(
    host: Mapping[str, Any],
    quiet: Mapping[str, Any],
) -> list[str]:
    reasons = list(quiet["reasons"])
    if host["os"] != "Darwin":
        reasons.append("R-006 resource authority requires Darwin")
    if host["power_source"] != "AC Power":
        reasons.append("R-006 normative capture requires machine-observed AC Power")
    if host["low_power_mode"] is not False:
        reasons.append("R-006 normative capture requires Low Power Mode off")
    thermal = quiet["observed"]["thermal"]
    if thermal["thermal_clear"] is not True:
        reasons.append("R-006 thermal/performance-warning state is not certified clear")
    gpu = host["gpu"]
    if not gpu["name"] or not gpu["core_count"] or not gpu["metal_support"]:
        reasons.append("Metal identity/core-count/support evidence is incomplete")
    return list(dict.fromkeys(reasons))


def build_host_preflight(host_value: Any, quiet_value: Any) -> dict[str, Any]:
    """Seal already observed host evidence under the frozen R-006 schema."""

    host = _validate_host_evidence(host_value)
    quiet = _validate_quiet_evidence(quiet_value, host)
    reasons = _preflight_reasons(host, quiet)
    result: dict[str, Any] = {
        "schema": PREFLIGHT_SCHEMA,
        "schema_version": 1,
        "captured_at_utc": _utc_now(),
        "admissible": not reasons,
        "classification": (
            "normative-capture-host-admitted"
            if not reasons
            else "normative-capture-host-rejected"
        ),
        "reasons": reasons,
        "host": host,
        "quiet_host": quiet,
        "requirements": dict(PREFLIGHT_REQUIREMENTS),
    }
    result["content_sha256"] = content_digest(result)
    return result


def validate_host_preflight(
    value: Any,
    *,
    require_admitted: bool,
) -> dict[str, Any]:
    """Replay a sealed preflight without trusting any stored verdict boolean."""

    preflight = exact_object(value, PREFLIGHT_FIELDS, "R-006 host preflight")
    if (
        preflight["schema"] != PREFLIGHT_SCHEMA
        or type(preflight["schema_version"]) is not int
        or preflight["schema_version"] != 1
        or type(preflight["captured_at_utc"]) is not str
        or UTC_RE.fullmatch(preflight["captured_at_utc"]) is None
        or type(preflight["admissible"]) is not bool
        or type(preflight["content_sha256"]) is not str
        or DIGEST_RE.fullmatch(preflight["content_sha256"]) is None
        or preflight["content_sha256"] != content_digest(preflight)
    ):
        raise CaptureError("R-006 host-preflight authority changed")
    requirements = exact_object(
        preflight["requirements"],
        set(PREFLIGHT_REQUIREMENTS),
        "R-006 host-preflight requirements",
    )
    if requirements != PREFLIGHT_REQUIREMENTS or any(
        type(requirements[name]) is not type(expected)
        for name, expected in PREFLIGHT_REQUIREMENTS.items()
    ):
        raise CaptureError("R-006 host-preflight requirements changed")
    if type(preflight["reasons"]) is not list or any(
        type(reason) is not str or not reason for reason in preflight["reasons"]
    ):
        raise CaptureError("R-006 host-preflight reasons are malformed")
    admitted = preflight["admissible"] is True
    expected_classification = (
        "normative-capture-host-admitted"
        if admitted
        else "normative-capture-host-rejected"
    )
    if preflight["classification"] != expected_classification:
        raise CaptureError("R-006 host-preflight classification disagrees")
    if admitted != (not preflight["reasons"]):
        raise CaptureError("R-006 host-preflight verdict and reasons disagree")
    host = _validate_host_evidence(preflight["host"])
    quiet = _validate_quiet_evidence(preflight["quiet_host"], host)
    expected_reasons = _preflight_reasons(host, quiet)
    if preflight["reasons"] != expected_reasons:
        raise CaptureError("R-006 host-preflight reasons are not evidence-derived")
    if admitted != (not expected_reasons):
        raise CaptureError("R-006 host-preflight verdict is not evidence-derived")
    if require_admitted and not admitted:
        raise CaptureError(
            "R-006 normative capture host is inadmissible: "
            + "; ".join(preflight["reasons"])
        )
    return preflight
