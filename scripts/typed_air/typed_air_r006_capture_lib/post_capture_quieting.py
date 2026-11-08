"""Bounded host quieting before an R-006 capture checkpoint is sealed."""

from __future__ import annotations

import time
from typing import Any, Callable

from .model import CaptureError
from .preflight import validate_host_preflight
from .pair_recovery import require_host_at_prefix


POST_CAPTURE_QUIETING_POLICY = {
    "schema": "stwo.typed-air.r006-post-capture-quieting.v2",
    "retry_fresh_preflight": True,
    "thresholds": "host-preflight-v2-unchanged",
    "retry_interval_ns": 30_000_000_000,
    "timeout_ns": 900_000_000_000,
}


PreflightProvider = Callable[[], dict[str, Any]]
Sleeper = Callable[[float], None]
Monotonic = Callable[[], int]


def require_admitted_preflight(
    provider: PreflightProvider,
    expected_host: dict[str, Any],
    *,
    expected_power_source: str | None = None,
) -> dict[str, Any]:
    current = validate_host_preflight(provider(), require_admitted=True)
    require_host_at_prefix(
        current["host"],
        expected_host,
        power_source=(
            expected_host["power_source"]
            if expected_power_source is None
            else expected_power_source
        ),
    )
    return current


def await_admitted_post_capture_preflight(
    *,
    provider: PreflightProvider,
    expected_host: dict[str, Any],
    expected_power_source: str | None = None,
    sleeper: Sleeper = time.sleep,
    monotonic: Monotonic = time.monotonic_ns,
    retry_interval_ns: int = POST_CAPTURE_QUIETING_POLICY["retry_interval_ns"],
    timeout_ns: int = POST_CAPTURE_QUIETING_POLICY["timeout_ns"],
) -> dict[str, Any]:
    """Return the first fresh admitted sample, or fail after the fixed bound."""

    if (
        type(retry_interval_ns) is not int
        or retry_interval_ns <= 0
        or type(timeout_ns) is not int
        or timeout_ns <= 0
        or retry_interval_ns > timeout_ns
    ):
        raise CaptureError("post-capture quieting policy is invalid")
    started_ns = monotonic()
    while True:
        current = validate_host_preflight(provider(), require_admitted=False)
        require_host_at_prefix(
            current["host"],
            expected_host,
            power_source=(
                expected_host["power_source"]
                if expected_power_source is None
                else expected_power_source
            ),
        )
        elapsed_ns = monotonic() - started_ns
        if elapsed_ns < 0:
            raise CaptureError("post-capture quieting monotonic clock regressed")
        if current["admissible"] is True:
            if elapsed_ns > timeout_ns:
                raise CaptureError(
                    "post-capture host quieting timed out before an admitted preflight"
                )
            return current
        if elapsed_ns >= timeout_ns:
            raise CaptureError(
                "post-capture host quieting timed out before an admitted preflight"
            )
        sleeper(min(retry_interval_ns, timeout_ns - elapsed_ns) / 1_000_000_000)
