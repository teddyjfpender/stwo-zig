"""Validation for resource telemetry measured across a Native request batch."""

from __future__ import annotations

import argparse
from typing import Any

from .model import MatrixError
from .validation import (
    require_bool,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
)


RESOURCE_KEYS = {
    "measurement_scope",
    "source",
    "measured_warmups",
    "measured_samples",
    "lifetime_peak_physical_footprint_bytes",
    "energy_nj",
    "instructions",
    "cycles",
    "canonical_proof_bytes",
    "complete",
    "unavailable_reason",
}
COUNTER_NAMES = (
    "lifetime_peak_physical_footprint_bytes",
    "energy_nj",
    "instructions",
    "cycles",
)


def validate_request_resources(
    report: dict[str, Any],
    lane: str,
    args: argparse.Namespace,
    fingerprint: tuple[str, int],
) -> bool:
    resources = require_object(report, "resources", lane)
    require_exact_keys(resources, RESOURCE_KEYS, f"{lane}.resources")
    if resources["measurement_scope"] != "verified_process_request_batch":
        raise MatrixError(f"{lane}.resources measurement scope is not governed")
    if require_int(
        resources["measured_warmups"], f"{lane}.resources.measured_warmups"
    ) != args.warmups:
        raise MatrixError(f"{lane}.resources measured warmups differ from request")
    if require_int(
        resources["measured_samples"], f"{lane}.resources.measured_samples"
    ) != args.samples:
        raise MatrixError(f"{lane}.resources measured samples differ from request")
    if require_int(
        resources["canonical_proof_bytes"],
        f"{lane}.resources.canonical_proof_bytes",
        positive=True,
    ) != fingerprint[1]:
        raise MatrixError(f"{lane}.resources canonical proof bytes disagree with proof")

    complete = require_bool(resources["complete"], f"{lane}.resources.complete")
    source = require_string(resources["source"], f"{lane}.resources.source")
    reason = resources["unavailable_reason"]
    if complete:
        if source != "darwin_proc_pid_rusage_v6" or reason is not None:
            raise MatrixError(
                f"{lane}.resources complete telemetry requires the Darwin v6 source"
            )
        for name in COUNTER_NAMES:
            require_int(resources[name], f"{lane}.resources.{name}", positive=True)
    else:
        if source != "unsupported":
            raise MatrixError(
                f"{lane}.resources incomplete telemetry requires source=unsupported"
            )
        require_string(reason, f"{lane}.resources.unavailable_reason", nonempty=True)
        if any(resources[name] is not None for name in COUNTER_NAMES):
            raise MatrixError(f"{lane}.resources unsupported counters must all be null")
    return complete
