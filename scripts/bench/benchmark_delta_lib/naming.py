"""Human-readable run identities for the benchmark history archive.

Layout v2 replaces content-hash filenames with named run directories:

    runs/<YYYY-MM-DD-HHMMSS>-<kind>-<commit7>/report.json

The sha256 digests remain the integrity authority — they move into
index.json instead of being the filename. One naming implementation is
shared by the delta archiver, the matrix bundle archiver, and the one-shot
v1 -> v2 migration so the three can never drift.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

_KIND_PATTERNS = (
    (re.compile(r"^native_proof_cross_backend_matrix_(v\d+)$"), r"matrix-\1"),
    (re.compile(r"^upstream_stwo_(.+)$"), r"upstream-\1"),
)

_SAFE = re.compile(r"[^a-z0-9_.-]+")


class NamingError(RuntimeError):
    pass


def kind_short(protocol: str) -> str:
    """Compact, human-legible kind for a report protocol string."""
    if not isinstance(protocol, str) or not protocol:
        raise NamingError("report protocol must be a nonempty string")
    for pattern, replacement in _KIND_PATTERNS:
        match = pattern.match(protocol)
        if match:
            return pattern.sub(replacement, protocol)
    return _SAFE.sub("-", protocol.lower()).strip("-")


def _utc_stamp(generated_at: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(generated_at)
    except (TypeError, ValueError) as error:
        raise NamingError(f"report generated_at is not ISO-8601: {generated_at!r}") from error
    if parsed.tzinfo is None:
        raise NamingError(f"report generated_at lacks a timezone: {generated_at!r}")
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%d-%H%M%S")


def run_id(generated_at: str, protocol: str, git_commit: str | None) -> str:
    """`2026-07-18-064334-matrix-v5-789feb4c`; commit segment omitted only
    when the source report genuinely lacks provenance."""
    stamp = _utc_stamp(generated_at)
    kind = kind_short(protocol)
    if isinstance(git_commit, str) and re.fullmatch(r"[0-9a-f]{7,40}", git_commit):
        return f"{stamp}-{kind}-{git_commit[:8]}"
    return f"{stamp}-{kind}"


def run_id_for_report(report: dict[str, Any]) -> str:
    provenance = report.get("configuration", {}).get("provenance", {})
    commit = provenance.get("git_commit") if isinstance(provenance, dict) else None
    return run_id(report.get("generated_at"), report.get("protocol"), commit)
