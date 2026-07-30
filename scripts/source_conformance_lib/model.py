"""Shared finding representation for source-conformance scanners."""

from __future__ import annotations

from dataclasses import dataclass

from . import policy


HEADROOM_PREFIX = "headroom:"


@dataclass(frozen=True, order=True)
class Finding:
    key: str
    message: str
    line_count: int | None = None
    limit: int | None = None


def is_headroom(finding: Finding) -> bool:
    """Report whether ``finding`` is a non-failing size notice rather than a breach."""
    return finding.key.startswith(HEADROOM_PREFIX)


def headroom(key: str, display: object, line_count: int, limit: int, ceiling: str) -> list[Finding]:
    """Return a notice once a measured size has consumed most of ``limit``.

    A size ceiling is otherwise invisible until it blocks, and it then blocks
    whoever touches the file next rather than whoever consumed the headroom. The
    notice reports and never fails: breaches remain the sole business of the
    ordinary finding keys the baseline ratchets.
    """
    if line_count > limit or line_count * 100 < limit * policy.HEADROOM_PERCENT:
        return []
    return [Finding(
        f"{HEADROOM_PREFIX}{key}",
        f"{display}: {line_count} lines approaches the {limit}-line {ceiling} "
        f"({limit - line_count} line(s) of headroom)",
        line_count,
        limit,
    )]
