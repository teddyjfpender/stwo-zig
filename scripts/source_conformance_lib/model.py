"""Shared finding representation for source-conformance scanners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import policy


HEADROOM_PREFIX = "headroom:"


@dataclass(frozen=True, order=True)
class Finding:
    key: str
    message: str
    line_count: int | None = None
    limit: int | None = None
    #: Repository-relative POSIX path a size notice measured, for change scoping.
    path: str | None = None
    #: Human name of the ceiling a size notice measured against.
    ceiling: str | None = None


def is_headroom(finding: Finding) -> bool:
    """Report whether ``finding`` is a non-failing size notice rather than a breach."""
    return finding.key.startswith(HEADROOM_PREFIX)


def headroom(
    key: str,
    display: object,
    line_count: int,
    limit: int,
    ceiling: str,
    repo_path: object | None = None,
) -> list[Finding]:
    """Return a notice once a measured size has consumed most of ``limit``.

    A size ceiling is otherwise invisible until it blocks, and it then blocks
    whoever touches the file next rather than whoever consumed the headroom. The
    notice reports and never fails: breaches remain the sole business of the
    ordinary finding keys the baseline ratchets.

    ``display`` is what the reader sees, which for ``src`` sources is relative to
    ``src``. ``repo_path`` is the repository-relative path the same measurement
    covers, and it defaults to ``display``; the reporter needs it to decide
    whether the measured file belongs to the change in hand.
    """
    if line_count > limit or line_count * 100 < limit * policy.HEADROOM_PERCENT:
        return []
    return [Finding(
        f"{HEADROOM_PREFIX}{key}",
        f"{display}: {line_count} lines approaches the {limit}-line {ceiling} "
        f"({limit - line_count} line(s) of headroom)",
        line_count,
        limit,
        Path(str(display if repo_path is None else repo_path)).as_posix(),
        ceiling,
    )]
