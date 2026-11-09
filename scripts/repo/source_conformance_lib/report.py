"""Render size notices as a short report instead of a wall of warnings.

Two rules keep the signal usable:

* One measurement produces one line. Several ceilings can cover the same file at
  the same measured size -- a deep evidence controller is also manual source --
  and repeating the identical measurement once per ceiling is noise, so the
  ceilings are named together on a single line.
* Only files the change in hand touches are listed. The remainder is one summary
  line naming the flag that prints them all, because a warning about a file
  nobody is editing serves neither the reader nor the file.

Reporting is all this module does. Breaches keep their own finding keys, their
own messages, and their own exit codes; nothing here can turn a notice into a
failure or a failure into a notice.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

from . import policy
from .change_scope import ChangeScope
from .model import Finding


SHOW_ALL_FLAG = "--show-headroom"


@dataclass(frozen=True, order=True)
class SizeNotice:
    """One measured size, with every ceiling that measurement approaches."""

    remaining: int
    path: str
    line_count: int
    message: str


def _ceiling_phrase(notice: Finding) -> str:
    limit = notice.limit or 0
    line_count = notice.line_count or 0
    return (
        f"the {limit}-line {notice.ceiling} "
        f"({limit - line_count} line(s) of headroom)"
    )


def merge(notices: list[Finding]) -> list[SizeNotice]:
    """Collapse notices sharing a file and a measured size into one line each."""
    groups: dict[tuple[str, int], list[Finding]] = {}
    for notice in notices:
        if notice.path is None or notice.limit is None or notice.line_count is None:
            continue
        groups.setdefault((notice.path, notice.line_count), []).append(notice)

    merged: list[SizeNotice] = []
    for (path, line_count), group in groups.items():
        ordered = sorted(group, key=lambda item: ((item.limit or 0) - line_count, item.key))
        tightest = (ordered[0].limit or 0) - line_count
        phrases = " and ".join(_ceiling_phrase(item) for item in ordered)
        merged.append(SizeNotice(
            tightest,
            path,
            line_count,
            f"{path}: {line_count} lines approaches {phrases}",
        ))
    return sorted(merged)


def report(
    notices: list[Finding],
    scope: ChangeScope,
    show_all: bool = False,
    stream: TextIO | None = None,
) -> None:
    """Warn about sizes nearing a ceiling in the change, tightest first."""
    stream = sys.stderr if stream is None else stream
    merged = merge(notices)
    if not merged:
        return

    if show_all:
        listed, summarised = merged, []
    elif scope.known:
        listed = [notice for notice in merged if scope.covers(notice.path)]
        summarised = [notice for notice in merged if not scope.covers(notice.path)]
    else:
        listed, summarised = [], merged

    for notice in listed:
        print(f"warning: {notice.message}", file=stream)
    if not summarised:
        return
    share = 100 - policy.HEADROOM_PERCENT
    prefix = (
        f"{len(summarised)} unchanged file(s)"
        if scope.known
        else f"change scope unavailable ({scope.unavailable}); {len(summarised)} file(s)"
    )
    print(
        f"note: {prefix} are within {share}% of a size ceiling; "
        f"rerun with {SHOW_ALL_FLAG} to list them",
        file=stream,
    )
