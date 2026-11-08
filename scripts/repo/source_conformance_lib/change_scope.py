"""Resolve which files the change in hand actually touches.

A size notice is only actionable for whoever is spending the headroom, so the
reporter needs the working change rather than the whole tree. The scope is the
union of every path that differs from the merge base with the integration branch
and every path git does not track yet, which is exactly the diff a review sees.

When git cannot answer the question the scope is *unavailable*, never silently
empty: the caller reports the reason on one line and summarises instead of
pretending the change touches nothing.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


#: Integration refs tried in order when locating the merge base of the change.
INTEGRATION_REFS = ("origin/main", "main")
GIT_TIMEOUT_SECONDS = 20

#: Runs a git argument vector and returns its stdout, or ``None`` if it failed.
Runner = Callable[[Sequence[str]], "str | None"]


@dataclass(frozen=True)
class ChangeScope:
    """The repository-relative POSIX paths the current change touches."""

    paths: frozenset[str]
    base: str | None = None
    unavailable: str | None = None

    @property
    def known(self) -> bool:
        return self.unavailable is None

    def covers(self, path: str | None) -> bool:
        return path is not None and path in self.paths


def run_git(argv: Sequence[str]) -> str | None:
    """Return git's stdout, or ``None`` when git is absent, slow, or unhappy."""
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def _lines(output: str) -> set[str]:
    return {stripped for line in output.splitlines() if (stripped := line.strip())}


def resolve(repo: Path, runner: Runner = run_git) -> ChangeScope:
    """Return the change scope for ``repo``, or an explained unavailable scope."""

    def git(*arguments: str) -> str | None:
        return runner(("git", "-C", str(repo), *arguments))

    toplevel = git("rev-parse", "--show-toplevel")
    if toplevel is None or not toplevel.strip():
        return ChangeScope(frozenset(), unavailable="no readable git work tree")
    if Path(toplevel.strip()).resolve() != repo.resolve():
        # git reports paths from its own root, so a scope resolved anywhere else
        # would silently never match the paths the scanners measured.
        return ChangeScope(frozenset(), unavailable="scanned tree is not a git work tree root")

    base: str | None = None
    for ref in INTEGRATION_REFS:
        output = git("merge-base", "HEAD", ref)
        if output is not None and output.strip():
            base = output.strip()
            break
    if base is None:
        return ChangeScope(
            frozenset(),
            unavailable=f"no merge base with {' or '.join(INTEGRATION_REFS)}",
        )

    changed = git("diff", "--name-only", base, "--")
    if changed is None:
        return ChangeScope(frozenset(), base, f"git diff against {base[:12]} failed")
    untracked = git("ls-files", "--others", "--exclude-standard")
    if untracked is None:
        return ChangeScope(frozenset(), base, "git could not list untracked files")
    return ChangeScope(frozenset(_lines(changed) | _lines(untracked)), base)
