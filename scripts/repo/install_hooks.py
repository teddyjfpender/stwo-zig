#!/usr/bin/env python3
"""Configure this checkout to use the repository's versioned Git hooks."""

from __future__ import annotations

import argparse
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOK_NAMES = ("pre-commit", "pre-push")


def install(repo: Path) -> None:
    repo = repo.resolve()
    hooks = repo / ".githooks"
    for name in HOOK_NAMES:
        hook = hooks / name
        if not hook.is_file():
            raise RuntimeError(f"missing versioned hook: {hook}")
        if not hook.stat().st_mode & stat.S_IXUSR:
            raise RuntimeError(f"hook is not executable: {hook}")

    subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "config", "--local", "core.hooksPath", ".githooks"],
        cwd=repo,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        install(args.repo)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print("configured core.hooksPath=.githooks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
