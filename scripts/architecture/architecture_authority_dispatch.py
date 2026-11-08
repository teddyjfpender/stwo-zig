#!/usr/bin/env python3
"""Execute an allowlisted authority Python policy against an explicit candidate root."""

from __future__ import annotations

import argparse
import os
import runpy
import sys
from pathlib import Path


AUTHORITY_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PREFIX = "scripts/"


class DispatchError(ValueError):
    pass


def resolve_script(relative: str) -> Path:
    if not relative.startswith(ALLOWED_PREFIX) or not relative.endswith(".py"):
        raise DispatchError("authority policy path is not an allowlisted Python script")
    script = (AUTHORITY_ROOT / relative).resolve()
    scripts_root = (AUTHORITY_ROOT / "scripts").resolve()
    if not script.is_relative_to(scripts_root) or not script.is_file() or script.is_symlink():
        raise DispatchError("authority policy path escapes the authenticated scripts tree")
    return script


def execute(
    *, candidate_root: Path, relative_script: str, arguments: list[str], smoke: bool,
) -> None:
    candidate_root = candidate_root.resolve(strict=True)
    script = resolve_script(relative_script)
    os.environ["STWO_ZIG_EXECUTION_ROOT"] = str(candidate_root)
    for entry in (str(AUTHORITY_ROOT), str(AUTHORITY_ROOT / "scripts")):
        while entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)
    sys.argv = [str(script), *arguments]
    runpy.run_path(str(script), run_name="_authority_import_smoke_" if smoke else "__main__")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--smoke-import", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        execute(
            candidate_root=args.candidate_root,
            relative_script=args.script,
            arguments=arguments,
            smoke=args.smoke_import,
        )
    except (OSError, DispatchError) as error:
        print(f"architecture authority dispatch: FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
