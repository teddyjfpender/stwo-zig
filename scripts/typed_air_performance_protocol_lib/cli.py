"""Command-line adapter for the typed-AIR performance protocol validator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .contract import DEFAULT_PROTOCOL, REPOSITORY_ROOT
from .validation import ProtocolError, validate_protocol


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the repository's typed-AIR M5--M9 performance protocol."
    )
    parser.add_argument(
        "protocol",
        nargs="?",
        type=Path,
        default=DEFAULT_PROTOCOL,
        help="repository-owned protocol path (defaults to the canonical v1 file)",
    )
    args = parser.parse_args(argv)
    path = args.protocol if args.protocol.is_absolute() else Path.cwd() / args.protocol
    try:
        result = validate_protocol(REPOSITORY_ROOT, path)
    except (OSError, ProtocolError) as error:
        print(f"typed-air performance protocol: FAIL: {error}", file=sys.stderr)
        return 1
    print(result.render())
    return 0
