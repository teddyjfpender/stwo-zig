#!/usr/bin/env python3
"""CLI and compatibility facade for the typed-AIR performance protocol validator."""

from __future__ import annotations

if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    __import__("sys").path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

if __package__:
    from .typed_air_performance_protocol_lib import (
        DEFAULT_PROTOCOL,
        REPOSITORY_ROOT,
        ProtocolError,
        ProtocolSummary,
        decode_strict_json,
        main,
        validate_protocol,
        validate_protocol_value,
    )
else:
    from scripts.typed_air.typed_air_performance_protocol_lib import (
        DEFAULT_PROTOCOL,
        REPOSITORY_ROOT,
        ProtocolError,
        ProtocolSummary,
        decode_strict_json,
        main,
        validate_protocol,
        validate_protocol_value,
    )

__all__ = [
    "DEFAULT_PROTOCOL",
    "ProtocolError",
    "ProtocolSummary",
    "REPOSITORY_ROOT",
    "decode_strict_json",
    "main",
    "validate_protocol",
    "validate_protocol_value",
]


if __name__ == "__main__":
    raise SystemExit(main())
