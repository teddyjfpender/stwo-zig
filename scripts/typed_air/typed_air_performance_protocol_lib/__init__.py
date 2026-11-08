"""Public API for the typed-AIR M5--M9 performance protocol validator."""

from .cli import main
from .contract import DEFAULT_PROTOCOL, REPOSITORY_ROOT
from .validation import (
    ProtocolError,
    ProtocolSummary,
    decode_strict_json,
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
