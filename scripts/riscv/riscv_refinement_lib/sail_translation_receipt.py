"""Canonical receipt construction and verification for Sail translations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .sail_translation_model import (
    NORMALIZATION_RULES,
    PARSER_VERSION,
    RECEIPT_CLAIM,
    SCHEMA_VERSION,
    SEQUENTIAL_NEXT_PC,
    SailTranslationError,
    ast_json,
    render,
)
from .sail_translation_normalization import normalize_definition
from .sail_translation_parser import parse_definition

# --------------------------------------------------------------------------
# receipt
# --------------------------------------------------------------------------


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def content_digest(value: Mapping[str, Any]) -> str:
    """Local mirror of codec.content_digest; the module stays standalone."""
    unsigned = dict(value)
    unsigned.pop("canonical_digest", None)
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def translate(name: str, text: str) -> dict:
    """Parse, normalize, and digest a single generated definition."""
    definition = parse_definition(text, expected_name=name)
    normalized = normalize_definition(definition)
    tree = ast_json(definition)
    return {
        "applied_rules": normalized["applied_rules"],
        "ast_sha256": hashlib.sha256(canonical_bytes(tree)).hexdigest(),
        "binders": [
            {"names": list(binder.names), "type": render(binder.declared_type)}
            for binder in definition.binders
        ],
        "result_type": render(definition.result_type),
        "selector_binder": normalized["selector_binder"],
        "selectors": normalized["selectors"],
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def build_receipt(definitions: Mapping[str, str]) -> dict:
    """Canonical translation receipt for the given generated definitions."""
    if not definitions:
        raise SailTranslationError(
            "a translation receipt needs at least one definition"
        )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "parser_version": PARSER_VERSION,
        "claim": RECEIPT_CLAIM,
        "normalization_rules": dict(NORMALIZATION_RULES),
        "sequential_next_pc": SEQUENTIAL_NEXT_PC,
        "definitions": {
            name: translate(name, definitions[name]) for name in sorted(definitions)
        },
    }
    payload["canonical_digest"] = content_digest(payload)
    return payload


def _difference(expected: Any, actual: Any, path: str = "$") -> str | None:
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in actual:
                return f"{path}.{key} is missing"
            if key not in expected:
                return f"{path}.{key} is unexpected"
            found = _difference(expected[key], actual[key], f"{path}.{key}")
            if found is not None:
                return found
        return None
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return f"{path} has {len(actual)} entries, expected {len(expected)}"
        for index, (left, right) in enumerate(zip(expected, actual)):
            found = _difference(left, right, f"{path}[{index}]")
            if found is not None:
                return found
        return None
    if expected != actual:
        return f"{path} is {actual!r}, expected {expected!r}"
    return None


def verify_receipt(receipt: Any, definitions: Mapping[str, str]) -> dict:
    """Re-derive the receipt from the definitions and fail closed on drift."""
    if not isinstance(receipt, dict):
        raise SailTranslationError("translation receipt must be a JSON object")
    claimed = receipt.get("canonical_digest")
    if not isinstance(claimed, str):
        raise SailTranslationError("translation receipt has no canonical digest")
    if claimed != content_digest(receipt):
        raise SailTranslationError("translation receipt digest does not cover its body")
    rederived = build_receipt(definitions)
    drift = _difference(
        {key: value for key, value in rederived.items() if key != "canonical_digest"},
        {key: value for key, value in receipt.items() if key != "canonical_digest"},
    )
    if drift is not None:
        raise SailTranslationError(f"translation receipt drifted: {drift}")
    if claimed != rederived["canonical_digest"]:
        raise SailTranslationError(
            "translation receipt digest does not match the re-derived receipt"
        )
    return rederived


def load_definitions(directory: Path, names: Iterable[str]) -> dict[str, str]:
    """Read `<name>.lean` definition slices out of one directory."""
    result: dict[str, str] = {}
    for name in names:
        path = Path(directory) / f"{name}.lean"
        try:
            result[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SailTranslationError(f"{path}: unreadable definition") from exc
    return result
