#!/usr/bin/env python3
"""Emit the candidate workflow's explicit non-authoritative architecture status."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DiagnosticError(ValueError):
    pass


def _load(path: Path) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DiagnosticError(f"duplicate architecture diagnostic key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise DiagnosticError("architecture diagnostic input is not an object")
    return value


def inspect(root: Path) -> dict[str, object]:
    state = _load(root / "conformance/build-architecture-authority-state-v1.json")
    contract = _load(root / "conformance/build-architecture-external-verifier-v1.json")
    if state.get("bg15_release_authority_enabled") is not False:
        raise DiagnosticError("candidate diagnostic cannot run after authority activation")
    if contract.get("candidate_workflow") != {
        "path": ".github/workflows/ci.yml", "role": "diagnostic-only",
    }:
        raise DiagnosticError("candidate workflow role drifted")
    return {
        "schema": "build-architecture-candidate-diagnostic-v1",
        "status": "NON_AUTHORITATIVE",
        "bg15_release_authority_enabled": False,
        "authority_workflow": contract["authority_workflow"],
        "reason": state.get("reason"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = inspect(args.root.resolve())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DiagnosticError) as error:
        print(f"architecture candidate diagnostic: FAIL: {error}", file=sys.stderr)
        return 2
    print("architecture candidate diagnostic: NON_AUTHORITATIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
