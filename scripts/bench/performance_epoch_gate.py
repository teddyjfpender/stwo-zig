#!/usr/bin/env python3
"""Create and validate build-monorepo performance epoch evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import performance_epoch_gate_lib.controller as controller
except ModuleNotFoundError:
    import scripts.performance_epoch_gate_lib.controller as controller


def promotion_enabled(state_path: Path) -> bool:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return (
        isinstance(state, dict)
        and state.get("schema") == "build-architecture-performance-state-v1"
        and state.get("performance_promotion_enabled") is True
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    promotion_command = next(
        (item for item in arguments if item in {"capture-host", "validate-receipt"}),
        None,
    )
    if promotion_command is not None:
        state_path = Path(__file__).resolve().parents[1] / (
            "conformance/build-architecture-performance-state-v1.json"
        )
        try:
            enabled = promotion_enabled(state_path)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(f"performance epoch admission: NO-GO: {error}", file=sys.stderr)
            return 2
        if not enabled:
            print(
                "performance epoch admission: NO-GO: promotion is explicitly deferred",
                file=sys.stderr,
            )
            return 2

    def run_oracle(binary, artifact, timeout):
        try:
            from scripts.native_proof_matrix_lib.artifacts import run_rust_oracle
        except ModuleNotFoundError:
            from native_proof_matrix_lib.artifacts import run_rust_oracle
        return run_rust_oracle(binary, artifact, timeout)

    return controller.main(arguments, oracle_runner=run_oracle)


if __name__ == "__main__":
    raise SystemExit(main())
