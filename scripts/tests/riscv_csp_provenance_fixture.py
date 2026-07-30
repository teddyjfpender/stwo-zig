"""Shared fixtures for the CSP benchmark provenance and wiring suites.

The two suites that consume this module test different things -- one the
validators, one that ``main`` actually calls them -- over the same committed
fixture and the same published document shapes.  One definition of those shapes
keeps a drift in either suite from being papered over by the other.
"""

from __future__ import annotations

import json

from scripts import riscv_cli_admission
from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib import build_identity as csp_build_identity
from scripts.riscv_csp_benchmark_lib import contract as csp_contract


TARGET = "ecdsa_secp256k1"
HEAD = "a" * 40
FOREIGN_COMMIT = "b" * 40
# Stand-ins for the two executables: tracked, executable, and never run, because
# every subprocess boundary the harness crosses is faked in these tests.
STAND_IN_CLI = csp.ROOT / "scripts" / "ci.py"
STAND_IN_TRACE = csp.ROOT / "scripts" / "cuda_build.py"


def public_values(
    case: csp_contract.Case | csp_contract.NegativeCase,
    *,
    commit: str = HEAD,
    dirty: bool = False,
    **overrides: object,
) -> bytes:
    """Build the diagnostic dump the trace dumper publishes for one fixture."""
    payload = bytes.fromhex(case.expected_digest)
    words: list[dict[str, int]] = [{"addr": 0x2000, "value": len(payload)}]
    for index in range(0, len(payload), 4):
        chunk = payload[index:index + 4]
        words.append(
            {"addr": 0x2004 + index, "value": int.from_bytes(chunk, "little")}
        )
    document: dict[str, object] = {
        "schema": csp_build_identity.TRACE_SCHEMA,
        "derivation": csp_build_identity.TRACE_DERIVATION,
        "provenance": {
            "implementation_commit": commit,
            "implementation_dirty": dirty,
            "oracle_commit": "c" * 40,
            "witness_layout_sha256": "d" * 64,
        },
        "source": {
            "elf_sha256": getattr(case, "guest_sha256", "e" * 64),
            "input_sha256": case.input_sha256,
        },
        "public_data": {
            "clock": case.expected_cycles,
            "io_entries": {
                "output_len": len(payload),
                "output_len_addr": 0x2000,
                "output_data_addr": 0x2004,
                "output_words": words,
            },
        },
    }
    document.update(overrides)
    return json.dumps(document).encode()


def admission_resolve(cli, *, cwd=None, timeout_seconds=30):
    """Stand in for the CLI admission probe without a built executable."""
    return riscv_cli_admission.Admission("promoted", "release_gated", False)
