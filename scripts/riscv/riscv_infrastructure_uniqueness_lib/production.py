"""Fail-closed binding from reviewed theorems to shipped Zig sources."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .contracts import INV2, MERKLE_DEPTH, P
from .production_bindings import (
    MERKLE_NODE_PATH,
    M31_PATH,
    PRODUCTION_PATHS,
    SOURCE_BINDINGS,
    SPARSE_MERKLE_PATH,
    STATE_CHAIN_PATH,
)


@dataclasses.dataclass(frozen=True)
class ProductionContract:
    sources: tuple[str, ...]
    bindings_checked: int
    source_modulus: int
    source_inverse_two: int
    source_merkle_depth: int
    source_clock_low_bits: int
    source_clock_high_bits: int
    merkle_admission_rule: str
    memory_coefficient_rule: str
    state_recurrence: str
    opcode_gap_table: str
    clock_predecessor_range: str
    program_relation: str
    memory_relation: str
    merkle_relation: str
    clock_relation: str


def compact(source: str) -> str:
    return " ".join(source.split())


def _decimal_constant(source: str, name: str) -> int:
    matches = re.findall(
        rf"(?:pub )?const {re.escape(name)}(?:: [^=]+)?\s*=\s*([0-9]+)\s*;",
        source,
    )
    if len(matches) != 1:
        raise AssertionError(
            f"could not uniquely locate production constant {name}: "
            f"found {len(matches)}"
        )
    return int(matches[0])


def check_production_contract(
    repo_root: Path,
    *,
    merkle_contract_checker: Callable[[Path], Any],
    clock_contract_checker: Callable[[Path], Any],
) -> ProductionContract:
    """Fail closed unless every machine-checked premise is still shipped."""
    sources = {
        path: (repo_root / path).read_text(encoding="utf-8")
        for path in PRODUCTION_PATHS
    }
    compacted = {path: compact(source) for path, source in sources.items()}
    modulus_matches = re.findall(
        r"pub const Modulus:\s*u32\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;",
        sources[M31_PATH],
    )
    if len(modulus_matches) != 1:
        raise AssertionError(
            "could not uniquely locate the production M31 modulus: "
            f"found {len(modulus_matches)}"
        )
    source_modulus = int(modulus_matches[0], 0)
    inverse_matches = re.findall(
        r"const INV2: QM31 = QM31\.fromBase\(M31\.fromU64\(([0-9]+)\)\);",
        compacted[MERKLE_NODE_PATH],
    )
    if len(inverse_matches) != 1:
        raise AssertionError(
            "could not uniquely locate the production Merkle INV2: "
            f"found {len(inverse_matches)}"
        )
    source_inverse_two = int(inverse_matches[0])
    source_merkle_depth = _decimal_constant(
        sources[SPARSE_MERKLE_PATH], "LEAF_DEPTH"
    )
    source_clock_low_bits = _decimal_constant(
        sources[STATE_CHAIN_PATH], "CLOCK_PREV_LOW_BITS"
    )
    source_clock_high_bits = _decimal_constant(
        sources[STATE_CHAIN_PATH], "CLOCK_PREV_HIGH_BITS"
    )
    if source_modulus != P:
        raise AssertionError("infrastructure checker modulus drifted from production")
    if source_inverse_two != INV2 or 2 * source_inverse_two % P != 1:
        raise AssertionError("infrastructure checker INV2 drifted from production")
    if source_merkle_depth != MERKLE_DEPTH:
        raise AssertionError("infrastructure checker Merkle depth drifted")
    if (source_clock_low_bits, source_clock_high_bits) != (20, 6):
        raise AssertionError("infrastructure checker clock radix drifted")
    max_clock_fragment = "pub const MAX_CLOCK_DIFF: u32 = (1 << 20) - 1;"
    if max_clock_fragment not in compacted[STATE_CHAIN_PATH]:
        raise AssertionError("production contract changed: maximum clock gap")

    for label, path, fragment in SOURCE_BINDINGS:
        occurrences = compacted[path].count(fragment)
        if occurrences != 1:
            raise AssertionError(
                f"production contract changed: {label} "
                f"(expected exactly once, found {occurrences})"
            )
    merkle_contract = merkle_contract_checker(repo_root)
    clock_contract = clock_contract_checker(repo_root)
    return ProductionContract(
        sources=tuple(str(path) for path in PRODUCTION_PATHS),
        bindings_checked=len(SOURCE_BINDINGS),
        source_modulus=source_modulus,
        source_inverse_two=source_inverse_two,
        source_merkle_depth=source_merkle_depth,
        source_clock_low_bits=source_clock_low_bits,
        source_clock_high_bits=source_clock_high_bits,
        merkle_admission_rule=merkle_contract.admission_rule,
        memory_coefficient_rule=(
            "3 * execution steps + clock-update rows + memory rows + "
            "public multiplicity < M31 modulus"
        ),
        state_recurrence=clock_contract.state_recurrence,
        opcode_gap_table=clock_contract.opcode_gap_table,
        clock_predecessor_range=clock_contract.clock_predecessor_range,
        program_relation=(
            "fixed row -> program tuple plus four same-root depth-30 leaves; "
            "bounded address limbs are unique"
        ),
        memory_relation=(
            "fixed signed boundary row -> one memory tuple plus four same-root leaves"
        ),
        merkle_relation=(
            "fixed row -> consecutive children, field-half/depth-1 parent, "
            "and one Poseidon2 call; the production all-source bound "
            "lifts exact field balance to integer coefficients"
        ),
        clock_relation=(
            "fixed predecessor tuple -> same key/value at clock + (2^20 - 1); "
            "bounded predecessor limbs are unique"
        ),
    )
