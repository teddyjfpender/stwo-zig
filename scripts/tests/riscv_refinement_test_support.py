"""Regression tests for the generated RISC-V refinement pilot."""

from __future__ import annotations

import copy
import json
import re
import shutil
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from scripts import riscv_refinement
from scripts.riscv_refinement_lib import (
    air,
    air_program,
    air_program_contract,
    audited_inventory,
    codec,
    negative,
    render,
    sail,
    sail_lean_bridge,
)
from scripts.riscv_refinement_lib.model import Paths, RefinementError

ROOT = Path(__file__).resolve().parents[2]
GENERATED_AIR = ROOT / "formal" / "riscv-refinement" / "generated" / "air"
MANIFEST = Path("generated-manifest.json")


def carried_fixture(root: Path) -> Paths:
    """Copy exactly the inputs a reused-evidence run is allowed to read."""
    paths = Paths(root)
    for relative in sail.CARRIED_INPUTS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    for relative in (
        MANIFEST,
        sail.COMMITTED_CONFIGURATION,
        sail.COMMITTED_CAPSULE,
        sail.COMMITTED_MONAD_BRIDGE_RECEIPT,
        sail.COMMITTED_TRANSLATION_RECEIPT,
        *sail.COMMITTED_DEFINITIONS.values(),
    ):
        destination = paths.formal / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Paths(ROOT).formal / relative, destination)
    for relative in (
        sail_lean_bridge.BRIDGE_SOURCE,
        sail_lean_bridge.SUPPORT_PATCH,
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return paths


def pinned_literal(text: str) -> tuple[str, ...]:
    """Read back an AUDITED_THEOREMS block exactly as Python would."""
    return audited_inventory.parse_source(text)


def audit_transcript(theorems: tuple[str, ...]) -> str:
    return "".join(
        f"REFINEMENT_THEOREM {theorem}\n"
        f"REFINEMENT_AXIOM {theorem} propext\n"
        for theorem in theorems
    )


def air_ir_v2_fixture() -> dict[str, object]:
    fixed_tables = [
        {
            "id": table_id,
            "domain": table_id,
            "arity": arity,
            "log_size": log_size,
            "schema_sha256": air_program.table_schema_digest(
                table_id,
                table_id,
                arity,
                log_size,
            ),
        }
        for table_id, arity, log_size in air_program.FIXED_TABLES
    ]
    files = [
        {
            "path": path,
            "sha256": "1" * 64,
        }
        for path in air_program.LUI_SOURCE_PATHS
    ]
    payload: dict[str, object] = {
        "schema_version": air_program.AIR_IR_SCHEMA_VERSION,
        "kind": air_program.AIR_IR_KIND,
        "field": {
            "name": "M31",
            "modulus": air_program.M31_MODULUS,
        },
        "family": "lui",
        "columns": [
            {
                "index": 0,
                "name": "enabler",
                "role": "input",
                "type": "m31",
                "width": 1,
            }
        ],
        "nodes": [
            {"op": "col", "column": 0},
            {"op": "const", "value": 1},
            {"op": "add", "args": [0, 1]},
            {"op": "sub", "args": [2, 1]},
            {"op": "mul", "args": [3, 1]},
            {"op": "neg", "args": [0]},
            {"op": "const", "value": 35},
            {"op": "const", "value": 0},
        ],
        "active_row": 0,
        "opcode_selector": {
            "manifest_id": 35,
            "mnemonic": "lui",
            "expression": 6,
        },
        "fixed_tables": fixed_tables,
        "events": [
            *[
                {"ordinal": ordinal, "kind": "constraint", "root": 4}
                for ordinal in range(9)
            ],
            {
                "ordinal": 9,
                "kind": "lookup",
                "role": "request",
                "domain": "program_access",
                "numerator": 5,
                "tuple": [0, 6, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 10,
                "kind": "lookup",
                "role": "consume",
                "domain": "registers_state",
                "numerator": 5,
                "tuple": [0, 1],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 11,
                "kind": "lookup",
                "role": "emit",
                "domain": "registers_state",
                "numerator": 0,
                "tuple": [2, 1],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 12,
                "kind": "lookup",
                "role": "request",
                "domain": "range_check_8_8_4",
                "numerator": 5,
                "tuple": [0, 0, 0],
                "table_id": "range_check_8_8_4",
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 13,
                "kind": "lookup",
                "role": "consume",
                "domain": "memory_access",
                "numerator": 5,
                "tuple": [0, 1, 7, 7, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
            {
                "ordinal": 14,
                "kind": "lookup",
                "role": "emit",
                "domain": "memory_access",
                "numerator": 0,
                "tuple": [0, 1, 2, 7, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
            {
                "ordinal": 15,
                "kind": "lookup",
                "role": "request",
                "domain": "range_check_20",
                "numerator": 5,
                "tuple": [0],
                "table_id": "range_check_20",
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
        ],
        "projection": {
            "program_event": 9,
            "state_events": [10, 11],
            "source_events": [],
            "destination_events": [13, 14],
            "next_pc": 2,
        },
        "source_identity": {
            "builder": "src/frontends/riscv/air/constraint_program.zig",
            "files": files,
            "source_closure_sha256": codec.sha256_bytes(
                codec.canonical_bytes(files)
            ),
        },
        "content_digest": "",
    }
    payload["content_digest"] = air_program.content_digest(payload)
    return payload


def resign_air_ir_v2(payload: dict[str, object]) -> None:
    payload["content_digest"] = air_program.content_digest(payload)


def receipt_mapping_fixture() -> tuple[
    list[dict[str, object]],
    dict[str, dict[str, object]],
]:
    """Build exact aggregate/source certificate projections for receipt tests."""
    team_a = riscv_refinement.riscv_team_a
    team_b = riscv_refinement.riscv_team_b
    team_a_families = set(team_a.TEAM_A_FAMILIES)
    mappings: list[dict[str, object]] = []
    team_a_sources: list[dict[str, object]] = []
    team_b_sources: list[dict[str, object]] = []
    for manifest_id, mnemonic, family in air_program_contract.OPCODES:
        is_team_a = family in team_a_families
        common = {
            "family": family,
            "manifest_id": manifest_id,
            "mnemonic": mnemonic,
            "mutation": f"{mnemonic}-mutation",
            "mutation_theorem": f"RiscvRefinement.{mnemonic}.mutation",
            "non_vacuity_theorem":
                f"RiscvRefinement.{mnemonic}.exists",
            "refinement_theorem":
                f"RiscvRefinement.{mnemonic}.refines",
            "tuple_theorem": f"RiscvRefinement.{mnemonic}.tuple",
        }
        if is_team_a:
            sail_binding = (
                "generated-retirement"
                if mnemonic in team_a.GENERATED_SAIL_RETIREMENT_THEOREMS
                else "generated-clause-input"
            )
            sail_theorem = (
                team_a.GENERATED_SAIL_RETIREMENT_THEOREMS[mnemonic]
                if sail_binding == "generated-retirement"
                else team_a.GENERATED_SAIL_INPUT_THEOREMS[mnemonic]
            )
            source = {
                **common,
                "air_digest": "a" * 64,
                "axioms": [],
                "proof_target": f"RiscvRefinement.{mnemonic}.Proof",
                "proof_time_ms": manifest_id + 1,
                "sail_binding": sail_binding,
                "sail_digest": "b" * 64,
                "sail_receipt":
                    "formal/riscv-refinement/generated/sail/"
                    "generated-monad-bridge-receipt-v1.json",
                "sail_theorem": sail_theorem,
                "selector_theorem":
                    f"RiscvRefinement.{mnemonic}.selector",
                "state": "air-proved",
            }
            team_a_sources.append(source)
            mapping = {
                key: value
                for key, value in source.items()
                if key != "proof_target"
            }
            mapping.update({
                "air_binding": "exact-generated-local-program",
                "team": "A",
            })
        else:
            source = {
                **common,
                "sail_binding": team_b.DEFAULT_SAIL_BINDING,
                "state": "proved",
            }
            team_b_sources.append(source)
            mapping = {
                **source,
                "air_binding": "reviewed-family-capsule",
                "air_digest": "a" * 64,
                "axioms": None,
                "proof_time_ms": None,
                "selector_theorem": None,
                "team": "B",
            }
        mappings.append(mapping)
    return mappings, {
        "team_a": {"payload": {"certificates": team_a_sources}},
        "team_b": {"payload": {"certificates": team_b_sources}},
    }
