"""Shared immutable policy constants for refinement receipts and audits."""

from __future__ import annotations

if __package__:
    from . import riscv_opcode_coverage, riscv_team_a, riscv_team_b
else:
    import riscv_opcode_coverage
    import riscv_team_a
    import riscv_team_b

APPROVED_LEAN_AXIOMS = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)
RECEIPT_SCHEMA_VERSION = 2
RECEIPT_TIER = "issue-136-a5-graded-integration"
RECEIPT_CLAIM_BOUNDARY = {
    "team_a_production_air": {
        "proved": 24,
        "total": 24,
    },
    "graded_opcode_index": {
        "covered": 46,
        "total": 46,
    },
    "team_a_generated_sail_input_bindings": {
        "bound": 24,
        "total": 24,
    },
    "normalized_retirements": {
        "proved": 2,
        "total": 46,
    },
    "publication_level": {
        "proved": 0,
        "total": 46,
    },
    "full_generated_sail_step": False,
    "proof_system_soundness": False,
    "whole_frontend_verified": False,
    "external_signoffs": {
        "status": "not-established",
        "shared_interface_signoff": {
            "status": "not-established",
            "required_signoffs": 5,
            "required_roles": [
                "team-a-integration-dri",
                "team-b-sail-profile-dri",
                "lh-representative",
                "div-representative",
                "independent-formal-reviewer",
            ],
            "established": [],
        },
        "team_a_family_non_author_signoffs": {
            "status": "not-established",
            "required_per_family": 3,
            "required_roles": [
                "air-tuple-reviewer",
                "team-b-sail-profile-reviewer",
                "lean-soundness-non-vacuity-reviewer",
            ],
            "families": list(riscv_team_a.TEAM_A_FAMILIES),
            "established": {
                family: []
                for family in riscv_team_a.TEAM_A_FAMILIES
            },
        },
        "joint_issue_137_gate": {
            "status": "not-established",
            "issue": 137,
            "established": False,
        },
    },
}
TEAM_A_INDEX_RELATIVE = riscv_team_a.CERTIFICATE_INDEX.relative_to(
    riscv_team_a.REPOSITORY_ROOT
)
TEAM_B_INDEX_RELATIVE = riscv_team_b.CERTIFICATE_INDEX.relative_to(
    riscv_team_b.REPOSITORY_ROOT
)
OPCODE_INDEX_RELATIVE = riscv_opcode_coverage.INDEX_PATH.relative_to(
    riscv_opcode_coverage.REPOSITORY_ROOT
)
MUTATION_THEOREMS = {
    "lui-free-low-limb": (
        "RiscvRefinement.Air.Bridge.Mutations."
        "luiLowLimb_strictly_weaker"
    ),
    "addi-free-high-carry": (
        "RiscvRefinement.Air.Bridge.Mutations."
        "addiCarry_strictly_weaker"
    ),
    "addi-immediate-range-request": (
        "RiscvRefinement.Air.Bridge.Mutations."
        "immediateRange_strictly_weaker"
    ),
    "addi-selector-relabel-xori": (
        "RiscvRefinement.Air.Bridge.Mutations."
        "selectorRelabel_strictly_weaker"
    ),
    "addi-lookup-event-reorder": (
        "RiscvRefinement.Air.Bridge.Mutations."
        "reordered_strictly_weaker"
    ),
}
NEGATIVE_CONTROLS = tuple(MUTATION_THEOREMS)
LIVE_SAIL_OPTIONS = (
    "sail_riscv_dir",
    "sail_bin",
    "sail_generated_file",
)
AUDIT_COMMAND = ("lake", "env", "lean", "RiscvRefinement/AxiomAudit.lean")
AUDITED_THEOREMS_REFRESH = (
    "refresh the pin with "
    "'python3 scripts/riscv_refinement.py audited-theorems --write' "
    "and review the diff"
)
