"""Demotion policy for the CP-11 boundaries the legacy oracle cannot arbitrate.

Stark-V, pinned in ``conformance/upstream.md``, remains the reference for the
shared transcript prefix and for legacy layout lineage: protocol and opcode
identity, witness column order, relation order.  It is no longer the correctness
oracle for opcode AIR constraints.  It admits the under-constraints this branch
closed -- a source register access that emits a value it did not consume (which
also leaves every witness derived from that value, including the ``LB``/``LH``
and ``SRL``/``SRA`` sign witnesses, a free prover choice), free unmarked
``SB``/``SH`` bytes, a second ``AUIPC`` immediate decomposition offset by
``p + 2``, and an unbounded ``composeU32(rs1)`` in ``JALR``.
``conformance/divergence-log.md`` is the authoritative disclosure.  An oracle
that accepts those cannot arbitrate AIR soundness, so the boundaries whose
comparison *is* an AIR comparison cannot be required to agree with it.

Demotion is not a waiver.  Telling an intended divergence apart from a new
regression is the whole purpose of this module:

* A demoted boundary must publish ``divergence_paths``: every structural path at
  which the two dumps differ, enumerated in full instead of stopping at the
  first difference.  The canonical digest of that set is the boundary's
  *divergence shape*.
* Only shapes listed in ``AUTHORIZED_SHAPES`` are accepted.  A regression at any
  path outside the intended blast radius enlarges the set, changes the digest,
  and fails the gate exactly as a boundary failure did before the demotion.
* Re-authorising a shape is a deliberate edit here, reviewed together with the
  matching ``conformance/divergence-log.md`` row.  ``AUTHORIZED_SHAPES`` is
  empty on purpose: no shape has been recorded from a CP-11 run since the
  soundness fixes landed, so the gate fails closed with a named remediation
  rather than trusting an unpinned difference.
* The status is not portable.  ``SUPERSEDED_BOUNDARIES`` is closed, and
  ``contract.receipt_errors`` rejects the status on every other boundary, so a
  parity boundary cannot launder a real failure through it.
* Lineage is still gated.  A demoted boundary must attest that the layout
  lineage Stark-V is still authoritative for was compared and agreed, so the
  demotion covers constraint and lookup content only -- never column identity,
  column order, family identity, or relation order.

Ownership: every value here is borrowed read-only by ``contract`` and by the
release-gate tests.  Nothing in this module reads the filesystem or a receipt.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


LEDGER_LANE = "RISC-V"
LEDGER_BOUNDARY = "Opcode AIR constraint and lookup layout"
LEDGER_ROW = (LEDGER_LANE, LEDGER_BOUNDARY)
LEDGER_REFERENCE = f"{LEDGER_LANE} / {LEDGER_BOUNDARY}"

# The producer spells this status literally; ``riscv_release_oracle_lib`` may not
# import this package, so the two spellings are bound by
# ``scripts/tests/test_riscv_release_gate.py`` instead of by a shared constant.
SUPERSEDED_STATUS = "superseded_by_soundness_divergence"

# Boundary -> why the pinned legacy oracle can no longer arbitrate it.  Closed
# set: no other boundary may report ``SUPERSEDED_STATUS``.
SUPERSEDED_BOUNDARIES: dict[str, str] = {
    "per_family_witness_rows": (
        "Zig binds rs1/rs2 read-only accesses and preserves every unmarked SB/SH "
        "destination byte, so witness cells the pinned AIR leaves free are now "
        "determined; row content cannot match a dump produced by the unsound AIR."
    ),
    "relation_tuples": (
        "JALR adds an rs1 middle-byte range_check_8_8 request (12 -> 13 entries, "
        "6 -> 7 batches) and AUIPC pins imm_limbs[0] == 0, so the activated "
        "lookup tuple streams differ from the pinned oracle by construction."
    ),
    "relation_sums": (
        "The added JALR lookup request and the injective AUIPC decomposition move "
        "per-domain cumulative sums; both sides must still balance to zero "
        "independently, which the sum parser continues to enforce."
    ),
}

# The closed set of soundness fixes that authorise a divergence at all.  Used in
# the remediation text so a reviewer re-pinning a shape must attribute it.
AIR_SOUNDNESS_SITES: tuple[str, ...] = (
    "read_only_access_binding",
    "store_unmarked_byte_preservation",
    "auipc_immediate_injectivity",
    "jalr_operand_range_check",
    "jalr_interaction_geometry",
)

# Divergence shapes accepted for each demoted boundary, as ``shape_digest``
# values.  Empty until a CP-11 run over the post-fix candidate records them.
AUTHORIZED_SHAPES: dict[str, frozenset[str]] = {
    "per_family_witness_rows": frozenset(),
    "relation_tuples": frozenset(),
    "relation_sums": frozenset(),
}


def shape_digest(paths: Any) -> str:
    """Canonical digest of a complete divergence-path set.

    Order- and duplicate-insensitive: the shape is the *set* of paths, so a
    producer cannot change the digest by reordering its report.
    """
    return hashlib.sha256(
        json.dumps(sorted(set(paths)), separators=(",", ":")).encode()
    ).hexdigest()


def _path_set(value: Any, label: str) -> tuple[list[str], tuple[str, ...]]:
    if not isinstance(value, list) or not value:
        return ([f"{label} enumerates no divergence path"], ())
    if any(not isinstance(path, str) or not path.startswith("/") for path in value):
        return ([f"{label} contains a non-structural divergence path"], ())
    if value != sorted(set(value)):
        return ([f"{label} divergence paths are unsorted or duplicated"], ())
    return ([], tuple(value))


def boundary_errors(name: str, boundary: dict[str, Any]) -> tuple[list[str], tuple[str, ...]]:
    """Validate a demoted boundary's divergence declaration.

    Returns the errors and the declared path set; the caller reuses the set to
    bound every per-case declaration, so the boundary declaration is the single
    authority for what this boundary is allowed to differ in.
    """
    label = f"boundary {name}"
    if name not in SUPERSEDED_BOUNDARIES:
        return (
            [f"{label} claims supersession outside the demoted AIR-comparison set"],
            (),
        )
    errors: list[str] = []
    if boundary.get("superseded_by") != LEDGER_REFERENCE:
        errors.append(f"{label} does not name the {LEDGER_REFERENCE} divergence row")
    lineage = boundary.get("lineage")
    if not isinstance(lineage, dict) or lineage.get("agree") is not True:
        errors.append(f"{label} does not attest legacy layout-lineage agreement")
    elif not isinstance(lineage.get("comparison"), str) or not lineage["comparison"].strip():
        errors.append(f"{label} does not name the lineage comparison it ran")
    path_errors, paths = _path_set(boundary.get("divergence_paths"), label)
    errors.extend(path_errors)
    if paths:
        digest = shape_digest(paths)
        if boundary.get("divergence_shape_sha256") != digest:
            errors.append(f"{label} divergence shape digest does not bind its paths")
        elif digest not in AUTHORIZED_SHAPES.get(name, frozenset()):
            errors.append(
                f"{label} reports unauthorized divergence shape {digest}; if the "
                "difference is confined to the recorded soundness sites ("
                + ", ".join(AIR_SOUNDNESS_SITES)
                + f") record it in AUTHORIZED_SHAPES[{name!r}] of "
                "scripts/riscv_release_gate_lib/air_divergence.py together with the "
                f"{LEDGER_REFERENCE} divergence-log row"
            )
    return (errors, paths)


def case_errors(key: str, case: dict[str, Any], declared: tuple[str, ...]) -> list[str]:
    """Bound one demoted case to its boundary's declared divergence shape."""
    label = f"boundary case {key}"
    if case.get("agree") is True:
        if "divergence_paths" in case:
            return [f"{label} attests agreement yet still declares a divergence"]
        return []
    errors: list[str] = []
    if "evidence_error" in case:
        errors.append(
            f"{label} produced no comparable evidence: {case['evidence_error']!r}"
        )
    path_errors, paths = _path_set(case.get("divergence_paths"), label)
    errors.extend(path_errors)
    errors.extend(
        f"{label} diverges at unauthorized path {path}"
        for path in paths
        if path not in declared
    )
    return errors


def status_errors(
    boundaries: dict[str, Any],
    ordered_names: tuple[str, ...],
) -> tuple[list[str], dict[str, tuple[str, ...]]]:
    """Check every boundary verdict and collect the demoted boundaries' shapes.

    ``ordered_names`` is the caller's boundary manifest, passed in because the
    receipt contract owns it and this package must not depend back on it.

    Returns the errors and, for each boundary that legitimately reports a
    divergence, the path set its declaration authorizes. A boundary that still
    passes is absent from that mapping and stays under full parity obligations,
    so demotion never weakens a boundary that in fact agrees.
    """
    errors: list[str] = []
    superseded: dict[str, tuple[str, ...]] = {}
    for name in ordered_names:
        boundary = boundaries.get(name)
        status = boundary.get("status") if isinstance(boundary, dict) else "missing"
        if status == "pass":
            continue
        if status != SUPERSEDED_STATUS:
            errors.append(f"boundary {name} is {status}")
            continue
        declaration_errors, paths = boundary_errors(name, boundary)
        errors.extend(declaration_errors)
        if not declaration_errors:
            superseded[name] = paths
    return errors, superseded


def coverage_errors(
    boundaries: dict[str, Any],
    superseded: dict[str, tuple[str, ...]],
    special_case_key: str,
) -> list[str]:
    """Bind every demoted case to its boundary's authorized divergence shape.

    The boundary declaration must equal the union of the paths its cases report.
    Requiring equality in both directions is what makes a regression visible: a
    case may not diverge outside the declaration, and a declaration may not
    pre-authorize a path no case observed, so future drift cannot hide inside a
    padded shape.
    """
    errors: list[str] = []
    for name, declared in superseded.items():
        boundary = boundaries.get(name)
        rows: list[Any] = []
        if isinstance(boundary, dict):
            cases = boundary.get("corpus")
            if isinstance(cases, list):
                rows.extend(cases)
            special = boundary.get(special_case_key)
            if isinstance(special, dict):
                rows.append(special)
        observed: set[str] = set()
        for case in rows:
            if not isinstance(case, dict):
                continue
            errors.extend(case_errors(f"{name}/{case.get('name')}", case, declared))
            paths = case.get("divergence_paths")
            if isinstance(paths, list):
                observed.update(path for path in paths if isinstance(path, str))
        if observed != set(declared):
            errors.append(
                f"boundary {name} divergence declaration is not exactly the union "
                "of the divergence paths its cases report"
            )
    return errors
