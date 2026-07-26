"""Producer side of the demoted CP-11 AIR-comparison boundaries.

Stark-V is no longer the correctness oracle for opcode AIR constraints, so
``per_family_witness_rows``, ``relation_tuples`` and ``relation_sums`` may
legitimately disagree with it.  A disagreement is only admissible if it is
completely described, so this module produces the two things the release
contract requires of a demoted boundary:

* the **divergence shape** -- every structural path at which the two dumps
  differ.  ``relations._first_difference`` stops at the first difference, which
  is what a parity failure needs; a pinned divergence needs the whole set,
  because the digest of the set is what a regression has to change.
* the **lineage verdict** -- Stark-V is still authoritative for family identity,
  column identity and column order, so a demoted witness-row boundary compares
  that projection separately and must still agree on it.

``scripts/riscv_release_gate_lib/air_divergence.py`` owns the policy: which
boundaries may be demoted, which shapes are authorized, and the reason for each.
This module observes and reports; it never decides that a difference is
acceptable.  The two packages cannot import each other (see
``scripts/source_conformance_lib/policy.py``), so the shared status and ledger
spellings below are bound to the policy module by
``scripts/tests/test_riscv_release_gate.py``.

Ownership: pure functions over borrowed strings and parsed dumps.  Nothing here
runs a subprocess, reads the filesystem, or mutates a receipt.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


DIVERGENCE_STATUS = "superseded_by_soundness_divergence"
LEDGER_REFERENCE = "RISC-V / Opcode AIR constraint and lookup layout"


def shape_digest(paths: Any) -> str:
    """Canonical digest of a complete divergence-path set."""
    return hashlib.sha256(
        json.dumps(sorted(set(paths)), separators=(",", ":")).encode()
    ).hexdigest()


def divergence_paths(rust: Any, zig: Any) -> list[str]:
    """Enumerate every structural path at which two parsed dumps differ.

    Keys present on only one side are reported at that key rather than descended
    into, so a whole missing component yields one path instead of a subtree.
    """
    found: list[str] = []
    _walk(rust, zig, "", found)
    return sorted(set(found))


def _walk(rust: Any, zig: Any, path: str, found: list[str]) -> None:
    if isinstance(rust, dict) and isinstance(zig, dict):
        for key in sorted(set(rust) | set(zig), key=str):
            child = f"{path}/{key}"
            if key not in rust or key not in zig:
                found.append(child)
                continue
            _walk(rust[key], zig[key], child, found)
        return
    if rust != zig:
        found.append(path or "/")


def witness_row_sections(dump: str) -> dict[str, dict[str, Any]]:
    """Split a witness-row dump into per-family layout and row sections.

    The dump is a flat line sequence: a ``family=`` header, its ``names=`` line,
    then that family's ``row=`` lines.  Separating layout from rows is what lets
    a demoted boundary keep gating column lineage while its row content differs.
    """
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for line in dump.splitlines():
        if line.startswith("family="):
            fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
            family = fields.get("family")
            if family is None or family in sections:
                raise ValueError(
                    f"witness dump has a missing or duplicate family: {family!r}"
                )
            current = {"layout": [line], "rows": []}
            sections[family] = current
            continue
        if current is None:
            raise ValueError("witness dump has content before its first family header")
        current["layout" if line.startswith("names=") else "rows"].append(line)
    if not sections:
        raise ValueError("witness dump contains no family layouts")
    return {
        name: {"layout": tuple(section["layout"]), "rows": tuple(section["rows"])}
        for name, section in sections.items()
    }


def witness_row_divergence(rust: str, zig: str) -> tuple[list[str], bool]:
    """Return the divergence paths of two witness-row dumps and the lineage verdict.

    Lineage covers the family set and each family's column count and column
    names.  A difference there is *not* covered by the AIR-soundness demotion --
    the closed constraints add no column -- so it clears the lineage verdict and
    the release contract then rejects the boundary.
    """
    rust_sections = witness_row_sections(rust)
    zig_sections = witness_row_sections(zig)
    paths: list[str] = []
    lineage_agree = set(rust_sections) == set(zig_sections)
    for family in sorted(set(rust_sections) | set(zig_sections)):
        if family not in rust_sections or family not in zig_sections:
            paths.append(f"/families/{family}")
            continue
        if rust_sections[family]["layout"] != zig_sections[family]["layout"]:
            paths.append(f"/{family}/columns")
            lineage_agree = False
        if rust_sections[family]["rows"] != zig_sections[family]["rows"]:
            paths.append(f"/{family}/rows")
    return sorted(set(paths)), lineage_agree


def declaration(paths: Any, lineage: dict[str, Any]) -> dict[str, Any]:
    """Fields a demoted boundary publishes in place of a ``pass`` status."""
    ordered = sorted(set(paths))
    return {
        "status": DIVERGENCE_STATUS,
        "superseded_by": LEDGER_REFERENCE,
        "divergence_paths": ordered,
        "divergence_shape_sha256": shape_digest(ordered),
        "lineage": lineage,
    }
