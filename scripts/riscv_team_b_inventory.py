#!/usr/bin/env python3
"""Evidence inventory for the Team B promotion decision.

The certificate index (``formal/riscv-refinement/team-b-coverage.json``) is
promoted from ``refined`` to ``proved`` only when an opcode has a refinement
theorem, a tuple theorem, a non-vacuity witness AND a load-bearing mutation
control. Doing that audit by hand has gone wrong twice: once by citing a
vacuous control, once by promoting on a soundness hypothesis that was false.

This tool makes the audit mechanical. It scans the Lean sources and reports,
per Team B opcode, the evidence that actually exists:

1. Every ``MutationControl`` instance: its ``name`` field, the weakened
   predicate, the conclusion predicate, and the file and line.
2. For each, whether the corresponding ``*_is_load_bearing`` theorem is
   UNCONDITIONAL (takes no hypothesis) or CONDITIONAL (takes a
   ``sound : ∀ row, ... → ...`` hypothesis). A conditional corollary whose
   hypothesis is false is vacuous and certifies nothing.
3. Whether a proof of that soundness hypothesis exists in the same file.
4. Which opcodes each control plausibly certifies, read mechanically from the
   selector guard in its conclusion predicate. Prose claims of broader
   coverage are deliberately not trusted.
5. A per-opcode summary of the four evidence slots.

The tool is read-only evidence production: it never writes the certificate
index. A promoter (or the integration monitor) acts on its output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEAN_ROOT = REPOSITORY_ROOT / "formal/riscv-refinement/RiscvRefinement"

#: The 22 Team B opcodes of issue #137, keyed by AIR family, in production
#: manifest order. Kept as an embedded constant so the inventory works on
#: any tree slice; ``verify_manifest`` cross-checks it against the production
#: opcode manifest when that file is present.
FAMILY_OPCODES: dict[str, tuple[str, ...]] = {
    "shifts_reg": ("sll", "srl", "sra"),
    "shifts_imm": ("slli", "srli", "srai"),
    "load_store": ("lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"),
    "mul": ("mul",),
    "mulh": ("mulh", "mulhsu", "mulhu"),
    "div": ("div", "divu", "rem", "remu"),
}

TEAM_B_OPCODES: tuple[str, ...] = tuple(
    mnemonic for opcodes in FAMILY_OPCODES.values() for mnemonic in opcodes
)

OPCODE_FAMILY: dict[str, str] = {
    mnemonic: family
    for family, opcodes in FAMILY_OPCODES.items()
    for mnemonic in opcodes
}

#: Lean row type -> the opcodes an unguarded conclusion over that row type can
#: speak about. ``ShiftRow`` is the shared layer under both shift families.
ROW_TYPE_OPCODES: dict[str, tuple[str, ...]] = {
    "MulRow": FAMILY_OPCODES["mul"],
    "MulhRow": FAMILY_OPCODES["mulh"],
    "DivRow": FAMILY_OPCODES["div"],
    "LoadStoreRow": FAMILY_OPCODES["load_store"],
    "ShiftsImmRow": FAMILY_OPCODES["shifts_imm"],
    "ShiftsRegRow": FAMILY_OPCODES["shifts_reg"],
    "ShiftRow": FAMILY_OPCODES["shifts_reg"] + FAMILY_OPCODES["shifts_imm"],
}

#: Derived (multi-opcode) selector fields, keyed by (row type, selector).
#: Transcribed from the family capsules:
#:   Air/Family/LoadStore.lean: isHalf, isHalfLoad, isSigned
#:   Air/Family/Div.lean: isSigned, isDivision
DERIVED_SELECTORS: dict[tuple[str, str], tuple[str, ...]] = {
    ("LoadStoreRow", "isHalf"): ("lh", "lhu", "sh"),
    ("LoadStoreRow", "isHalfLoad"): ("lh", "lhu"),
    ("LoadStoreRow", "isSigned"): ("lb", "lh"),
    ("LoadStoreRow", "isLoad"): ("lb", "lh", "lw", "lbu", "lhu"),
    ("LoadStoreRow", "isStore"): ("sb", "sh", "sw"),
    ("DivRow", "isSigned"): ("div", "rem"),
    ("DivRow", "isDivision"): ("div", "divu"),
    ("DivRow", "isRemainder"): ("rem", "remu"),
}

#: ``row.semantic.kind = ShiftKind.<k>`` guards, keyed by (row type, kind).
SHIFT_KIND_OPCODES: dict[tuple[str, str], tuple[str, ...]] = {
    ("ShiftsImmRow", "sll"): ("slli",),
    ("ShiftsImmRow", "srl"): ("srli",),
    ("ShiftsImmRow", "sra"): ("srai",),
    ("ShiftsRegRow", "sll"): ("sll",),
    ("ShiftsRegRow", "srl"): ("srl",),
    ("ShiftsRegRow", "sra"): ("sra",),
    ("ShiftRow", "sll"): ("sll", "slli"),
    ("ShiftRow", "srl"): ("srl", "srli"),
    ("ShiftRow", "sra"): ("sra", "srai"),
}

try:
    from .riscv_team_b_inventory_lean import (
        CLOSE_BRACKETS,
        CONTROL_NAME_FIELD,
        CONTROL_TYPE,
        DECLARATION,
        END_LINE,
        FALLBACK_DEVICE,
        MANIFEST_ENTRY,
        NAMESPACE_LINE,
        OPEN_BRACKETS,
        SELECTOR_ENUM_GUARD,
        SELECTOR_GUARD,
        SHIFT_KIND_GUARD,
        STRICTLY_WEAKER,
        ConclusionInfo,
        ControlInfo,
        Declaration,
        LoadBearingInfo,
        _binder_groups,
        _binder_name,
        _scan_top_level,
        parse_declarations,
        strip_comments,
    )
except ImportError:
    from riscv_team_b_inventory_lean import (
        CLOSE_BRACKETS,
        CONTROL_NAME_FIELD,
        CONTROL_TYPE,
        DECLARATION,
        END_LINE,
        FALLBACK_DEVICE,
        MANIFEST_ENTRY,
        NAMESPACE_LINE,
        OPEN_BRACKETS,
        SELECTOR_ENUM_GUARD,
        SELECTOR_GUARD,
        SHIFT_KIND_GUARD,
        STRICTLY_WEAKER,
        ConclusionInfo,
        ControlInfo,
        Declaration,
        LoadBearingInfo,
        _binder_groups,
        _binder_name,
        _scan_top_level,
        parse_declarations,
        strip_comments,
    )


def conclusion_opcodes(decl: Declaration) -> ConclusionInfo:
    """Which opcodes a conclusion predicate can certify, from its guard.

    A conclusion guarded on a selector certifies exactly the opcodes that can
    set that selector. An unguarded conclusion is only family-granular: it is
    reported against every opcode of its row type's family and flagged,
    because an unguarded claim over a multi-opcode family is refuted by an
    honest row of a different opcode unless it genuinely holds family-wide.
    """

    row_type = ""
    for group in decl.binders:
        if ":" in group:
            name, type_text = group.split(":", 1)
            if name.strip().split() == ["row"]:
                row_type = type_text.strip().split()[0].split(".")[-1]
                break
    if not row_type and decl.binders:
        first = decl.binders[0]
        if ":" in first:
            row_type = first.split(":", 1)[1].strip().split()[0].split(".")[-1]

    family_scope = set(ROW_TYPE_OPCODES.get(row_type, TEAM_B_OPCODES))
    opcodes = set(family_scope)
    guards: list[str] = []
    unknown: list[str] = []
    guarded = False

    for match in SELECTOR_GUARD.finditer(decl.body):
        selector = match.group(1)
        guards.append(f"row.{selector} = true")
        mapped = DERIVED_SELECTORS.get((row_type, selector))
        if mapped is None:
            mnemonic = selector[2:].lower()
            if mnemonic in OPCODE_FAMILY:
                mapped = (mnemonic,)
        if mapped is None:
            unknown.append(selector)
            continue
        guarded = True
        opcodes &= set(mapped)

    for match in SHIFT_KIND_GUARD.finditer(decl.body):
        kind = match.group(1)
        guards.append(f"kind = ShiftKind.{kind}")
        mapped = SHIFT_KIND_OPCODES.get((row_type, kind))
        if mapped is None:
            unknown.append(f"ShiftKind.{kind}")
            continue
        guarded = True
        opcodes &= set(mapped)

    for match in SELECTOR_ENUM_GUARD.finditer(decl.body):
        mnemonic = match.group(1)
        guards.append(f"row.selector = ...Selector.{mnemonic}")
        if mnemonic in OPCODE_FAMILY:
            guarded = True
            opcodes &= {mnemonic}
        else:
            unknown.append(f"Selector.{mnemonic}")

    ordered = [m for m in TEAM_B_OPCODES if m in opcodes]
    return ConclusionInfo(
        name=decl.name,
        file=decl.file,
        line=decl.line,
        row_type=row_type,
        guards=guards,
        opcodes=ordered,
        guarded=guarded,
        unknown_guards=unknown,
    )


def parse_load_bearing(decl: Declaration) -> LoadBearingInfo:
    hypotheses = list(decl.binders)
    classification = "conditional" if hypotheses else "unconditional"
    control_ref = original = sound_term = derived_from = None
    match = STRICTLY_WEAKER.search(decl.body)
    if match:
        control_ref = match.group(1).split(".")[-1]
        original = match.group(2).split(".")[-1]
        sound_term = match.group(3).split(".")[-1]
    else:
        reference = re.search(
            r"\b([A-Za-z0-9_']*_is_load_bearing)\b", decl.body
        )
        if reference and reference.group(1) != decl.name:
            derived_from = reference.group(1)
    return LoadBearingInfo(
        name=decl.name,
        qualified=decl.qualified,
        file=decl.file,
        line=decl.line,
        classification=classification,
        hypotheses=hypotheses,
        control_ref=control_ref,
        original=original,
        sound_term=sound_term,
        derived_from=derived_from,
    )


def _infer_original(weakened: str) -> str | None:
    match = re.match(r"([A-Za-z0-9_']*Holds)Without", weakened)
    return match.group(1) if match else None


def _is_soundness_theorem(
    decl: Declaration, original: str, conclusion: str
) -> bool:
    """A theorem of shape ``(row) (holds : Original row) : Conclusion row``."""

    if decl.kind not in ("theorem", "lemma"):
        return False
    goal_head = decl.goal.strip().split()
    if not goal_head or goal_head[0].split(".")[-1] != conclusion:
        return False
    pattern = re.compile(rf"\b{re.escape(original)}\b")
    return any(pattern.search(group) for group in decl.binders)


@dataclass
class Inventory:
    lean_root: str
    controls: list[ControlInfo]
    conclusions: dict[str, ConclusionInfo]
    theorems: dict[str, list[tuple[str, int]]]
    fallbacks: list[dict]
    flags: list[str]
    manifest_note: str | None = None


def build_inventory(lean_root: Path) -> Inventory:
    controls: list[ControlInfo] = []
    conclusions: dict[str, ConclusionInfo] = {}
    theorems: dict[str, list[tuple[str, int]]] = {}
    fallbacks: list[dict] = []
    load_bearing_by_file: dict[str, list[LoadBearingInfo]] = {}
    declarations_by_file: dict[str, list[Declaration]] = {}

    for path in sorted(lean_root.rglob("*.lean")):
        declarations = parse_declarations(path, lean_root)
        if not declarations:
            continue
        rel = declarations[0].file
        declarations_by_file[rel] = declarations
        for decl in declarations:
            if decl.kind in ("theorem", "lemma"):
                theorems.setdefault(decl.name, []).append((rel, decl.line))
                if FALLBACK_DEVICE.search(decl.body):
                    fallbacks.append(
                        {"name": decl.name, "file": rel, "line": decl.line}
                    )
                if decl.name.endswith("_is_load_bearing"):
                    load_bearing_by_file.setdefault(rel, []).append(
                        parse_load_bearing(decl)
                    )
            elif decl.kind in ("def", "abbrev") and decl.goal.strip() == "Prop":
                conclusions.setdefault(decl.name, conclusion_opcodes(decl))
            if decl.kind in ("def", "instance"):
                type_and_body = " ".join(
                    [" ".join(decl.binders), decl.goal, decl.body]
                )
                match = CONTROL_TYPE.search(
                    (decl.goal + " where " + decl.body)
                    if decl.goal
                    else decl.body
                )
                if match is None:
                    match = CONTROL_TYPE.search(type_and_body)
                if match:
                    name_field = CONTROL_NAME_FIELD.search(decl.body)
                    controls.append(
                        ControlInfo(
                            definition=decl.name,
                            qualified=decl.qualified,
                            control_name=(
                                name_field.group(1) if name_field else ""
                            ),
                            weakened=match.group(1).split(".")[-1],
                            conclusion=match.group(2).split(".")[-1],
                            file=rel,
                            line=decl.line,
                        )
                    )

    flags: list[str] = []
    for control in controls:
        conclusion = conclusions.get(control.conclusion)
        if conclusion is not None:
            control.row_type = conclusion.row_type
            control.guards = conclusion.guards
            control.certifies = conclusion.opcodes
            control.guarded = conclusion.guarded
            control.unknown_guards = conclusion.unknown_guards
        else:
            control.flags.append(
                f"conclusion predicate `{control.conclusion}` not found in "
                "the scanned tree; certified opcodes unknown"
            )

        file_corollaries = load_bearing_by_file.get(control.file, [])
        direct = [
            c for c in file_corollaries if c.control_ref == control.definition
        ]
        control.corollaries = direct
        direct_names = {c.name for c in direct}
        control.derived_corollaries = [
            c for c in file_corollaries if c.derived_from in direct_names
        ]

        if not direct:
            control.status = "no-corollary"
            control.flags.append(
                "no `*_is_load_bearing` corollary references this control"
            )
        elif any(c.classification == "unconditional" for c in direct):
            control.status = "unconditional"
        else:
            control.status = "conditional"

        control.original = next(
            (c.original for c in direct if c.original), None
        ) or _infer_original(control.weakened)

        if control.original and conclusion is not None:
            in_file = [
                decl.name
                for decl in declarations_by_file.get(control.file, [])
                if _is_soundness_theorem(
                    decl, control.original, control.conclusion
                )
            ]
            control.soundness_theorems = in_file
            control.soundness_in_file = bool(in_file)

        if control.status == "conditional":
            control.flags.append(
                "CONDITIONAL corollary: rests on an unproved soundness "
                "hypothesis; review before promoting its opcodes"
                + (
                    " (an in-file soundness theorem exists but the corollary "
                    "does not use it)"
                    if control.soundness_in_file
                    else ""
                )
            )
        if conclusion is not None and not control.guarded:
            control.flags.append(
                "conclusion has no selector guard: certification is "
                "family-granular; confirm the claim holds for every opcode "
                "of the family"
            )
        if control.unknown_guards:
            control.flags.append(
                "unrecognised selector guard(s) "
                + ", ".join(control.unknown_guards)
                + "; certified opcode set may be wrong"
            )
        for note in control.flags:
            flags.append(f"{control.definition}: {note}")

    claimed = {c.name for control in controls for c in control.corollaries}
    claimed |= {
        c.name for control in controls for c in control.derived_corollaries
    }
    for file_corollaries in load_bearing_by_file.values():
        for corollary in file_corollaries:
            if corollary.name not in claimed:
                flags.append(
                    f"{corollary.name} ({corollary.file}:{corollary.line}): "
                    "load-bearing theorem not linked to any MutationControl; "
                    "inspect by hand"
                )

    return Inventory(
        lean_root=str(lean_root),
        controls=controls,
        conclusions=conclusions,
        theorems=theorems,
        fallbacks=fallbacks,
        flags=flags,
    )


def verify_manifest(inventory: Inventory, manifest_path: Path) -> None:
    """Cross-check the embedded opcode table against the production manifest."""

    if not manifest_path.exists():
        inventory.manifest_note = (
            f"opcode manifest not found at {manifest_path}; "
            "using the embedded issue-137 opcode table"
        )
        return
    text = manifest_path.read_text(encoding="utf-8")
    manifest: dict[str, str] = {}
    for mnemonic, family in MANIFEST_ENTRY.findall(text):
        if family in FAMILY_OPCODES:
            manifest[mnemonic] = family
    embedded = dict(OPCODE_FAMILY)
    if manifest != embedded:
        missing = sorted(set(embedded) - set(manifest))
        extra = sorted(set(manifest) - set(embedded))
        inventory.manifest_note = (
            "embedded opcode table DISAGREES with the production manifest"
            f" (missing from manifest: {missing}; unexpected: {extra})"
        )
        inventory.flags.append(inventory.manifest_note)
    else:
        inventory.manifest_note = (
            "embedded opcode table matches the production manifest"
        )


# ---------------------------------------------------------------------------
# Summary


def opcode_summary(inventory: Inventory) -> dict[str, dict]:
    summary: dict[str, dict] = {}
    for mnemonic in TEAM_B_OPCODES:
        refine_name = f"{mnemonic}_refines"
        refinement = inventory.theorems.get(refine_name, [])
        tuple_candidates = [
            name
            for name in inventory.theorems
            if re.fullmatch(rf"{re.escape(mnemonic)}_tuple(_[a-z0-9_']+)?", name)
        ]
        witness_names = sorted(
            name
            for name in inventory.theorems
            if re.fullmatch(
                rf"{re.escape(mnemonic)}(_[a-z0-9_']+)?_exists", name
            )
        )
        covering = [
            c for c in inventory.controls if mnemonic in c.certifies
        ]
        unconditional = [
            c for c in covering if c.status == "unconditional"
        ]
        conditional = [c for c in covering if c.status == "conditional"]
        if unconditional:
            mutation_status = "unconditional"
        elif conditional:
            mutation_status = "conditional-only"
        elif covering:
            mutation_status = "control-without-corollary"
        else:
            mutation_status = "none"
        entry = {
            "family": OPCODE_FAMILY[mnemonic],
            "refinement_theorem": refine_name if refinement else None,
            "tuple_theorem": (
                tuple_candidates[0]
                if tuple_candidates
                else (refine_name if refinement else None)
            ),
            "tuple_via_refinement": bool(refinement) and not tuple_candidates,
            "non_vacuity_theorems": witness_names,
            "mutation_status": mutation_status,
            "mutation_controls": [
                {
                    "definition": c.definition,
                    "control_name": c.control_name,
                    "status": c.status,
                    "guarded": c.guarded,
                }
                for c in covering
            ],
            "promotion_ready": bool(
                refinement and witness_names and unconditional
            ),
            "needs_review": bool(conditional)
            or any(not c.guarded for c in unconditional),
        }
        summary[mnemonic] = entry
    return summary


# ---------------------------------------------------------------------------
# Rendering


def render_json(inventory: Inventory) -> str:
    payload = {
        "lean_root": inventory.lean_root,
        "manifest_note": inventory.manifest_note,
        "controls": [c.to_dict() for c in inventory.controls],
        "fallback_devices": inventory.fallbacks,
        "opcodes": opcode_summary(inventory),
        "flags": inventory.flags,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _slot(value: str | None) -> str:
    return value if value else "—"


def render_text(inventory: Inventory) -> str:
    lines: list[str] = []
    lines.append("# Team B mutation-control evidence inventory")
    lines.append("")
    lines.append(f"Lean root: `{inventory.lean_root}`")
    if inventory.manifest_note:
        lines.append(f"Manifest check: {inventory.manifest_note}")
    lines.append("")
    lines.append(
        "Produced by `scripts/riscv_team_b_inventory.py` (read-only; the "
        "certificate index is never written). Certified-opcode sets are "
        "read mechanically from selector guards; prose claims of broader "
        "coverage are not trusted."
    )

    conditional = [
        control
        for control in inventory.controls
        if control.status == "conditional"
    ]
    lines.append("")
    if conditional:
        lines.append(
            f"**CONDITIONAL corollaries requiring review: {len(conditional)}** "
            "— every one rests on an unproved soundness hypothesis and must "
            "not be cited for promotion until it is discharged: "
            + ", ".join(f"`{control.definition}`" for control in conditional)
        )
    else:
        lines.append(
            "Conditional corollaries requiring review: 0 — every control's "
            "`*_is_load_bearing` corollary is unconditional."
        )

    lines.append("")
    lines.append(f"## MutationControl instances ({len(inventory.controls)})")
    for control in inventory.controls:
        lines.append("")
        lines.append(
            f"### `{control.definition}` — \"{control.control_name}\""
        )
        lines.append(f"- location: `{control.file}:{control.line}`")
        lines.append(f"- weakened predicate: `{control.weakened}`")
        guard_text = (
            "; ".join(control.guards) if control.guards else "UNGUARDED"
        )
        lines.append(
            f"- conclusion predicate: `{control.conclusion}` "
            f"(row type `{control.row_type or '?'}`, guard: {guard_text})"
        )
        lines.append(
            "- certifies (from guard): "
            + (", ".join(control.certifies) if control.certifies else "unknown")
        )
        if control.corollaries:
            for corollary in control.corollaries:
                marker = corollary.classification.upper()
                detail = f"- corollary: `{corollary.name}` — {marker}"
                if corollary.classification == "conditional":
                    detail += (
                        " (hypothesis: "
                        + "; ".join(corollary.hypotheses)
                        + ")"
                    )
                elif corollary.sound_term:
                    detail += f" (soundness via `{corollary.sound_term}`)"
                lines.append(detail)
        else:
            lines.append("- corollary: NONE")
        for derived in control.derived_corollaries:
            lines.append(
                f"- derived corollary: `{derived.name}` "
                f"(from `{derived.derived_from}`; opcode credit not "
                "extended mechanically — review)"
            )
        lines.append(
            "- soundness proof in file: "
            + (
                "yes ("
                + ", ".join(f"`{t}`" for t in control.soundness_theorems)
                + ")"
                if control.soundness_in_file
                else "NO"
            )
        )
        for note in control.flags:
            lines.append(f"- FLAG: {note}")

    if inventory.fallbacks:
        lines.append("")
        lines.append(
            "## Fallback strictness devices "
            "(`strictly_weaker_of_not_original`)"
        )
        lines.append(
            "These prove a deletion is strict without an architectural "
            "conclusion. They are honest but weaker and do NOT fill the "
            "mutation slot."
        )
        for entry in inventory.fallbacks:
            lines.append(
                f"- `{entry['name']}` at `{entry['file']}:{entry['line']}`"
            )

    summary = opcode_summary(inventory)
    lines.append("")
    lines.append("## Per-opcode evidence summary")
    lines.append("")
    lines.append(
        "| opcode | family | refinement | tuple | non-vacuity | "
        "mutation control | promotion-ready |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for mnemonic, entry in summary.items():
        witness = (
            ", ".join(entry["non_vacuity_theorems"])
            if entry["non_vacuity_theorems"]
            else "—"
        )
        mutation = entry["mutation_status"]
        if mutation == "unconditional":
            mutation_text = "unconditional: " + ", ".join(
                c["definition"]
                for c in entry["mutation_controls"]
                if c["status"] == "unconditional"
            )
        elif mutation == "conditional-only":
            mutation_text = "CONDITIONAL ONLY (review): " + ", ".join(
                c["definition"]
                for c in entry["mutation_controls"]
                if c["status"] == "conditional"
            )
        elif mutation == "control-without-corollary":
            mutation_text = "control without corollary"
        else:
            mutation_text = "—"
        tuple_text = _slot(entry["tuple_theorem"])
        if entry["tuple_via_refinement"] and entry["tuple_theorem"]:
            tuple_text += " (via refinement)"
        ready = "YES" if entry["promotion_ready"] else "no"
        if entry["promotion_ready"] and entry["needs_review"]:
            ready = "YES (review flags)"
        lines.append(
            f"| {mnemonic} | {entry['family']} | "
            f"{_slot(entry['refinement_theorem'])} | {tuple_text} | "
            f"{witness} | {mutation_text} | {ready} |"
        )

    lines.append("")
    lines.append("## Review flags")
    if inventory.flags:
        for flag in inventory.flags:
            lines.append(f"- {flag}")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report the mutation-control evidence that exists per Team B "
            "opcode. Read-only: never touches the certificate index."
        )
    )
    parser.add_argument(
        "--lean-root",
        type=Path,
        default=DEFAULT_LEAN_ROOT,
        help="Lean source tree to scan (default: RiscvRefinement/)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="also write the report to this path",
    )
    parser.add_argument(
        "--skip-manifest-check",
        action="store_true",
        help="do not cross-check the embedded opcode table",
    )
    args = parser.parse_args(argv)

    if not args.lean_root.is_dir():
        print(f"error: lean root {args.lean_root} is not a directory",
              file=sys.stderr)
        return 2

    inventory = build_inventory(args.lean_root)
    if not args.skip_manifest_check:
        verify_manifest(
            inventory,
            REPOSITORY_ROOT / "src/frontends/riscv/opcode_manifest.zig",
        )

    report = render_json(inventory) if args.json else render_text(inventory)
    sys.stdout.write(report)
    if args.output is not None:
        args.output.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
