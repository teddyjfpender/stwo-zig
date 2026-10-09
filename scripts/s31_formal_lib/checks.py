"""Exact source/theorem inventories and fail-closed S31 proof checks."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable

APPROVED_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})
REUSED = (
    "formal/riscv-refinement/RiscvRefinement/Field/M31.lean",
    "formal/riscv-refinement/RiscvRefinement/Recursion/CompactPoseidon.lean",
)
# Lean's source-range audit also sees proof projections, a Prop-valued
# instance and Mathlib's generated extensionality iff theorem. Name these
# explicitly rather than silently dropping non-`theorem` declarations.
DERIVED_THEOREMS = {
    REUSED[0]: ("RiscvRefinement.M31.isLt",),
    "formal/s31/S31/Gadgets/Field.lean": ("S31.Field.instFactPrimeOfNatNat_s31",),
    "formal/s31/S31/Gadgets/Packed.lean": ("S31.Gadgets.Packed.Quad.ext_iff",),
}
CONTROLS = frozenset("S31.Evidence." + name for name in (
    "honest_byte_boundary", "byte_out_of_range", "honest_carry", "honest_borrow",
    "checked_overflow_rejected", "checked_underflow_rejected", "zero_inverse_witness_free",
    "nonboolean_rejected", "illegal_selector_rejected", "signed_positive_overflow",
    "signed_negative_overflow", "signed_subtraction_overflow", "negative_interpretation",
    "honest_division", "wrong_quotient_rejected", "oversized_remainder_rejected",
    "high_product_not_truncated", "terminal_carry_is_necessary", "invalid_exponent_rejected",
    "honest_exponent", "digest_last_word", "honest_field_hash_gate", "forged_field_hash_gate",
    "padding_requires_widths",
))


class FormalError(RuntimeError):
    """Missing, stale, or invalid formal evidence."""


def scan_source(source: str, label: str, lexer: Callable[[str], str]) -> None:
    for match in re.finditer(r"\b(sorry|admit|axiom|unsafe|native_decide)\b", lexer(source)):
        line = source.count("\n", 0, match.start()) + 1
        raise FormalError(f"{label}:{line}: forbidden proof term {match.group()}")


def theorem_names(source: str, lexer: Callable[[str], str]) -> list[str]:
    """Inventory this package's explicit namespace/section declaration style.

    Compilation and the live Lean metadata audit are authoritative. This
    independent source inventory prevents an omitted root import from hiding
    a theorem from that audit. New unsupported declaration syntax fails closed.
    """
    scopes: list[tuple[str, str]] = []
    names = []
    for line in lexer(source).splitlines():
        if match := re.fullmatch(r"\s*(namespace|section)(?:\s+([\w.]+))?\s*", line):
            scopes.append((match[1], match[2] or ""))
        elif match := re.fullmatch(r"\s*end(?:\s+([\w.]+))?\s*", line):
            if not scopes or (match[1] and match[1] != scopes[-1][1]):
                raise FormalError("unmatched Lean namespace/section")
            scopes.pop()
        elif re.search(r"\btheorem\b", line):
            match = re.match(r"\s*(?:@\[[^\]]+\]\s*)*(?:(private|protected)\s+)?"
                             r"theorem\s+([\w.?!']+)(?=\s|[:({]|$)", line)
            if not match:
                raise FormalError(f"unsupported theorem declaration: {line.strip()}")
            if match[1] != "private":
                namespace = ".".join(name for kind, name in scopes if kind == "namespace")
                names.append(namespace + "." + match[2] if namespace else match[2])
    if scopes:
        raise FormalError("unterminated Lean namespace/section")
    if len(names) != len(set(names)):
        raise FormalError("duplicate theorem declaration")
    return names


def source_paths(root: Path) -> list[Path]:
    formal = root / "formal/s31"
    required = [formal / "S31.lean", formal / "S31/Semantics/Node.lean",
                formal / "S31/Evidence/NonVacuity.lean", formal / "S31/Evidence/Coverage.lean",
                formal / "S31/Evidence/AxiomAudit.lean", *(root / path for path in REUSED)]
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise FormalError(f"missing regular proof source: {path.relative_to(root)}")
    sources = sorted({formal / "S31.lean", *formal.joinpath("S31").rglob("*.lean"),
                      *(root / path for path in REUSED)})
    if any(not p.is_file() or p.is_symlink() for p in sources):
        raise FormalError("proof source closure contains a non-regular file")
    return sources


def inventory(root: Path, lexer: Callable[[str], str]) -> dict:
    files, declarations = {}, []
    for path in source_paths(root):
        source = path.read_text(encoding="utf-8")
        label = path.relative_to(root).as_posix()
        scan_source(source, label, lexer)
        files[label] = hashlib.sha256(path.read_bytes()).hexdigest()
        declarations.extend(theorem_names(source, lexer))
        declarations.extend(DERIVED_THEOREMS.get(label, ()))
    if len(declarations) != len(set(declarations)):
        raise FormalError("duplicate theorem in proof closure")
    if not CONTROLS <= set(declarations):
        raise FormalError("missing required non-vacuity theorem controls")
    return {"schema": "s31-lean-inventory-v1", "files": files, "theorems": sorted(declarations)}


def check_coverage(root: Path, ops: list[str], coverage: dict, theorems: set[str]) -> None:
    if coverage.get("schema") != "s31-operation-coverage-v1":
        raise FormalError("unsupported operation coverage schema")
    if coverage.get("boundary") != "normalized relation IR v1 and local constraint models":
        raise FormalError("operation coverage claim boundary changed")
    if coverage.get("production_compiler_correctness_proved") is not False:
        raise FormalError("coverage cannot claim production compiler correctness")
    entries = coverage.get("operations", [])
    if [row.get("op") for row in entries] != ops or len(ops) != len(set(ops)):
        raise FormalError("operation coverage is not the exact source inventory")
    for row in entries:
        name = row["op"]
        if not row.get("semantics", "").startswith("S31."):
            raise FormalError(f"{name}: missing executable semantics declaration")
        if not row.get("gadget_theorems") or not set(row["gadget_theorems"]) <= theorems:
            raise FormalError(f"{name}: missing or unknown gadget theorem")
        source = root / row["source"]["path"]
        if not source.is_file() or not re.search(
            rf"\bfn\s+{re.escape(row['source']['function'])}\b", source.read_text()):
            raise FormalError(f"{name}: missing production source function")


def render_coverage(coverage: dict) -> str:
    rows = coverage["operations"]
    names = sorted({name for row in rows for name in row["gadget_theorems"]})
    result = "/- Generated by scripts/s31_formal.py from reviewed coverage.json. -/\n"
    result += "import S31.Gadgets\n\n"
    result += "".join(f"#check {name}\n" for name in names)
    result += "\n" + "".join(f"#check {name}\n" for name in sorted({r['semantics'] for r in rows}))
    result += "\nnamespace S31.Evidence\n\n"
    result += "def operationCoverage : List (Op × List String) := [\n"
    result += ",\n".join("  (." + row["op"] + ", " + json.dumps(row["gadget_theorems"]) + ")"
                           for row in rows)
    result += "]\n\n"
    result += "theorem operation_inventory_exact : operationCoverage.map Prod.fst = allOps := rfl\n\n"
    result += "theorem operation_inventory_complete (op : Op) :\n"
    result += "    op ∈ operationCoverage.map Prod.fst := by cases op <;> simp [operationCoverage]\n\n"
    result += "theorem operation_inventory_size : operationCoverage.length = 43 := rfl\n\n"
    result += "end S31.Evidence\n"
    return result


def check_audit(output: str, expected: set[str]) -> dict:
    found: dict[str, set[str]] = {}
    if not expected:
        raise FormalError("empty expected theorem inventory")
    if "error:" in output:
        raise FormalError("Lean audit reported an error")
    for line in output.splitlines():
        if line.startswith("S31_THEOREM "):
            parts = line.split()
            if len(parts) != 2 or parts[1] in found:
                raise FormalError("malformed or duplicate theorem audit record")
            found[parts[1]] = set()
        elif line.startswith("S31_AXIOM "):
            parts = line.split()
            if len(parts) != 3 or parts[1] not in found or parts[2] in found[parts[1]]:
                raise FormalError("malformed or duplicate axiom audit record")
            if parts[2] not in APPROVED_AXIOMS:
                raise FormalError(f"unapproved axiom: {parts[2]}")
            found[parts[1]].add(parts[2])
    if set(found) != expected:
        raise FormalError("live theorem inventory differs from source inventory: "
                          f"missing={sorted(expected - set(found))}, extra={sorted(set(found) - expected)}")
    return {"theorems": len(found), "approved_axioms": sorted(APPROVED_AXIOMS),
            "theorem_axioms": {name: sorted(found[name]) for name in sorted(found)}}


def check_kernel_log(output: str, files: dict[str, str]) -> dict:
    expected = set()
    for path in files:
        if path.startswith("formal/s31/"):
            expected.add(path.removeprefix("formal/s31/").removesuffix(".lean").replace("/", "."))
        elif path in REUSED:
            expected.add(path.removeprefix("formal/riscv-refinement/").removesuffix(".lean").replace("/", "."))
    actual = [line.removeprefix("replaying ") for line in output.splitlines() if line.startswith("replaying ")]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise FormalError("kernel replay module inventory is incomplete or duplicated")
    if any(marker in output for marker in ("error", "exception", "found a problem")):
        raise FormalError("kernel replay reported a failure")
    return {"replayed_modules": len(actual)}
