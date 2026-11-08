"""Production-AIR evaluation, schema audit, and export provenance."""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any

__all__ = [
    "M31",
    "REPOSITORY_ROOT",
    "AIR_SOURCE_ROOT",
    "EXPORT_COMMAND",
    "RANGE_DOMAINS",
    "SKIPPED_DOMAINS",
    "SUPPORTED_OPERATIONS",
    "WitnessError",
    "modular_inverse",
    "load_family",
    "_column_drift_message",
    "evaluate",
    "check_constraints",
    "_unknown_domain_error",
    "check_range_lookups",
    "check_witness",
    "INT_MIN",
    "_limbs",
    "_signed",
    "audit_exported_families",
    "export_digest",
    "check_export_provenance",
]

M31 = 2147483647

#: Repository root, derived from this file's location so the freshness guard
#: works no matter which directory the gate is invoked from.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

#: Every Zig source that can change the exported production AIR lives under
#: this tree (the AIR components, their lookups, and the IR export tool). The
#: provenance check compares its newest mtime against the export's oldest.
AIR_SOURCE_ROOT = REPOSITORY_ROOT / "src" / "frontends" / "riscv"

#: The exact command that regenerates the exported production AIR this gate
#: reads. Failure messages quote it so a digest or shape drift tells the reader
#: what to run next instead of only what went wrong.
EXPORT_COMMAND = (
    "zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir"
)

#: Range-check domains and the bit width of each tuple coordinate.
#: ``range_check_m31`` additionally rejects the maximal tuple, matching
#: ``src/frontends/riscv/air/lookups/entry.zig``.
RANGE_DOMAINS: dict[str, tuple[int, ...]] = {
    "range_check_20": (20,),
    "range_check_8_11": (8, 11),
    "range_check_8_8": (8, 8),
    "range_check_8_8_4": (8, 8, 4),
    "range_check_m31": (8, 7),
}

#: Lookup domains this gate deliberately does not check, with the reason. They
#: are multiset (bus) relations balanced across the whole trace — memory,
#: program and register consistency, and the preprocessed bitwise table — so a
#: single-row evaluation cannot decide them; the Lean side models them as
#: `unmodelled_bus_requests`. Every domain a family uses must appear either
#: here or in ``RANGE_DOMAINS``: an unknown domain is an ERROR, never a silent
#: skip, because a new production range table that this gate ignored would
#: quietly widen what a "reachable" witness is allowed to claim.
SKIPPED_DOMAINS: dict[str, str] = {
    "bitwise": "preprocessed AND/OR/XOR table; a trace-global lookup argument",
    "memory_access": "trace-global memory-consistency bus, not a range table",
    "program_access": "trace-global program-ROM consistency bus, not a range table",
    "registers_state": "trace-global register-file bus, not a range table",
}

#: Node operations the evaluator implements. ``audit_exported_families`` holds
#: every exported family to this set, and the test suite holds ``evaluate`` to
#: it, so the constant cannot drift from the dispatch below.
SUPPORTED_OPERATIONS = frozenset({"const", "col", "neg", "add", "sub", "mul"})


class WitnessError(RuntimeError):
    """A witness failed the production AIR. Every path out raises this."""


def modular_inverse(value: int) -> int:
    return pow(value % M31, M31 - 2, M31)


def load_family(air_ir_dir: Path, family: str) -> dict[str, Any]:
    path = air_ir_dir / f"{family}.json"
    if not path.is_file():
        raise WitnessError(f"exported AIR for {family} is absent at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _column_drift_message(declared: set[str], assigned: set[str]) -> str:
    """Explain a witness/AIR column mismatch as new vs renamed vs removed.

    The witness builders in this file encode the column set the AIR had when
    they were written; ``declared`` is what the export has now. Diffing the two
    turns "unassigned columns" from a wall of names into a statement about what
    actually moved, which is exactly what a reader needs when Team A's AIR IR
    work or an opcode fix reshapes the exported production AIR.
    """
    missing = sorted(declared - assigned)  # in the AIR, not in the witness
    unknown = sorted(assigned - declared)  # in the witness, not in the AIR
    renamed: list[tuple[str, str]] = []
    unmatched_missing = list(missing)
    for old in unknown:
        candidates = difflib.get_close_matches(old, unmatched_missing, n=1)
        if candidates:
            renamed.append((old, candidates[0]))
            unmatched_missing.remove(candidates[0])
    renamed_old = {old for old, _ in renamed}
    added = unmatched_missing
    removed = [name for name in unknown if name not in renamed_old]

    lines = ["witness and exported AIR disagree on the column set:"]
    if missing:
        lines.append(
            "  witness leaves AIR columns unassigned: " + ", ".join(missing)
        )
    if unknown:
        lines.append(
            "  witness assigns columns the AIR does not declare: "
            + ", ".join(unknown)
        )
    if added:
        lines.append("  likely NEW in the AIR: " + ", ".join(added))
    if renamed:
        lines.append(
            "  likely RENAMED: "
            + ", ".join(f"{old} -> {new}" for old, new in renamed)
        )
    if removed:
        lines.append("  likely REMOVED from the AIR: " + ", ".join(removed))
    lines.append(
        "  likely cause: the exported production AIR changed shape (for "
        "example Team A's AIR IR v2 work or an opcode fix) while the witness "
        "builders in scripts/riscv_team_b_witnesses.py still describe the old "
        f"layout. Re-derive the export with `{EXPORT_COMMAND}`, then update "
        "the witness builders (and the Lean capsule transcription) to the new "
        "column set."
    )
    return "\n".join(lines)


def evaluate(payload: dict[str, Any], assignment: dict[str, int]) -> list[int]:
    """Evaluate the flat AIR DAG over M31 under ``assignment``."""
    declared = {column["name"] for column in payload["columns"]}
    if declared != set(assignment):
        raise WitnessError(_column_drift_message(declared, set(assignment)))

    values: list[int] = []
    for node in payload["nodes"]:
        operation = node["op"]
        if operation == "const":
            value = node["value"] % M31
        elif operation == "col":
            value = assignment[node["name"]] % M31
        elif operation == "neg":
            value = (-values[node["args"][0]]) % M31
        elif operation == "add":
            value = (values[node["args"][0]] + values[node["args"][1]]) % M31
        elif operation == "sub":
            value = (values[node["args"][0]] - values[node["args"][1]]) % M31
        elif operation == "mul":
            value = (values[node["args"][0]] * values[node["args"][1]]) % M31
        else:
            raise WitnessError(f"unsupported AIR node operation {operation!r}")
        values.append(value)
    return values


def check_constraints(payload: dict[str, Any], values: list[int]) -> None:
    unsatisfied = [
        index
        for index, root in enumerate(payload["constraints"])
        if values[root] != 0
    ]
    if unsatisfied:
        raise WitnessError(
            "witness does not satisfy production AIR constraint roots "
            + ", ".join(str(index) for index in unsatisfied)
        )


def _unknown_domain_error(family: str, domain: str) -> WitnessError:
    return WitnessError(
        f"family {family!r} uses lookup domain {domain!r}, which this gate "
        "does not know. It is neither a range-check domain "
        f"({', '.join(sorted(RANGE_DOMAINS))}) nor a deliberately skipped bus "
        f"domain ({', '.join(sorted(SKIPPED_DOMAINS))}). A new production "
        "lookup domain must be classified explicitly in RANGE_DOMAINS or "
        "SKIPPED_DOMAINS in scripts/riscv_team_b_witnesses.py — skipping it "
        "silently could hide an unchecked range table. If the domain is new, "
        f"re-derive the export with `{EXPORT_COMMAND}` and read "
        "src/frontends/riscv/air/lookups/ for what the domain provides."
    )


def check_range_lookups(payload: dict[str, Any], values: list[int]) -> int:
    """Every requested range-check tuple must exist in its production table.

    Domains are classified before activity is considered: an unknown domain is
    an error even on a row where the request is inactive, because
    classification is a property of the AIR's shape, not of one witness.
    """
    checked = 0
    for index, lookup in enumerate(payload["lookups"]):
        domain = lookup["domain"]
        widths = RANGE_DOMAINS.get(domain)
        if widths is None:
            if domain not in SKIPPED_DOMAINS:
                raise _unknown_domain_error(payload.get("family", "?"), domain)
            continue
        if values[lookup["numerator"]] == 0:
            # An inactive request asserts nothing, exactly as in production.
            continue
        tuple_values = [values[node] for node in lookup["tuple"]]
        if len(tuple_values) != len(widths):
            raise WitnessError(
                f"lookup {index} on {domain} has arity {len(tuple_values)}, "
                f"expected {len(widths)}"
            )
        for coordinate, (value, width) in enumerate(zip(tuple_values, widths)):
            if value >= 1 << width:
                raise WitnessError(
                    f"lookup {index} on {domain} coordinate {coordinate} is "
                    f"{value}, outside the {width}-bit production table"
                )
        if domain == "range_check_m31" and tuple_values == [255, 127]:
            raise WitnessError(
                f"lookup {index} requests the tuple production rejects (255, 127)"
            )
        checked += 1
    return checked


def check_witness(
    air_ir_dir: Path, family: str, assignment: dict[str, int]
) -> str:
    payload = load_family(air_ir_dir, family)
    try:
        values = evaluate(payload, assignment)
        check_constraints(payload, values)
        checked = check_range_lookups(payload, values)
    except WitnessError as error:
        raise WitnessError(
            f"family {family!r} rejected the witness: {error}\n"
            "  If this appeared after the production AIR moved (Team A AIR IR "
            "work, an opcode fix), the witness builders here lag the export. "
            f"Re-derive it with `{EXPORT_COMMAND}` and diff "
            f"zig-out/team-b-ir/{family}.json against the previous export."
        ) from error
    return (
        f"{family}: {len(payload['constraints'])} constraints satisfied, "
        f"{checked} active range requests inside their production tables"
    )

INT_MIN = 0x80000000


def _limbs(word: int) -> list[int]:
    return [(word >> (8 * index)) & 0xFF for index in range(4)]


def _signed(word: int) -> int:
    return word - (1 << 32) if word & INT_MIN else word

# --------------------------------------------------------------------------
# Family-agnostic schema audit of the whole export
# --------------------------------------------------------------------------


def audit_exported_families(air_ir_dir: Path) -> str:
    """Audit every exported family JSON against what this gate can evaluate.

    Family-agnostic on purpose: it reads whatever families the export
    contains, so a brand-new family, node operation, or lookup domain arriving
    in production fails here by name instead of being silently outside the
    witness gate's vocabulary. Three properties are enforced:

    * every node operation present is one the evaluator implements;
    * every lookup domain present is classified — range-checked via
      ``RANGE_DOMAINS`` or deliberately skipped via ``SKIPPED_DOMAINS``;
    * no lookup domain is silently ignored (the unknown-domain path raises).
    """
    paths = sorted(air_ir_dir.glob("*.json"))
    if not paths:
        raise WitnessError(
            f"no exported AIR families found in {air_ir_dir}; "
            f"re-derive the export with `{EXPORT_COMMAND}`"
        )
    range_checked: set[str] = set()
    skipped: set[str] = set()
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        family = payload.get("family", path.stem)
        operations = {node["op"] for node in payload["nodes"]}
        unsupported = operations - SUPPORTED_OPERATIONS
        if unsupported:
            raise WitnessError(
                f"family {family!r} uses node operations the evaluator does "
                f"not implement: {', '.join(sorted(unsupported))} (supported: "
                f"{', '.join(sorted(SUPPORTED_OPERATIONS))}). The evaluator "
                "in scripts/riscv_team_b_witnesses.py must learn them before "
                "any witness verdict on this family can be trusted."
            )
        for lookup in payload["lookups"]:
            domain = lookup["domain"]
            if domain in RANGE_DOMAINS:
                range_checked.add(domain)
            elif domain in SKIPPED_DOMAINS:
                skipped.add(domain)
            else:
                raise _unknown_domain_error(family, domain)
    return (
        f"schema audit: {len(paths)} exported families use only supported "
        f"node operations; {len(range_checked)} lookup domains range-checked, "
        f"{len(skipped)} deliberately skipped bus domains, none ignored"
    )


# --------------------------------------------------------------------------
# Export provenance: what exactly is this gate evaluating, and is it fresh?
# --------------------------------------------------------------------------


def export_digest(air_ir_dir: Path) -> str:
    """A single digest over every exported family, in name order."""
    paths = sorted(air_ir_dir.glob("*.json"))
    if not paths:
        raise WitnessError(
            f"no exported AIR families found in {air_ir_dir}; "
            f"re-derive the export with `{EXPORT_COMMAND}`"
        )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def check_export_provenance(
    air_ir_dir: Path, source_root: Path | None = None
) -> str:
    """Digest the export being evaluated and refuse a stale one.

    Every verdict this gate emits is a statement about the bytes in
    ``air_ir_dir``, not about the Zig source tree — so a stale local export
    would let every check pass against an AIR that no longer ships. Two
    defenses: the report always carries the export's digest (so a human can
    tie a log line to exact bytes), and any AIR source file newer than the
    export fails the gate with the re-derivation command.
    """
    digest = export_digest(air_ir_dir)
    paths = sorted(air_ir_dir.glob("*.json"))
    export_oldest = min(path.stat().st_mtime_ns for path in paths)

    root = AIR_SOURCE_ROOT if source_root is None else source_root
    if not root.is_dir():
        raise WitnessError(
            f"cannot establish export freshness: the AIR source tree is "
            f"absent at {root}. Run this gate from a checkout that contains "
            "the production AIR sources, or fix AIR_SOURCE_ROOT."
        )
    sources = list(root.rglob("*.zig"))
    if not sources:
        raise WitnessError(
            f"cannot establish export freshness: no Zig sources under {root}"
        )
    newest = max(sources, key=lambda path: path.stat().st_mtime_ns)
    if newest.stat().st_mtime_ns > export_oldest:
        raise WitnessError(
            f"the export in {air_ir_dir} is STALE: "
            f"{newest.relative_to(root)} is newer than the oldest exported "
            "family, so this gate would evaluate an AIR that may no longer "
            f"ship. Re-derive the export with `{EXPORT_COMMAND}`."
        )
    return (
        f"export provenance: {len(paths)} families, sha256 {digest[:16]}; "
        "no production AIR source is newer than the export"
    )
