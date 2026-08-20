"""Shared parsing, rendering, and CLI helpers for the Team A gate."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    from .riscv_team_a_constants import TeamAError
except ImportError:
    from riscv_team_a_constants import TeamAError


def assigned_opcodes(
    shared: Any,
    families: tuple[str, ...],
    expected_count: int,
) -> list[tuple[str, str, int]]:
    """Project Team A's exact family assignment from the shared manifest."""

    try:
        entries = shared.manifest_opcodes()
    except shared.TeamBError as exc:
        raise TeamAError(str(exc)) from exc
    selected = [entry for entry in entries if entry[1] in families]
    if len(selected) != expected_count:
        raise TeamAError(
            f"Team A families cover {len(selected)} opcodes, expected {expected_count}"
        )
    observed = {family for _, family, _ in selected}
    if observed != set(families):
        raise TeamAError(
            "Team A family assignment drifted; missing "
            + ", ".join(sorted(set(families) - observed))
        )
    return selected


def parse_audit_output(path: Path) -> dict[str, list[str]]:
    try:
        output = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TeamAError(
            f"axiom audit transcript is unreadable at {path}"
        ) from exc
    theorem_pattern = re.compile(
        r"^REFINEMENT_THEOREM (?P<theorem>RiscvRefinement\.\S+)$"
    )
    axiom_pattern = re.compile(
        r"^REFINEMENT_AXIOM "
        r"(?P<theorem>RiscvRefinement\.\S+) "
        r"(?P<axiom>\S+)$"
    )
    report: dict[str, list[str]] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        theorem_match = theorem_pattern.fullmatch(line)
        if theorem_match is not None:
            theorem = theorem_match.group("theorem")
            if theorem in report:
                raise TeamAError(
                    f"axiom audit repeated theorem record {theorem}"
                )
            report[theorem] = []
            continue
        axiom_match = axiom_pattern.fullmatch(line)
        if axiom_match is None:
            continue
        theorem = axiom_match.group("theorem")
        axiom = axiom_match.group("axiom")
        if theorem not in report:
            raise TeamAError(
                f"axiom audit records {axiom} before theorem {theorem}"
            )
        if axiom in report[theorem]:
            raise TeamAError(
                f"axiom audit repeats {axiom} for {theorem}"
            )
        report[theorem].append(axiom)
    if not report:
        raise TeamAError("axiom audit transcript contains no theorem records")
    return report


def check_raw_column_models(
    lean_root: Path,
    raw_column_models: dict[str, dict[str, Any]],
) -> str:
    """Reject canonical-by-construction production column models."""

    checked = 0
    for relative, contract in raw_column_models.items():
        path = lean_root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise TeamAError(
                f"raw-column model is unreadable at {relative}"
            ) from exc
        blocks = re.findall(
            r"\ndef columns\b.*?(?=\ndef evaluation\b)",
            source,
            flags=re.DOTALL,
        )
        if len(blocks) != contract["blocks"]:
            raise TeamAError(
                f"{relative} exposes {len(blocks)} column models, expected "
                f"{contract['blocks']}"
            )
        for block in blocks:
            for token in contract["forbidden"]:
                if token in block:
                    raise TeamAError(
                        f"{relative} constructs a production column from "
                        f"architectural helper {token!r}; model the raw "
                        "column and derive it from Acceptance instead"
                    )
        admission_forbidden = contract.get("admission_forbidden", ())
        if admission_forbidden:
            admission_blocks = re.findall(
                r"\nstructure Admission\b.*?(?=\ndef \w)",
                source,
                flags=re.DOTALL,
            )
            if len(admission_blocks) != 1:
                raise TeamAError(
                    f"{relative} exposes {len(admission_blocks)} Admission "
                    "models, expected 1"
                )
            for token in admission_forbidden:
                if token in admission_blocks[0]:
                    raise TeamAError(
                        f"{relative} assumes witness/output fact {token!r} "
                        "in Admission; derive it from Acceptance instead"
                    )
        checked += len(blocks)
    return (
        f"team A raw-column guard: {checked} high-risk family models do not "
        "bake architectural outputs into production columns"
    )


def render_inventory(
    entries: list[tuple[str, str, int]],
    certificates: dict[str, dict[str, Any]],
) -> str:
    rows = [("id", "mnemonic", "family", "Sail", "mutation")]
    for mnemonic, family, manifest_id in entries:
        certificate = certificates[mnemonic]
        rows.append(
            (
                str(manifest_id),
                mnemonic,
                family,
                certificate["sail_binding"],
                certificate["mutation"],
            )
        )
    widths = [
        max(len(row[index]) for row in rows)
        for index in range(len(rows[0]))
    ]
    return "\n".join(
        "  ".join(
            value.ljust(width)
            for value, width in zip(row, widths)
        ).rstrip()
        for row in rows
    )


def run_cli(
    argv: list[str] | None,
    api: Any,
    description: str | None,
) -> int:
    """Run the public CLI against the facade module's live bindings."""

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "command",
        choices=(
            "write",
            "coverage",
            "air-programs",
            "theorems",
            "axioms",
            "raw-columns",
            "inventory",
            "check",
        ),
    )
    parser.add_argument(
        "--audit-output",
        type=Path,
        help="Lean AxiomAudit transcript, required by the axioms command",
    )
    parser.add_argument(
        "--air-program-ir-dir",
        type=Path,
        help=(
            "exact fresh 46-file unsigned production AIR IR v2 export, "
            "consumed by air-programs or check"
        ),
    )
    args = parser.parse_args(argv)
    try:
        if (
            args.air_program_ir_dir is not None
            and args.command not in ("air-programs", "check")
        ):
            raise api.TeamAError(
                "--air-program-ir-dir is only valid with air-programs or check"
            )
        if args.command == "write":
            if args.audit_output is None:
                raise api.TeamAError("write requires --audit-output")
            print(api.write_index(args.audit_output))
        elif args.command == "coverage":
            print(api.check_coverage())
        elif args.command == "air-programs":
            print(api.check_air_programs(args.air_program_ir_dir))
        elif args.command == "theorems":
            print(api.check_theorems())
        elif args.command == "axioms":
            if args.audit_output is None:
                raise api.TeamAError("axioms requires --audit-output")
            print(
                api.check_axiom_bindings(
                    api.parse_audit_output(args.audit_output)
                )
            )
        elif args.command == "raw-columns":
            print(api.check_raw_column_models())
        elif args.command == "inventory":
            print(api.inventory())
        else:
            print(api.check_coverage())
            print(api.check_air_programs(args.air_program_ir_dir))
            print(api.check_theorems())
            print(api.check_raw_column_models())
    except api.TeamAError as exc:
        print(f"team A gate failed: {exc}", file=sys.stderr)
        return 1
    return 0
