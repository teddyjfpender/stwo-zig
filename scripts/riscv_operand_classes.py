#!/usr/bin/env python3
"""Sail-chosen operand classes for RV32IM coverage.

The coverage suites used to invent operand words one hand-picked probe at
a time. This tool derives the operand classes the ISA admits and the AIR's
structure distinguishes (`riscv_operand_classes_lib/classes.py` documents
the derivation), executes one concrete case per class on the pinned Sail
model over RVFI-DII, and commits Sail's architectural results as Zig data
under `src/tests/riscv/operand_class_corpus/` for guest-building tests to
consume. It also measures which of those classes an existing trace corpus
ever touches -- the untouched list is the actionable finding.

  python3 scripts/riscv_operand_classes.py list
  python3 scripts/riscv_operand_classes.py emit  [--output-dir DIR]
  python3 scripts/riscv_operand_classes.py check [--output-dir DIR]
  python3 scripts/riscv_operand_classes.py audit [--zig-bin BIN] [--elf E ...]

`emit` and `check` refuse to run without the pinned Sail binary (exit 3,
same contract as scripts/riscv_sail_oracle.py): expectations this tool
cannot source from Sail are not emitted at all, because a structurally
derived corpus presented as Sail-derived would be another self-referential
oracle. The Sail binary resolution order is riscv_sail_oracle's.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

if __package__:
    from scripts import riscv_sail_oracle as oracle
    from scripts.riscv_operand_classes_lib import audit, classes, emit
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import riscv_sail_oracle as oracle
    from riscv_operand_classes_lib import audit, classes, emit

ROOT = Path(__file__).resolve().parent.parent
EXIT_OK, EXIT_DRIFT, EXIT_ERROR, EXIT_UNAVAILABLE = 0, 1, 2, 3
DEFAULT_ZIG_BIN = ROOT / "zig-out" / "bin" / "riscv-trace-dump"


def cmd_list() -> int:
    cases = classes.all_cases()
    classes.validate_cases(cases)
    listing = [
        {
            "name": case.name,
            "op": case.op,
            "class": case.tag,
            "body_words": len(case.body),
            "under_test": case.under_test,
        }
        for case in cases
    ]
    print(json.dumps({
        "schema": "stwo-riscv-operand-class-listing-v1",
        "cases": listing,
        "case_count": len(listing),
        "pair_count": len({(case.op, case.tag) for case in cases}),
        "class_tags": list(classes.PREDICATES),
    }, indent=2))
    return EXIT_OK


def _resolve_or_unavailable() -> tuple[Path, dict[str, str]] | None:
    try:
        return emit.resolve()
    except oracle.SailUnavailable as error:
        print(f"UNAVAILABLE: {error}", file=sys.stderr)
        return None


def cmd_emit(output_dir: Path) -> int:
    resolved = _resolve_or_unavailable()
    if resolved is None:
        return EXIT_UNAVAILABLE
    sail_bin, identity = resolved
    counts = emit.emit(sail_bin, identity, output_dir)
    print(json.dumps({"written": {f"{name}.zig": count for name, count in counts.items()},
                      "output_dir": str(output_dir)}, indent=2))
    return EXIT_OK


def cmd_check(output_dir: Path) -> int:
    """Regenerate into a scratch directory and require byte identity with
    the committed corpus, so silent drift between the enumeration, the
    pinned Sail model, and the committed data cannot accumulate."""
    resolved = _resolve_or_unavailable()
    if resolved is None:
        return EXIT_UNAVAILABLE
    sail_bin, identity = resolved
    with tempfile.TemporaryDirectory() as scratch:
        fresh_dir = Path(scratch)
        emit.emit(sail_bin, identity, fresh_dir)
        drift = []
        for fresh in sorted(fresh_dir.glob("*.zig")):
            committed = output_dir / fresh.name
            if not committed.is_file():
                drift.append(f"{committed}: missing")
            elif committed.read_bytes() != fresh.read_bytes():
                drift.append(f"{committed}: differs from regeneration")
        for committed in sorted(output_dir.glob("*.zig")):
            if not (fresh_dir / committed.name).is_file():
                drift.append(f"{committed}: not produced by the generator")
    if drift:
        print("DRIFT:", file=sys.stderr)
        for line in drift:
            print(f"- {line}", file=sys.stderr)
        return EXIT_DRIFT
    print("operand-class corpus matches regeneration from pinned Sail")
    return EXIT_OK


def cmd_audit(zig_bin: Path, elf_paths: tuple[str, ...]) -> int:
    resolved = _resolve_or_unavailable()
    if resolved is None:
        return EXIT_UNAVAILABLE
    sail_bin, _ = resolved
    if not zig_bin.is_file():
        print(f"ERROR: trace-dump binary missing at {zig_bin}", file=sys.stderr)
        return EXIT_ERROR
    coverage, skipped = audit.audit_corpus(sail_bin, zig_bin, elf_paths)
    print(json.dumps(audit.report(coverage, skipped), indent=2))
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="print the enumeration as JSON, no Sail needed")
    for name in ("emit", "check"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--output-dir", type=Path,
                         default=ROOT / emit.DEFAULT_OUTPUT_DIR)
    audit_cmd = sub.add_parser("audit")
    audit_cmd.add_argument("--zig-bin", type=Path, default=DEFAULT_ZIG_BIN)
    audit_cmd.add_argument("--elf", action="append", default=None,
                           help="guest to audit (repeatable); default corpus otherwise")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "list":
        return cmd_list()
    if args.command == "emit":
        return cmd_emit(args.output_dir)
    if args.command == "check":
        return cmd_check(args.output_dir)
    elfs = tuple(args.elf) if args.elf else audit.DEFAULT_CORPUS
    return cmd_audit(args.zig_bin, elfs)


if __name__ == "__main__":
    raise SystemExit(main())
