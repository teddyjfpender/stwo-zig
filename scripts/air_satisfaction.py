#!/usr/bin/env python3
"""Independent row-satisfaction and LogUp-closure checker for exported RISC-V
proving runs.

WHAT THIS CHECKS INDEPENDENTLY
------------------------------
Given a committed opcode trace exported from a real proving run, plus the
extracted per-family constraint IR, it re-decides in Python:

  1. the committed-row placement permutation — the export is in committed
     (circle-domain, bit-reversed) order and this reader undoes it itself;
  2. every direct constraint of every real opcode row, over M31;
  3. every activated preprocessed-table request of those rows: the box tables
     and the functional `bitwise` table;
  4. every opcode component's claimed LogUp sum, recomputed from the committed
     trace and the exported challenges rather than read from the prover;
  5. the verifier's public boundary compensation, as a second implementation of
     `air/public_logup.zig`;
  6. the global LogUp cancellation: (4) + the exported infrastructure claims +
     (5) must be zero.

It shares no code with the Zig evaluator. A bug in Zig's row evaluation loop,
its committed-row placement, its column offsets, or its public-boundary
arithmetic cannot hide in both.

WHAT THIS DOES NOT CHECK
------------------------
This is NOT a verifier and must not be read as one. Everything below is out of
scope, and a green result says nothing about any of it:

  * the proof wire — PCS commitments, Merkle openings, FRI, the composition
    polynomial, the out-of-domain sampling, and the Fiat-Shamir transcript are
    never touched. Nothing here reads the proof;
  * the binding between the export and the proof. The export is taken from the
    prover's committed buffers at the point they are handed to the commitment
    scheme, which is a code-level identity (see `prover/test_trace_dump.zig`),
    not a cryptographic one. This checker cannot tell that the values it read
    are the values the proof opens;
  * infrastructure components. Program, RW-memory, Merkle, Poseidon2, clock
    update and the six lookup tables have their claimed sums TAKEN AS GIVEN from
    the export. Their internal constraints and their multiplicity columns are
    not re-decided, so a closure failure attributes to "the opcode side and the
    boundary agree, the ledger does not" and no further;
  * padding rows. The extracted IR fixes the preprocessed `is_active` selector
    to one, so it is the active-row system; what the AIR requires of padding
    rows is decided in Zig;
  * the bus relations. `registers_state`, `memory_access`, `program_access`,
    `merkle`, `poseidon2` and `poseidon2_io` are multiset buses closed across
    rows and components. Their tuples enter (4) and (6) but are never decided
    row-locally, because a per-row query cannot decide them;
  * whether the extracted IR is the shipped AIR. That is established separately,
    by the fixed-seed extraction differential in
    `src/tests/riscv/uniqueness_ir_test.zig`. Without it, this checker would be
    comparing a trace against a model of unknown provenance.

Usage
-----
    python3 -m scripts.air_satisfaction explain
    python3 -m scripts.air_satisfaction check [--dump PATH] [--ir DIR]
        [--max-report N]

`check` exits 0 when every row is satisfied and the ledger closes, and 1
otherwise. Inputs are produced by
`src/tests/riscv/committed_trace_export_test.zig` (`zig-out/committed-trace/`)
and `src/tests/riscv/uniqueness_ir_test.zig` (`zig-out/uniqueness-ir/`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from air_satisfaction_lib import dump as dump_mod
    from air_satisfaction_lib import logup, rows
    from air_uniqueness_lib import ir
except ModuleNotFoundError:  # Imported as scripts.air_satisfaction in tests.
    from scripts.air_satisfaction_lib import dump as dump_mod
    from scripts.air_satisfaction_lib import logup, rows
    from scripts.air_uniqueness_lib import ir

DEFAULT_DUMP = Path("zig-out/committed-trace/honest.json")
DEFAULT_IR = Path("zig-out/uniqueness-ir")


class Report:
    """Everything one run of `check` concluded, so a caller can assert on it."""

    def __init__(self) -> None:
        self.violations: list[rows.Violation] = []
        self.counts: dict[str, rows.Counts] = {}
        self.closure: logup.Closure | None = None
        self.unsupported: str | None = None

    def satisfied(self) -> bool:
        return not self.violations

    def closed(self) -> bool:
        return self.closure is not None and self.closure.is_closed()

    def ok(self) -> bool:
        return self.satisfied() and self.closed() and self.unsupported is None


def load_systems(directory: Path, families: set[str]) -> dict[str, "ir.System"]:
    systems: dict[str, "ir.System"] = {}
    for family in sorted(families):
        path = directory / f"{family}.json"
        if not path.exists():
            raise FileNotFoundError(
                f"{path} is missing; run the 'uniqueness IR: emit every family' test"
            )
        systems[family] = ir.load(path)
    return systems


def check(dump_path: Path, ir_dir: Path) -> Report:
    exported = dump_mod.load(dump_path)
    systems = load_systems(ir_dir, {c.family for c in exported.components})
    report = Report()
    # Bind every component to its system before deciding any of them: a layout
    # mismatch anywhere means the whole run was read against the wrong AIR, and
    # a partial report of that is worse than none.
    prepared = {
        component.index: rows.prepare(systems[component.family], component)
        for component in exported.components
    }
    for component in exported.components:
        violations, counts = rows.check_component(prepared[component.index])
        report.violations.extend(violations)
        report.counts[f"{component.family}[{component.index}]"] = counts
    try:
        report.closure = logup.closure(exported, prepared)
    except logup.UnsupportedStatement as error:
        report.unsupported = str(error)
    return report


def render(report: Report, dump_path: Path, max_report: int) -> str:
    lines = [f"dump: {dump_path}", ""]
    header = f"{'component':<20}{'rows':>6}{'constraints':>13}{'skipped':>9}"
    lines.append(header + f"{'box':>7}{'bitwise':>9}{'bus':>7}")
    for label, counts in report.counts.items():
        lines.append(
            f"{label:<20}{counts.rows:>6}{counts.constraints:>13}"
            f"{counts.skipped_constraints:>9}"
            f"{counts.box_requests:>7}{counts.bitwise_requests:>9}{counts.bus_requests:>7}"
        )
    lines.append("")
    if report.violations:
        lines.append(f"ROW VIOLATIONS: {len(report.violations)}")
        for violation in report.violations[:max_report]:
            lines.append(f"  {violation}")
        if len(report.violations) > max_report:
            lines.append(f"  ... {len(report.violations) - max_report} more")
    else:
        lines.append("rows: every real row satisfies every constraint and every table request")
    lines.append("")
    if report.unsupported is not None:
        lines.append(f"LOGUP CLOSURE: not attempted — {report.unsupported}")
        return "\n".join(lines)

    closure = report.closure
    assert closure is not None
    for family, index, claimed, recomputed in closure.recomputed_opcode:
        verdict = "agrees" if claimed.as_tuple() == recomputed.as_tuple() else "DIFFERS"
        lines.append(f"  claim {family}[{index}]: recomputed from the trace {verdict}")
    lines.append(f"  infrastructure claims (taken as given): {closure.infra_total.as_tuple()}")
    lines.append(f"  public boundary (recomputed):           {closure.boundary.as_tuple()}")
    lines.append(f"  global sum:                             {closure.total.as_tuple()}")
    for message in closure.disagreeing_claims():
        lines.append(f"  CLAIM MISMATCH: {message}")
    lines.append(
        "  LOGUP CLOSURE: closed" if closure.is_closed() else "  LOGUP CLOSURE: NOT CLOSED"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("explain", help="print the scope statement above")
    checker = subparsers.add_parser("check", help="decide one exported run")
    checker.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    checker.add_argument("--ir", type=Path, default=DEFAULT_IR)
    checker.add_argument("--max-report", type=int, default=20)
    args = parser.parse_args(argv)

    if args.command == "explain":
        print(__doc__)
        return 0

    report = check(args.dump, args.ir)
    print(render(report, args.dump, args.max_report))
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
