#!/usr/bin/env python3
"""Machine-check the arithmetic used by the RISC-V cross-row clock lemmas.

This is not a LogUp verifier and it does not prove the opcode AIR.  It checks
the small integer facts on which the reviewed state-chain and offline-memory
arguments depend:

* a ``clock -> clock + 1`` state cycle over M31 needs exactly p edges;
* admitted execution geometry is far shorter than that cycle;
* the committed clock-update predecessor window keeps every possible emitted
  memory clock far below the field wrap;
* an opcode gap in ``[0, 2**20)`` between clocks in that window is therefore an
  ordinary non-negative integer gap, not a wrapped subtraction; and
* the old unbounded clock-update layout really did admit a 2,049-edge wrapped
  cycle, while the new predecessor decomposition rejects its eighteenth
  synthetic row.

The production-contract check pins those facts to the shipped Zig sources so a
constant or recurrence change makes this checker fail closed.

Run from the repository root:

    python3 -m scripts.riscv_state_chain_recurrence
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
from collections.abc import Sequence
from pathlib import Path


M31_MODULUS = (1 << 31) - 1
MAX_COMPONENTS = 256
MAX_OPCODE_SHARD_ROWS = 1 << 16
MAX_EXECUTION_STEPS = MAX_COMPONENTS * MAX_OPCODE_SHARD_ROWS
MAX_CLOCK_DIFF = (1 << 20) - 1
CLOCK_PREV_BOUND = 1 << 24


@dataclasses.dataclass(frozen=True)
class StateCycleCertificate:
    field_modulus: int
    state_clock_step: int
    minimum_positive_cycle_rows: int
    maximum_execution_rows: int
    public_initial_clock: int
    maximum_public_final_clock: int
    final_clock_is_canonical: bool
    detached_cycle_excluded: bool


@dataclasses.dataclass(frozen=True)
class ClockWindowCertificate:
    field_modulus: int
    maximum_clock_gap: int
    predecessor_bound_exclusive: int
    maximum_synthetic_predecessor: int
    maximum_synthetic_output: int
    minimum_wrapped_backward_gap: int
    wrapped_gap_exceeds_table: bool
    synthetic_addition_does_not_wrap: bool


@dataclasses.dataclass(frozen=True)
class WrappedCycleCounterexample:
    start_clock: int
    synthetic_rows: int
    synthetic_step: int
    endpoint_clock: int
    final_opcode_gap: int
    total_edges: int
    closes_mod_field: bool
    every_gap_was_in_old_window: bool
    first_rejected_row_zero_based: int
    first_rejected_predecessor: int


@dataclasses.dataclass(frozen=True)
class ProductionContract:
    m31_source: str
    state_relation_source: str
    admission_source: str
    clock_tracker_source: str
    clock_component_source: str
    clock_interaction_source: str
    source_modulus: int
    source_max_components: int
    source_shard_log_size: int
    source_clock_low_bits: int
    source_clock_high_bits: int
    state_recurrence: str
    opcode_gap_table: str
    clock_update_recurrence: str
    clock_predecessor_range: str


def additive_order(step: int, modulus: int) -> int:
    """Return the additive order of ``step`` modulo ``modulus``."""

    if modulus <= 1:
        raise ValueError("modulus must be greater than one")
    return modulus // math.gcd(step % modulus, modulus)


def state_cycle_certificate(
    modulus: int = M31_MODULUS,
    maximum_execution_rows: int = MAX_EXECUTION_STEPS,
) -> StateCycleCertificate:
    """Certify the ``+1`` state-clock walk and the admitted row bound."""

    order = additive_order(1, modulus)
    maximum_final = maximum_execution_rows + 1
    certificate = StateCycleCertificate(
        field_modulus=modulus,
        state_clock_step=1,
        minimum_positive_cycle_rows=order,
        maximum_execution_rows=maximum_execution_rows,
        public_initial_clock=1,
        maximum_public_final_clock=maximum_final,
        final_clock_is_canonical=maximum_final < modulus,
        detached_cycle_excluded=maximum_execution_rows < order,
    )
    if not certificate.final_clock_is_canonical:
        raise AssertionError("the public final clock can wrap M31")
    if not certificate.detached_cycle_excluded:
        raise AssertionError("admitted execution rows can contain a state cycle")
    return certificate


def clock_window_certificate(
    modulus: int = M31_MODULUS,
    maximum_clock_gap: int = MAX_CLOCK_DIFF,
    predecessor_bound_exclusive: int = CLOCK_PREV_BOUND,
) -> ClockWindowCertificate:
    """Certify that the committed predecessor range excludes field wrapping.

    A clock-update source is below ``B`` and emits ``source + D``.  Therefore
    every positive memory-bus clock is at most ``E = B - 1 + D``.  If two
    clocks in ``[0, E]`` are in decreasing integer order, their field
    subtraction is at least ``p - E``.  The production inequality
    ``p - E > D`` makes such a subtraction impossible to place in range20.
    """

    if predecessor_bound_exclusive <= 0 or maximum_clock_gap <= 0:
        raise ValueError("clock bounds must be positive")
    maximum_predecessor = predecessor_bound_exclusive - 1
    maximum_output = maximum_predecessor + maximum_clock_gap
    minimum_backward = modulus - maximum_output
    certificate = ClockWindowCertificate(
        field_modulus=modulus,
        maximum_clock_gap=maximum_clock_gap,
        predecessor_bound_exclusive=predecessor_bound_exclusive,
        maximum_synthetic_predecessor=maximum_predecessor,
        maximum_synthetic_output=maximum_output,
        minimum_wrapped_backward_gap=minimum_backward,
        wrapped_gap_exceeds_table=minimum_backward > maximum_clock_gap,
        synthetic_addition_does_not_wrap=maximum_output < modulus,
    )
    if not certificate.synthetic_addition_does_not_wrap:
        raise AssertionError("a bounded synthetic clock can wrap M31")
    if not certificate.wrapped_gap_exceeds_table:
        raise AssertionError("range20 still admits a backwards wrapped clock edge")
    return certificate


def bridge_clocks(previous: int, target: int, step: int = MAX_CLOCK_DIFF) -> tuple[int, ...]:
    """Return the synthetic outputs inserted before one real access."""

    if step <= 0:
        raise ValueError("step must be positive")
    if not 0 <= previous <= target:
        raise ValueError("clock bridge needs 0 <= previous <= target")
    outputs: list[int] = []
    current = previous
    while target - current > step:
        current += step
        outputs.append(current)
    return tuple(outputs)


def bridge_certificate(previous: int, target: int, step: int = MAX_CLOCK_DIFF) -> dict[str, int | bool]:
    """Check the exact bridge count and final residual gap."""

    outputs = bridge_clocks(previous, target, step)
    difference = target - previous
    expected_rows = 0 if difference <= step else (difference - 1) // step
    effective_previous = outputs[-1] if outputs else previous
    final_gap = target - effective_previous
    if len(outputs) != expected_rows:
        raise AssertionError("clock bridge row-count formula disagrees")
    if not 0 <= final_gap <= step:
        raise AssertionError("clock bridge left a gap outside range20")
    return {
        "previous": previous,
        "target": target,
        "synthetic_rows": len(outputs),
        "effective_previous": effective_previous,
        "final_gap": final_gap,
        "strictly_increasing": all(
            left < right
            for left, right in zip((previous, *outputs), outputs)
        ),
    }


def old_wrapped_cycle_counterexample(
    modulus: int = M31_MODULUS,
    step: int = MAX_CLOCK_DIFF,
    start: int = 1,
) -> WrappedCycleCounterexample:
    """Reproduce the shortest old ``+D`` chain that can close at ``start``.

    We choose the least positive number of synthetic rows for which the
    remaining field gap back to ``start`` is also in ``[0, D]``.
    """

    rows = next(
        count
        for count in range(1, modulus + 1)
        if 0 <= (start - (start + count * step)) % modulus <= step
    )
    endpoint = (start + rows * step) % modulus
    final_gap = (start - endpoint) % modulus
    first_rejected = next(
        index
        for index in range(rows)
        if (start + index * step) % modulus >= CLOCK_PREV_BOUND
    )
    first_rejected_predecessor = (start + first_rejected * step) % modulus
    certificate = WrappedCycleCounterexample(
        start_clock=start,
        synthetic_rows=rows,
        synthetic_step=step,
        endpoint_clock=endpoint,
        final_opcode_gap=final_gap,
        total_edges=rows + 1,
        closes_mod_field=(endpoint + final_gap) % modulus == start,
        every_gap_was_in_old_window=0 < step < (1 << 20) and 0 <= final_gap < (1 << 20),
        first_rejected_row_zero_based=first_rejected,
        first_rejected_predecessor=first_rejected_predecessor,
    )
    if not certificate.closes_mod_field or not certificate.every_gap_was_in_old_window:
        raise AssertionError("the old wrapped-cycle witness is not valid")
    if certificate.first_rejected_predecessor < CLOCK_PREV_BOUND:
        raise AssertionError("the new predecessor window did not reject the old cycle")
    return certificate


def _compact(source: str) -> str:
    return " ".join(source.split())


def _decimal_constant(source: str, name: str) -> int:
    match = re.search(
        rf"(?:pub )?const {re.escape(name)}(?:: [^=]+)?\s*=\s*([0-9]+)\s*;",
        source,
    )
    if match is None:
        raise AssertionError(f"could not locate production constant {name}")
    return int(match.group(1))


def check_production_contract(repo_root: Path) -> ProductionContract:
    """Bind the certificates to the exact shipped relations and guards."""

    m31_path = repo_root / "src/core/fields/m31.zig"
    common_path = repo_root / "src/frontends/riscv/air/semantics/common.zig"
    entry_path = repo_root / "src/frontends/riscv/air/lookups/entry.zig"
    admission_path = repo_root / "src/frontends/riscv/prover/statement_validation.zig"
    tracker_path = repo_root / "src/frontends/riscv/runner/state_chain.zig"
    component_path = repo_root / "src/frontends/riscv/air/clock_update_component.zig"
    interaction_path = repo_root / "src/frontends/riscv/air/clock_update_interaction.zig"

    m31_source = m31_path.read_text(encoding="utf-8")
    common_source = _compact(common_path.read_text(encoding="utf-8"))
    entry_source = _compact(entry_path.read_text(encoding="utf-8"))
    admission_source = _compact(admission_path.read_text(encoding="utf-8"))
    tracker_source = _compact(tracker_path.read_text(encoding="utf-8"))
    component_source = _compact(component_path.read_text(encoding="utf-8"))
    interaction_source = _compact(interaction_path.read_text(encoding="utf-8"))

    modulus_match = re.search(
        r"pub const Modulus:\s*u32\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;",
        m31_source,
    )
    if modulus_match is None:
        raise AssertionError("could not locate the production M31 modulus")
    source_modulus = int(modulus_match.group(1), 0)

    statement_path = repo_root / "src/frontends/riscv/air/statement.zig"
    statement_source = statement_path.read_text(encoding="utf-8")
    source_max_components = _decimal_constant(statement_source, "MAX_COMPONENTS")
    source_shard_log_size = _decimal_constant(
        admission_path.read_text(encoding="utf-8"),
        "MAX_OPCODE_SHARD_LOG_SIZE",
    )
    source_clock_low_bits = _decimal_constant(
        tracker_path.read_text(encoding="utf-8"),
        "CLOCK_PREV_LOW_BITS",
    )
    source_clock_high_bits = _decimal_constant(
        tracker_path.read_text(encoding="utf-8"),
        "CLOCK_PREV_HIGH_BITS",
    )

    if source_modulus != M31_MODULUS:
        raise AssertionError("checker modulus drifted from production")
    if source_max_components != MAX_COMPONENTS or source_shard_log_size != 16:
        raise AssertionError("execution-capacity constants drifted from production")
    if (source_clock_low_bits, source_clock_high_bits) != (20, 4):
        raise AssertionError("clock predecessor decomposition drifted")

    required = {
        "state +1 recurrence": (
            common_source,
            ".next = .{ .pc = pc.add(q(4)), .clock = clock.add(S.one()) },",
        ),
        "opcode memory gap lookup": (
            entry_source,
            "Self.range20(list, enabler.neg(), chain.clock_gap);",
        ),
        "execution field-cycle guard": (
            admission_source,
            "if (total_steps >= m31.Modulus - 1) return types.ProverError.InvalidStatement;",
        ),
        "execution geometry sum": (
            admission_source,
            "if (total_rows != statement.total_steps) return types.ProverError.InvalidStatement;",
        ),
        "clock bridge loop": (
            tracker_source,
            "while (clk -| current > MAX_CLOCK_DIFF) { const next = current + MAX_CLOCK_DIFF;",
        ),
        "clock low range": (
            interaction_source,
            "entry.range20(&result, row.enabler.neg(), row.clock_prev_low20);",
        ),
        "clock high range": (
            interaction_source,
            ".{ QM31.zero(), QM31.zero(), row.clock_prev_high4 },",
        ),
        "clock recomposition": (
            component_source,
            "row.clock_prev_low20.add( row.clock_prev_high4.mul(",
        ),
    }
    for label, (source, fragment) in required.items():
        if fragment not in source:
            raise AssertionError(f"production contract changed: {label}")

    if MAX_EXECUTION_STEPS != source_max_components * (1 << source_shard_log_size):
        raise AssertionError("checker execution bound disagrees with production geometry")
    if CLOCK_PREV_BOUND != 1 << (source_clock_low_bits + source_clock_high_bits):
        raise AssertionError("checker clock bound disagrees with production decomposition")

    return ProductionContract(
        m31_source=str(m31_path.relative_to(repo_root)),
        state_relation_source=str(common_path.relative_to(repo_root)),
        admission_source=str(admission_path.relative_to(repo_root)),
        clock_tracker_source=str(tracker_path.relative_to(repo_root)),
        clock_component_source=str(component_path.relative_to(repo_root)),
        clock_interaction_source=str(interaction_path.relative_to(repo_root)),
        source_modulus=source_modulus,
        source_max_components=source_max_components,
        source_shard_log_size=source_shard_log_size,
        source_clock_low_bits=source_clock_low_bits,
        source_clock_high_bits=source_clock_high_bits,
        state_recurrence="(pc, clock) -> (next_pc, clock + 1)",
        opcode_gap_table="range_check_20(row_clock - previous_clock)",
        clock_update_recurrence="clock -> clock + (2^20 - 1)",
        clock_predecessor_range="0 <= clock_prev < 2^24",
    )


def report(repo_root: Path) -> dict[str, object]:
    return {
        "schema": "stwo-riscv-state-chain-recurrence-v1",
        "state_cycle": dataclasses.asdict(state_cycle_certificate()),
        "clock_window": dataclasses.asdict(clock_window_certificate()),
        "maximum_honest_bridge": bridge_certificate(0, MAX_EXECUTION_STEPS),
        "old_wrapped_cycle": dataclasses.asdict(old_wrapped_cycle_counterexample()),
        "production_contract": dataclasses.asdict(check_production_contract(repo_root)),
        "scope": {
            "proves": (
                "field-cycle and integer-window arithmetic used by the reviewed "
                "state-chain and memory-chain lemmas"
            ),
            "does_not_prove": (
                "LogUp multiset equality, opcode row semantics, same-clock "
                "access ordering, PCS/FRI soundness, or Sail refinement"
            ),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    print(json.dumps(report(args.repo_root.resolve()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
