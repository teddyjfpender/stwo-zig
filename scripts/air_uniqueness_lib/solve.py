"""z3 runner over the emitted SMT-LIB2 text, with counterexample decoding.

The solver is fed the emitted text rather than a parallel z3-API construction,
so the artifact a reviewer reads is the artifact that was checked.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .ir import System
from .smtlib import (
    COPIES,
    Query,
    emit_satisfiability_query,
    emit_uniqueness_query,
)


@dataclass
class Witness:
    """One decoded side of a counterexample, as field elements per column."""

    inputs: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, int] = field(default_factory=dict)
    witness: dict[str, int] = field(default_factory=dict)


@dataclass
class Result:
    family: str
    status: str  # "sat" | "unsat" | "unknown" | "skipped"
    seconds: float
    witnesses: dict[str, Witness] = field(default_factory=dict)
    differing_outputs: tuple[str, ...] = ()
    reason_unknown: str = ""
    modelled_lookups: tuple[str, ...] = ()
    skipped_bus_lookups: tuple[str, ...] = ()
    # None when the vacuity probe was not run; see `emit_satisfiability_query`.
    constraints_satisfiable: bool | None = None
    # Non-empty exactly when `status == "skipped"`.
    skip_reason: str = ""

    @property
    def unique(self) -> bool:
        return self.status == "unsat"

    @property
    def vacuous(self) -> bool:
        """Unique only because nothing satisfies the constraints at all."""
        return self.unique and self.constraints_satisfiable is False


def check(
    system: System,
    timeout_ms: int = 0,
    refine: bool = True,
    assume_domains: bool = False,
) -> Result:
    """Run the uniqueness query.  `sat` is a real under-constraint witness pair;
    see `air_uniqueness.py explain` for what `unsat` does not mean.

    A family the query cannot say anything about returns `skipped` with the
    reason, never a verdict.  A fabricated `unsat` on such a family is worse
    than no row on the board, because the board is read as coverage.
    """
    reason = system.uniqueness_skip_reason()
    if reason is not None:
        return Result(
            family=system.family, status="skipped", seconds=0.0, skip_reason=reason
        )
    result = run_query(
        emit_uniqueness_query(system, refine=refine, assume_domains=assume_domains),
        timeout_ms,
    )
    if result.unique:
        probe = run_query(
            emit_satisfiability_query(
                system, refine=refine, assume_domains=assume_domains
            ),
            timeout_ms,
        )
        result.constraints_satisfiable = probe.status == "sat"
    return result


def run_query(query: Query, timeout_ms: int = 0) -> Result:
    import z3  # Imported lazily: emitting SMT-LIB must not require the bindings.

    solver = z3.Solver()
    if timeout_ms:
        solver.set("timeout", timeout_ms)
    solver.add(z3.parse_smt2_string(query.text))

    started = time.perf_counter()
    verdict = solver.check()
    seconds = time.perf_counter() - started

    if verdict == z3.sat:
        status = "sat"
    elif verdict == z3.unsat:
        status = "unsat"
    else:
        status = "unknown"

    result = Result(
        family=query.family,
        status=status,
        seconds=seconds,
        modelled_lookups=query.modelled_lookups,
        skipped_bus_lookups=query.skipped_bus_lookups,
    )
    if result.status == "unknown":
        result.reason_unknown = solver.reason_unknown()
        return result
    if result.status == "unsat":
        return result

    model = solver.model()
    values = {
        declaration.name(): model[declaration].as_long()
        for declaration in model.decls()
        if z3.is_int_value(model[declaration])
    }
    for copy in query.copies:
        decoded = Witness()
        for name, role in query.columns.items():
            value = values.get(query.var(name, copy))
            if value is None:
                # z3 leaves don't-care constants out of the model; any value
                # works, and 0 is in range for every column.
                value = 0
            getattr(decoded, "witness" if role == "witness" else f"{role}s")[
                name
            ] = value
        result.witnesses[copy] = decoded

    if len(query.copies) >= 2:  # The satisfiability probe emits a single copy.
        first, second = query.copies[0], query.copies[1]
        result.differing_outputs = tuple(
            name
            for name, role in query.columns.items()
            if role == "output"
            and result.witnesses[first].outputs[name]
            != result.witnesses[second].outputs[name]
        )
    return result


def counterexample_payload(system: System, result: Result) -> dict[str, object]:
    """A `sat` model as a self-contained malicious-witness record.

    Both sides satisfy every constraint and every modelled table membership, so
    each is a valid witness in isolation; what the pair demonstrates is that the
    family admits two of them for one architectural input.  That makes the
    record directly usable as a mutation-corpus seed rather than only a report.
    """
    if result.status != "sat":
        raise ValueError(f"no counterexample to export: verdict is {result.status}")
    first, second = COPIES
    return {
        "family": system.family,
        "kind": "per_row_witness_uniqueness_counterexample",
        "differing_outputs": list(result.differing_outputs),
        "shared_inputs": dict(sorted(result.witnesses[first].inputs.items())),
        "witnesses": {
            copy: {
                "witness": dict(sorted(result.witnesses[copy].witness.items())),
                "outputs": dict(sorted(result.witnesses[copy].outputs.items())),
            }
            for copy in (first, second)
        },
        "unmodelled_bus_lookups": list(result.skipped_bus_lookups),
    }


def format_result(result: Result) -> str:
    if result.status == "skipped":
        return "\n".join(
            [
                f"family                : {result.family}",
                "verdict               : skipped",
                f"reason                : {result.skip_reason}",
            ]
        )
    lines = [
        f"family                : {result.family}",
        f"verdict               : {result.status}",
        f"solver wall clock     : {result.seconds:.3f}s",
        f"table lookups modelled: {len(result.modelled_lookups)}",
        f"bus lookups ignored   : {len(result.skipped_bus_lookups)}"
        + (
            f" ({', '.join(result.skipped_bus_lookups)})"
            if result.skipped_bus_lookups
            else ""
        ),
    ]
    if result.status == "unsat":
        lines.append(f"constraints satisfiable: {result.constraints_satisfiable}")
        if result.vacuous:
            lines.append(
                "VACUOUS: nothing satisfies the constraints, so uniqueness is "
                "empty. Fix the model before reading this as evidence."
            )
        else:
            lines.append(
                "outputs are a function of the inputs, under the assumptions "
                "in `air_uniqueness.py explain`."
            )
        return "\n".join(lines)
    if result.status == "unknown":
        lines.append(f"reason unknown        : {result.reason_unknown}")
        return "\n".join(lines)

    first, second = COPIES
    lines.append(f"differing outputs     : {', '.join(result.differing_outputs)}")
    lines.append("")
    lines.append("shared architectural inputs:")
    for name, value in sorted(result.witnesses[first].inputs.items()):
        lines.append(f"  {name:<24} {value}")
    lines.append("")
    header = f"  {'column':<24} {'copy ' + first:>12} {'copy ' + second:>12}"
    lines.append("witness columns (free prover choice):")
    lines.append(header)
    for name in sorted(result.witnesses[first].witness):
        left = result.witnesses[first].witness[name]
        right = result.witnesses[second].witness[name]
        marker = "  <-- differs" if left != right else ""
        lines.append(f"  {name:<24} {left:>12} {right:>12}{marker}")
    lines.append("")
    lines.append("architectural outputs:")
    lines.append(header)
    for name in sorted(result.witnesses[first].outputs):
        left = result.witnesses[first].outputs[name]
        right = result.witnesses[second].outputs[name]
        marker = "  <-- differs" if left != right else ""
        lines.append(f"  {name:<24} {left:>12} {right:>12}{marker}")
    return "\n".join(lines)
