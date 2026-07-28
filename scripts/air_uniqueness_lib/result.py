"""Result models, counterexample records, and human-readable reporting."""

from __future__ import annotations

from dataclasses import dataclass, field

from .smtlib import COPIES

try:
    from riscv_air_ir_lib.ir import System
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_lib in tests.
    from scripts.riscv_air_ir_lib.ir import System


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
    # Which sub-query this is, or which sub-queries an aggregate covers.
    shard: str = "monolithic"
    open_shards: tuple[str, ...] = ()

    @property
    def unique(self) -> bool:
        return self.status == "unsat"

    @property
    def vacuous(self) -> bool:
        """Unique only because nothing satisfies the constraints at all."""
        return self.unique and self.constraints_satisfiable is False


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
        elif result.constraints_satisfiable is None:
            lines.append(
                "the honest-witness probe did not finish, so this unsat is not "
                "yet known to be non-vacuous."
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

    lines.append(f"differing outputs     : {', '.join(result.differing_outputs)}")
    return "\n".join(lines + _format_counterexample(result))


def _format_counterexample(result: Result) -> list[str]:
    """The witness pair, side by side, with the disagreements marked."""
    first, second = COPIES
    lines = ["", "shared architectural inputs:"]
    lines += [
        f"  {name:<24} {value}"
        for name, value in sorted(result.witnesses[first].inputs.items())
    ]
    header = f"  {'column':<24} {'copy ' + first:>12} {'copy ' + second:>12}"
    for title, side in (
        ("witness columns (free prover choice)", "witness"),
        ("architectural outputs", "outputs"),
    ):
        lines += ["", f"{title}:", header]
        left_side = getattr(result.witnesses[first], side)
        right_side = getattr(result.witnesses[second], side)
        for name in sorted(left_side):
            left, right = left_side[name], right_side[name]
            marker = "  <-- differs" if left != right else ""
            lines.append(f"  {name:<24} {left:>12} {right:>12}{marker}")
    return lines
