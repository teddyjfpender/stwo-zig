"""In-process and isolated-process runners for emitted SMT-LIB queries."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from .result import Result, Witness
from .smtlib import Query

try:
    from riscv_air_ir_lib.ir import MODULUS
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_lib in tests.
    from scripts.riscv_air_ir_lib.ir import MODULUS


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
    if query.weakened:
        result.status = "unknown"
        result.reason_unknown = (
            "proof-only weakened shard is satisfiable; dropped AIR lookups make "
            "that model inconclusive"
        )
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
        for name, factor in query.eliminated.items():
            decoded.witness[name] = _solve_linear(query.nodes, factor, name, decoded)
        result.witnesses[copy] = decoded

    if len(query.copies) >= 2:  # The satisfiability probe emits a single copy.
        first, second = query.copies[0], query.copies[1]

        def value(copy: str, name: str) -> int:
            side = query.columns[name]
            witness = result.witnesses[copy]
            return getattr(witness, "witness" if side == "witness" else f"{side}s")[
                name
            ]

        result.differing_outputs = tuple(
            name
            for name in query.conclusion
            if value(first, name) != value(second, name)
        )
    return result


def run_query_fresh(query: Query, timeout_ms: int = 0) -> Result:
    """Decide one proof shard in a disposable Python/Z3 process.

    Long nonlinear queries measurably degrade later queries when solver use is
    kept in one process, while the same later shards finish quickly in a clean
    process. A reported external 529/worker exit carries no Z3 proof verdict.
    A proof shard needs only a verdict, so process isolation is the exact
    lifecycle boundary: no solver state crosses from one logical query to the
    next.

    Any abnormal worker exit, malformed reply, or outer wall timeout is
    `unknown`, never `unsat`.  This is important: isolation improves liveness
    but cannot manufacture proof evidence.
    """
    helper = Path(__file__).with_name("fresh_solver.py")
    started = time.perf_counter()
    deadline = None if timeout_ms == 0 else started + timeout_ms / 1000 + 5.0
    active: list[subprocess.Popen[str]] = []
    results: list[Result] = []
    try:
        for seed in (0, 17, 31):
            process = subprocess.Popen(
                [sys.executable, str(helper), str(timeout_ms), str(seed)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            active.append(process)
            assert process.stdin is not None
            process.stdin.write(query.text)
            process.stdin.close()
            process.stdin = None
        while active:
            for process in list(active):
                returncode = process.poll()
                if returncode is None:
                    continue
                active.remove(process)
                stdout, stderr = process.communicate()
                result = _fresh_result(query, returncode, stdout, stderr)
                results.append(result)
                if result.status in ("unsat", "sat"):
                    return result
            if deadline is not None and time.perf_counter() >= deadline:
                break
            time.sleep(0.01)
    finally:
        for process in active:
            process.terminate()
        for process in active:
            try:
                process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
    if not results:
        return Result(
            family=query.family,
            status="unknown",
            seconds=time.perf_counter() - started,
            reason_unknown="isolated solver portfolio exceeded its outer wall timeout",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    chosen = results[0]
    chosen.seconds = time.perf_counter() - started
    chosen.reason_unknown = "; ".join(
        sorted({result.reason_unknown for result in results if result.reason_unknown})
    )
    return chosen


def _fresh_result(
    query: Query, returncode: int, stdout: str, stderr: str
) -> Result:
    """Decode one isolated worker without promoting process failure to proof."""
    if returncode != 0:
        diagnostic = (stderr or stdout).strip().splitlines()
        detail = diagnostic[-1] if diagnostic else "no diagnostic"
        return Result(
            family=query.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=f"isolated solver exited with status {returncode}: {detail}",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    try:
        payload = json.loads(stdout)
        status = payload["status"]
        if status not in ("sat", "unsat", "unknown"):
            raise ValueError(f"invalid status {status!r}")
        seconds = float(payload["seconds"])
        reason_unknown = str(payload.get("reason_unknown", ""))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        return Result(
            family=query.family,
            status="unknown",
            seconds=0.0,
            reason_unknown=f"isolated solver returned a malformed reply: {error}",
            modelled_lookups=query.modelled_lookups,
            skipped_bus_lookups=query.skipped_bus_lookups,
        )
    if status == "sat" and query.weakened:
        status = "unknown"
        reason_unknown = (
            "proof-only weakened shard is satisfiable; dropped AIR lookups make "
            "that model inconclusive"
        )
    return Result(
        family=query.family,
        status=status,
        seconds=seconds,
        reason_unknown=reason_unknown,
        modelled_lookups=query.modelled_lookups,
        skipped_bus_lookups=query.skipped_bus_lookups,
    )


def _solve_linear(nodes: tuple, factor: int, column: str, decoded: Witness) -> int:
    """The value the projected witness must take for `factor` to vanish.

    The emitter replaced this factor with its solvability condition (see
    `eliminable_inverses`), so the model carries no value for `column`; the
    factor is linear in it, so evaluating at 0 and 1 recovers offset and slope
    and one field division re-solves it.  Zero slope means the factor vanishes
    for no choice or every choice -- either way the model satisfied some other
    factor of the constraint, and any in-range value serves; 0 is one.
    """
    assignment = {**decoded.inputs, **decoded.outputs, **decoded.witness}
    at_zero = _eval_node(nodes, factor, {**assignment, column: 0})
    slope = (_eval_node(nodes, factor, {**assignment, column: 1}) - at_zero) % MODULUS
    if slope == 0:
        return 0
    return -at_zero * pow(slope, MODULUS - 2, MODULUS) % MODULUS


def _eval_node(nodes: tuple, root: int, assignment: dict[str, int]) -> int:
    """Field value of one DAG node under a full column assignment."""
    values: dict[int, int] = {}
    for index in range(root + 1):
        node = nodes[index]
        if node.op == "const":
            values[index] = node.value % MODULUS
        elif node.op == "col":
            values[index] = assignment[node.name] % MODULUS
        elif node.op == "neg":
            values[index] = -values[node.args[0]] % MODULUS
        else:
            lhs, rhs = values[node.args[0]], values[node.args[1]]
            op = {"add": lhs + rhs, "sub": lhs - rhs, "mul": lhs * rhs}[node.op]
            values[index] = op % MODULUS
    return values[root]
