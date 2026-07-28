"""One-shot Z3 worker for proof shards.

The parent process sends one SMT-LIB query on stdin and receives one small JSON
verdict on stdout.  Keeping this worker intentionally model-free makes process
isolation cheap and prevents a timed-out nonlinear query from retaining Z3
state before the next proof shard.
"""

from __future__ import annotations

import json
import sys
import time


def main(argv: list[str] | None = None) -> int:
    import z3

    args = sys.argv[1:] if argv is None else argv
    timeout_ms = int(args[0]) if args else 0
    random_seed = int(args[1]) if len(args) > 1 else 0
    solver = z3.Solver()
    # Keep nonlinear proof shards reproducible across worker lifecycles.  This
    # is search order only; the emitted formula and accepted verdict are
    # unchanged.
    solver.set("smt.random_seed", random_seed)
    if timeout_ms:
        solver.set("timeout", timeout_ms)
    solver.add(z3.parse_smt2_string(sys.stdin.read()))
    started = time.perf_counter()
    verdict = solver.check()
    seconds = time.perf_counter() - started
    status = (
        "sat"
        if verdict == z3.sat
        else "unsat"
        if verdict == z3.unsat
        else "unknown"
    )
    print(
        json.dumps(
            {
                "status": status,
                "seconds": seconds,
                "reason_unknown": solver.reason_unknown()
                if status == "unknown"
                else "",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
