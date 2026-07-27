#!/usr/bin/env python3
"""Run the witness-uniqueness question over every emitted AIR family.

    python3 -m scripts.air_uniqueness_board

reproduces the board: one row per family, each of `unsat` / `sat` with a decoded
two-witness counterexample / `skipped` with the reason / `timeout` with its wall
clock.  `scripts/air_uniqueness.py` answers the question for one family and
explains the encoding; this schedules it across all of them.

Budget
------
`--timeout-ms` is per solver query, not per family. A family splits into opcode
and/or output shards, and a long carry shard may decompose again into sequential
proof queries. A family is unique exactly when every architectural shard is
unsat. The board prints the shard count alongside the summed solver seconds so
neither number can be read as the other.

Splitting by opcode is on by default and splitting by output is not, because
that is what the measurement said. Over the 17 shipped families at a 60 s
per-query budget: monolithic closes 9 (17 shards), by opcode closes 11
(46 shards), by output closes 9 (118 shards).  Both axes are sound; only the
opcode one pays, because pinning a selector is what lets interval analysis
delete the other opcodes' machinery, while asking about one output re-derives
the whole family per output.  `--split-outputs` turns the other axis on anyway:
its counterexamples are sharper, which is worth the budget during triage.

Honesty rules this runner exists to keep
----------------------------------------
  * a shard that does not finish is reported as `timeout` with its wall clock,
    and it makes its whole family `timeout`.  Nine unsat shards and one timeout
    is not an unsat family;
  * `sat` is never reported bare.  The counterexample is decoded inline, and
    `--counterexample-dir` writes the witness pair as a mutation-corpus seed;
  * a family with nothing to conclude about is `skipped` with the reason.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import time
from pathlib import Path

try:
    from air_uniqueness_lib import ir, smtlib, solve
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_board in tests.
    from scripts.air_uniqueness_lib import ir, smtlib, solve

# Worst first: a counterexample outranks an unfinished shard, which outranks a
# family the query cannot speak about, which outranks a proof.
SHARD_ORDER = ("sat", "unknown", "skipped", "unsat")
BOARD_ORDER = ("sat", "timeout", "skipped", "unsat")


def _run_job(job: tuple[str, dict, dict]) -> dict:
    """One sub-query, in its own process.

    A `probe` job is the honest-witness check, planned once per opcode rather
    than once per shard: it ignores the output axis, so every output shard of an
    opcode would otherwise re-run the same query.

    A long multiplier shard starts with the sequential ladder (`solve.ladder`)
    rather than first spending its whole budget on a monolith known not to
    finish. DIV uses its exact-IR arithmetic control; MULH uses the generic
    carry-prefix ladder. The escalation stays inside the job so the pool sees
    one work item either way, and the row keeps both costs: `seconds` sums the
    failed monolith and every ladder/control step.
    """
    path, spec, options = job
    system = ir.load(path)
    started = time.perf_counter()
    shard = smtlib.Shard(spec.get("output", ""), spec.get("selector", ""))
    if spec.get("kind") == "probe":
        control_probe = (
            system.family == "div"
            and shard.selector in solve.DIVISION_SELECTORS
            and not options.get("no_ladder")
        )
        return {
            "family": system.family,
            "kind": "probe",
            "shard": shard.label(),
            "method": (
                "complete pinned DIV 0/1 row"
                if control_probe
                else "one-copy satisfiability search"
            ),
            "satisfiable": (
                solve.division_known_answer_satisfiable(
                    system,
                    shard.selector,
                    options["timeout_ms"],
                    refine=options["refine"],
                    derived=options["derived"],
                    assume_domains=options["assume_domains"],
                )
                if control_probe
                else solve.satisfiable(
                    system,
                    options["timeout_ms"],
                    fresh=solve.prefers_ladder(system),
                    refine=options["refine"],
                    derived=options["derived"],
                    assume_domains=options["assume_domains"],
                    shard=shard,
                )
            ),
            "seconds": time.perf_counter() - started,
            "wall": time.perf_counter() - started,
        }
    check_options = {k: v for k, v in options.items() if k != "no_ladder"}
    decomposed = (
        not spec.get("output")
        and not options.get("no_ladder")
        and solve.prefers_ladder(system)
    )
    if (
        decomposed
        and system.family == "div"
        and shard.selector in solve.DIVISION_SELECTORS
    ):
        result = solve.division_control(
            system,
            shard.selector,
            options["timeout_ms"],
            refine=options["refine"],
            derived=options["derived"],
            assume_domains=options["assume_domains"],
        )
    elif decomposed:
        result = solve.ladder(
            system,
            options["timeout_ms"],
            shard=smtlib.Shard(selector=shard.selector),
            fresh=True,
            refine=options["refine"],
            derived=options["derived"],
            assume_domains=options["assume_domains"],
        )
    else:
        result = solve.check(system, shard=shard, probe=False, **check_options)
    if (
        result.status == "unknown"
        and not decomposed
        and not spec.get("output")
        and not options.get("no_ladder")
    ):
        escalated = solve.ladder(
            system,
            options["timeout_ms"],
            shard=smtlib.Shard(selector=shard.selector),
            fresh=True,
            refine=options["refine"],
            derived=options["derived"],
            assume_domains=options["assume_domains"],
        )
        escalated.seconds += result.seconds
        result = escalated
    return {
        "family": system.family,
        "kind": "unique",
        "path": path,
        "shard": result.shard,
        "status": result.status,
        "seconds": result.seconds,
        "wall": time.perf_counter() - started,
        "detail": _detail(result),
        "counterexample": (
            solve.counterexample_payload(system, result)
            if result.status == "sat"
            else None
        ),
        "report": solve.format_result(result),
    }


def _detail(result: solve.Result) -> str:
    if result.status == "sat":
        return ",".join(result.differing_outputs)
    if result.status == "unsat":
        return "VACUOUS" if result.vacuous else "unique"
    if result.status == "unknown":
        return result.reason_unknown
    return result.skip_reason


def plan(paths: list[str], args: argparse.Namespace) -> list[tuple[str, dict, dict]]:
    """Every sub-query the board will ask, flattened across families.

    Flattened rather than nested so the pool can fill every core with whatever
    is left: a family split eight ways and a family split once are the same kind
    of work item, and scheduling them together stops one wide family from
    serialising behind one narrow one.
    """
    options = {
        "timeout_ms": args.timeout_ms,
        "refine": not args.no_refine,
        "derived": not args.no_derived_facts,
        "assume_domains": args.assume_declared_domains,
        "no_ladder": args.no_ladder,
    }
    jobs: list[tuple[str, dict, dict]] = []
    for path in paths:
        system = ir.load(path)
        if system.uniqueness_skip_reason() is not None:
            jobs.append((path, {}, options))
            continue
        shards = smtlib.plan_shards(
            system, args.split_outputs, not args.no_split_opcodes
        )
        for shard in shards:
            jobs.append(
                (path, {"output": shard.output, "selector": shard.selector}, options)
            )
        for selector in sorted({shard.selector for shard in shards}):
            jobs.append((path, {"kind": "probe", "selector": selector}, options))
    return jobs


def collect(rows: list[dict]) -> list[dict]:
    """Fold shard rows into one row per family."""
    families: dict[str, list[dict]] = {}
    probes: dict[str, list[dict]] = {}
    for row in rows:
        bucket = probes if row.get("kind") == "probe" else families
        bucket.setdefault(row["family"], []).append(row)
    out = []
    for family, shards in families.items():
        worst = min(shards, key=lambda r: SHARD_ORDER.index(r["status"]))
        family_probes = probes.get(family, ())
        witnessed = [p["satisfiable"] for p in family_probes]
        honest_witness = (
            False
            if False in witnessed
            else None
            if None in witnessed or not witnessed
            else True
        )
        out.append(
            {
                "family": family,
                "status": (
                    "timeout" if worst["status"] == "unknown" else worst["status"]
                ),
                "shards": len(shards),
                # False beats None beats True: an opcode nothing satisfies makes
                # its shards vacuously unsat, and a probe that ran out of budget
                # leaves the question open rather than answering it.
                "honest_witness": honest_witness,
                "seconds": sum(r["seconds"] for r in shards)
                + sum(p["seconds"] for p in family_probes),
                "wall": max(r["wall"] for r in shards),
                "detail": worst["detail"],
                "deciding_shard": worst["shard"],
                "open_shards": [
                    r["shard"] for r in shards if r["status"] in ("sat", "unknown")
                ],
                "report": worst["report"],
                "counterexample": worst["counterexample"],
                # Keep every verdict and non-vacuity control in the JSON
                # artifact. A folded `unsat` is useful only if a reviewer can
                # see that no open shard was averaged away.
                "shard_results": [
                    {
                        key: row[key]
                        for key in ("shard", "status", "seconds", "wall", "detail")
                    }
                    for row in sorted(shards, key=lambda row: row["shard"])
                ],
                "probe_results": [
                    {
                        **{
                            key: row[key]
                            for key in ("shard", "satisfiable", "seconds", "wall")
                        },
                        "method": row.get("method", "unspecified"),
                    }
                    for row in sorted(family_probes, key=lambda row: row["shard"])
                ],
            }
        )
    return sorted(out, key=lambda r: (BOARD_ORDER.index(r["status"]), r["family"]))


def render(rows: list[dict], args: argparse.Namespace) -> str:
    lines = [
        f"per-query budget {args.timeout_ms} ms | {len(rows)} families | "
        f"{sum(r['shards'] for r in rows)} shards | "
        f"declared input domains assumed={args.assume_declared_domains}",
        "",
        f"{'family':<14} {'verdict':<8} {'shards':>6} {'solver s':>9}  detail",
    ]
    for row in rows:
        lines.append(
            f"{row['family']:<14} {row['status']:<8} {row['shards']:>6} "
            f"{row['seconds']:>9.1f}  {row['detail'][:64]}"
            + _vacuity_note(row)
        )
        if row["status"] in ("sat", "timeout"):
            # A timeout is only a result if it says how long it was given, so
            # the longest shard's wall clock rides along with the open list.
            lines.append(
                f"{'':<14} {'':<8} {'':>6} {row['wall']:>9.1f}  open ("
                f"{len(row['open_shards'])}): "
                f"{', '.join(row['open_shards'][:6])}"
            )
    tally: dict[str, int] = {}
    for row in rows:
        tally[row["status"]] = tally.get(row["status"], 0) + 1
    lines += ["", "tally: " + ", ".join(f"{k}={v}" for k, v in sorted(tally.items()))]
    for row in rows:
        if row["status"] == "sat":
            lines += ["", "=" * 72, row["report"]]
    return "\n".join(lines)


def _vacuity_note(row: dict) -> str:
    """An unsat means nothing until an honest witness is known to exist."""
    if row["status"] != "unsat":
        return ""
    if row["honest_witness"] is False:
        return "  <-- VACUOUS: no witness satisfies the constraints"
    if row["honest_witness"] is None:
        return "  (honest-witness probe did not finish)"
    return ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ir-dir", default="zig-out/uniqueness-ir")
    parser.add_argument("--timeout-ms", type=int, default=120_000)
    parser.add_argument("--jobs", type=int, default=0, help="0 = one per core")
    parser.add_argument("--family", action="append", default=[])
    parser.add_argument("--json", help="write the board here as JSON")
    parser.add_argument("--counterexample-dir", help="write each sat witness pair here")
    parser.add_argument(
        "--split-outputs",
        action="store_true",
        help="one query per architectural output. Sharper, and measurably "
        "slower; see the module docstring",
    )
    parser.add_argument("--no-split-opcodes", action="store_true")
    parser.add_argument(
        "--no-ladder",
        action="store_true",
        help="disable carry-family ladder/certificate decomposition and run "
        "the raw shard query",
    )
    parser.add_argument("--no-derived-facts", action="store_true")
    parser.add_argument("--no-refine", action="store_true")
    parser.add_argument("--assume-declared-domains", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = sorted(str(p) for p in Path(args.ir_dir).glob("*.json"))
    if args.family:
        paths = [p for p in paths if Path(p).stem in args.family]
    if not paths:
        print(f"no IR under {args.ir_dir}", file=sys.stderr)
        return 2
    jobs = plan(paths, args)
    with mp.Pool(processes=args.jobs or None) as pool:
        rows = collect(pool.map(_run_job, jobs, chunksize=1))
    print(render(rows, args))
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    if args.counterexample_dir:
        directory = Path(args.counterexample_dir)
        directory.mkdir(parents=True, exist_ok=True)
        for row in rows:
            if row["counterexample"] is not None:
                target = directory / f"{row['family']}.json"
                target.write_text(
                    json.dumps(row["counterexample"], indent=2) + "\n", encoding="utf-8"
                )
    return 1 if any(row["status"] != "unsat" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
