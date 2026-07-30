#!/usr/bin/env python3
"""Confirmation-ladder tier cost targets, checked per track (TRACKS §3.6).

Every tier of the ladder has a pre-registered cost target in
``autoresearch/MANIFEST.json`` (``gates_policy.confirmation_ladder.tiers``).
This check reads the telemetry that real runs already record — verdict
``score.portfolio.measurement_seconds`` for the claimed (T2) and judged (T3)
tiers, and the ``measurement_seconds`` of T0/T1 ladder documents — and fails
when a track's tier is over its target. The remedy is always the same one:
*a track whose T1 exceeds five minutes must shrink its proxy, not its honesty.*

Fail-closed applies to honesty, not to absent tracks: a track with no recorded
telemetry for a tier passes with a loud note, because refusing to rank an
unmeasured track would only encourage nobody to measure it.

Wiring: the autoresearch-validate workflow runs
``python3 -m unittest discover -s autoresearch/tests``, and
``autoresearch/tests/test_tier_cost_targets.py`` invokes this check over the
repository, so the target is enforced on every PR without a new workflow step.
Run it directly with::

    python3 scripts/check_tier_cost_targets.py
    python3 scripts/check_tier_cost_targets.py --report /tmp/tier-costs.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

T0_SCHEMA = "stwo_perf_ladder_t0_prefilter_v1"
T1_SCHEMA = "stwo_perf_ladder_t1_estimate_v1"
LADDER_SCHEMAS = {T0_SCHEMA: "T0", T1_SCHEMA: "T1"}
#: Default telemetry roots, relative to the repository root.
TELEMETRY_ROOTS = ("autoresearch/submissions", "autoresearch/.runs")
#: A measurement document larger than this is not one of ours.
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024


class TierCostError(RuntimeError):
    pass


def load_policy(repo_root: Path) -> dict:
    """Tier targets, telemetry statistic, and the track list from the manifest."""
    try:
        raw = json.loads(
            (repo_root / "autoresearch" / "MANIFEST.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise TierCostError(f"cannot read MANIFEST.json: {exc}") from exc
    ladder = raw.get("gates_policy", {}).get("confirmation_ladder")
    if not isinstance(ladder, dict):
        raise TierCostError(
            "gates_policy.confirmation_ladder is not registered; tier cost "
            "targets cannot be checked against an unregistered ladder"
        )
    tiers = ladder.get("tiers")
    telemetry = ladder.get("cost_telemetry")
    if not isinstance(tiers, dict) or not isinstance(telemetry, dict):
        raise TierCostError("confirmation_ladder is missing tiers or cost_telemetry")
    targets = {
        tier: spec.get("cost_target_seconds")
        for tier, spec in tiers.items()
        if isinstance(spec, dict)
    }
    groups = raw.get("workload_registry", {}).get("groups", {})
    tracks = sorted(
        spec["board"] for spec in groups.values()
        if isinstance(spec, dict) and isinstance(spec.get("board"), str)
    )
    statistic = telemetry.get("statistic")
    window = telemetry.get("window")
    if statistic not in ("median", "max") or type(window) is not int or window < 1:
        raise TierCostError("confirmation_ladder.cost_telemetry is malformed")
    return {
        "targets": targets,
        "tracks": tracks,
        "statistic": statistic,
        "window": window,
    }


def _document_observation(document: object) -> tuple[str, str, float] | None:
    """Map one JSON document to ``(track, tier, seconds)`` when it is telemetry."""
    if not isinstance(document, dict):
        return None
    schema = document.get("schema")
    if schema in LADDER_SCHEMAS:
        board = document.get("board")
        seconds = document.get("measurement_seconds")
        tier = LADDER_SCHEMAS[schema]
    elif document.get("schema_version") == 1 and isinstance(document.get("score"), dict):
        objective = document.get("declared_objective")
        portfolio = document["score"].get("portfolio")
        if not isinstance(objective, dict) or not isinstance(portfolio, dict):
            return None
        board = objective.get("board")
        seconds = portfolio.get("measurement_seconds")
        kind = document.get("kind")
        if kind == "judged":
            tier = "T3"
        elif kind == "claimed":
            tier = "T2"
        else:
            return None
    else:
        return None
    if not isinstance(board, str) or not board:
        return None
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return None
    if float(seconds) <= 0.0:
        return None
    return board, tier, float(seconds)


def collect_observations(
    repo_root: Path, extra_dirs: list[Path] | None = None,
) -> dict[tuple[str, str], list[tuple[str, float]]]:
    """Gather ``(track, tier) -> [(source, seconds)]`` from recorded telemetry.

    Sources are visited in sorted path order; submission directories are
    date-prefixed, so "the last ``window`` entries" is a deterministic,
    reproducible recency window rather than a filesystem-timestamp race.
    """
    roots = [repo_root / relative for relative in TELEMETRY_ROOTS]
    roots.extend(extra_dirs or [])
    observations: dict[tuple[str, str], list[tuple[str, float]]] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json")):
            try:
                if path.stat().st_size > MAX_DOCUMENT_BYTES:
                    continue
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            found = _document_observation(document)
            if found is None:
                continue
            board, tier, seconds = found
            try:
                source = str(path.relative_to(repo_root))
            except ValueError:
                source = str(path)
            observations.setdefault((board, tier), []).append((source, seconds))
    return observations


def evaluate(
    policy: dict,
    observations: dict[tuple[str, str], list[tuple[str, float]]],
) -> dict:
    """Assess every (track, tier) with a registered target against telemetry."""
    statistic_fn = (
        statistics.median if policy["statistic"] == "median" else max
    )
    rows: list[dict] = []
    tracks = sorted(set(policy["tracks"]) | {board for board, _ in observations})
    for track in tracks:
        for tier, target in policy["targets"].items():
            if target is None:
                continue  # judge-scheduled: no cost target by contract
            recorded = observations.get((track, tier), [])
            window = recorded[-policy["window"]:]
            if not window:
                rows.append({
                    "track": track,
                    "tier": tier,
                    "target_seconds": target,
                    "observations": 0,
                    "statistic": None,
                    "worst_seconds": None,
                    "pass": True,
                    "absent": True,
                    "sources": [],
                })
                continue
            values = [seconds for _source, seconds in window]
            summary = float(statistic_fn(values))
            rows.append({
                "track": track,
                "tier": tier,
                "target_seconds": target,
                "observations": len(window),
                "statistic": summary,
                "worst_seconds": max(values),
                "pass": summary <= float(target),
                "absent": False,
                "sources": [source for source, _seconds in window],
            })
    return {
        "schema": "stwo_perf_tier_cost_report_v1",
        "statistic": policy["statistic"],
        "window": policy["window"],
        "rows": rows,
        "violations": [row for row in rows if not row["pass"]],
        "absent": [row for row in rows if row["absent"]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--telemetry-dir", type=Path, action="append", default=[],
        help="extra directory of recorded run telemetry (repeatable)",
    )
    parser.add_argument("--report", type=Path, help="write the JSON assessment here")
    parser.add_argument(
        "--quiet-absent", action="store_true",
        help="suppress the per-track absent-telemetry notes",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        policy = load_policy(repo_root)
    except TierCostError as exc:
        print(f"tier cost targets: {exc}", file=sys.stderr)
        return 1
    report = evaluate(
        policy, collect_observations(repo_root, args.telemetry_dir),
    )
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    for row in report["rows"]:
        if row["absent"]:
            if not args.quiet_absent:
                print(
                    f"tier cost targets: NOTE {row['track']} {row['tier']} has no "
                    f"recorded telemetry yet (target {row['target_seconds']}s) — "
                    "passing an unmeasured track, not excusing a slow one"
                )
            continue
        state = "ok" if row["pass"] else "OVER"
        print(
            f"tier cost targets: {state} {row['track']} {row['tier']} "
            f"{policy['statistic']}={row['statistic']:.1f}s worst="
            f"{row['worst_seconds']:.1f}s target={row['target_seconds']}s "
            f"(n={row['observations']})"
        )
    if report["violations"]:
        for row in report["violations"]:
            print(
                f"tier cost targets: {row['track']} {row['tier']} exceeds its "
                f"{row['target_seconds']}s target "
                f"({policy['statistic']} {row['statistic']:.1f}s over "
                f"{row['observations']} run(s)) — shrink the proxy, not the honesty",
                file=sys.stderr,
            )
        print(
            f"tier cost targets: {len(report['violations'])} violation(s)",
            file=sys.stderr,
        )
        return 1
    print(
        "tier cost targets: every measured track/tier is within its "
        "pre-registered cost target"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
