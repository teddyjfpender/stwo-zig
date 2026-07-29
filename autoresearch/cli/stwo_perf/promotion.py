"""Promotion decisions and ledger rows, shared by the promote bot and the CLI.

Two adjudication paths write rows through this module:

- the promote bot (bots/promote_action.py), from an HMAC-signed judged
  verdict — rows carry ``verdict_kind=judged``;
- ``stwo-perf promote-claimed``, the maintainer-as-judge interim path: after
  a human merges a submission PR, the merged submission's claimed verdict is
  recorded optimistically — rows carry ``verdict_kind=claimed`` and are
  expected to be superseded by a judged row when the judge host activates.

A claimed row is never upgraded: the kind travels through the ledger, the
feed, and every consumer (site-feed contract), so optimism stays labeled.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import subprocess
from pathlib import Path

from . import frontier, ledger, manifest as manifest_mod, stats


class PromotionError(RuntimeError):
    pass


def require_board_promotion_eligible(
    manifest: manifest_mod.Manifest, board: str
) -> None:
    """Fail closed unless the board's current manifest group may promote."""
    try:
        group = manifest.group_for_board(board)
    except manifest_mod.ManifestError as exc:
        raise PromotionError(f"board is not registered for promotion: {board}") from exc
    group_spec = manifest.raw["workload_registry"]["groups"].get(group.group_id, {})
    if group_spec.get("enabled") is not True:
        raise PromotionError(f"board workload group is disabled: {board}")
    retirement = group_spec.get("retirement")
    if isinstance(retirement, dict) and group_spec.get("promotion_eligible") is not True:
        # TRACKS §6 retire-and-complete: a retired board is not "not yet live",
        # it is finished. Say so, so nobody re-opens it by flipping a flag.
        raise PromotionError(
            f"board is retired and is not promotion eligible: {board} "
            f"(retired {retirement.get('retired_at_utc')}: {retirement.get('reason')}); "
            "its era is banked and its history stays served — new promotions "
            "belong on a live track (TRACKS §6)"
        )
    if group_spec.get("promotion_eligible") is not True:
        raise PromotionError(f"board is not promotion eligible: {board}")


def require_verdict_promotion_eligible(repo: Path, verdict: dict) -> None:
    objective = verdict.get("declared_objective")
    if not isinstance(objective, dict):
        raise PromotionError("verdict must declare an objective")
    board = objective.get("board")
    workload_class = objective.get("workload_class")
    if not isinstance(board, str):
        raise PromotionError("verdict must declare a string board")
    if not isinstance(workload_class, str):
        raise PromotionError("verdict must declare a string workload_class")
    try:
        manifest = manifest_mod.load(repo)
    except manifest_mod.ManifestError as exc:
        raise PromotionError(f"cannot load current promotion authority: {exc}") from exc
    require_board_promotion_eligible(manifest, board)
    try:
        manifest.validate_workload_class(workload_class, board=board)
    except manifest_mod.ManifestError as exc:
        raise PromotionError(
            f"verdict workload class is not registered for promotion: {board}/{workload_class}"
        ) from exc


def portfolio_ledger_summary(
    score: dict,
) -> tuple[float, float, float, int, int]:
    """Return the complete portfolio evidence vector for one ledger row.

    New multi-workload verdicts must carry the deterministic portfolio
    statistics emitted by the runner. Legacy single-workload verdicts remain
    recordable because their only row is mathematically identical to the
    portfolio.
    """
    per_workload = score.get("per_workload")
    if not isinstance(per_workload, dict) or not per_workload:
        raise PromotionError("verdict score has no per-workload evidence")
    portfolio = score.get("portfolio")
    if portfolio is None:
        if len(per_workload) != 1:
            raise PromotionError(
                "multi-workload verdict is missing deterministic portfolio statistics"
            )
        only = next(iter(per_workload.values()))
        ci = only.get("ci")
        prove_ms = only.get("b_median_ms")
        proof_bytes = only.get("proof_bytes")
        measurement_rounds = only.get("rounds")
    else:
        if not isinstance(portfolio, dict):
            raise PromotionError("score.portfolio must be an object")
        if portfolio.get("ci_method") != stats.PORTFOLIO_CI_METHOD:
            raise PromotionError("score.portfolio has an unsupported CI method")
        if portfolio.get("prove_ms_method") != stats.PORTFOLIO_PROVE_MS_METHOD:
            raise PromotionError("score.portfolio has an unsupported prove-ms method")
        if portfolio.get("proof_bytes_method") != stats.PORTFOLIO_PROOF_BYTES_METHOD:
            raise PromotionError("score.portfolio has an unsupported proof-bytes method")
        level = portfolio.get("ci_level")
        iterations = portfolio.get("bootstrap_iterations")
        seed = portfolio.get("seed")
        if (
            isinstance(level, bool)
            or not isinstance(level, (int, float))
            or not math.isfinite(float(level))
            or not 0.0 < float(level) < 1.0
        ):
            raise PromotionError("score.portfolio has an invalid confidence level")
        if iterations != stats.PORTFOLIO_BOOTSTRAP_ITERATIONS:
            raise PromotionError("score.portfolio has an unsupported bootstrap count")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise PromotionError("score.portfolio has an invalid deterministic seed")
        ci = portfolio.get("ci")
        prove_ms = portfolio.get("b_median_ms_geomean")
        proof_bytes = portfolio.get("proof_bytes")
        measurement_rounds = portfolio.get("measurement_rounds")
    if not isinstance(ci, list) or len(ci) != 2:
        raise PromotionError("portfolio CI must contain exactly two bounds")
    try:
        ci_low, ci_high, prove = float(ci[0]), float(ci[1]), float(prove_ms)
    except (TypeError, ValueError) as exc:
        raise PromotionError("portfolio ledger values must be numeric") from exc
    if (
        not all(math.isfinite(value) for value in (ci_low, ci_high, prove))
        or ci_low <= 0
        or ci_high < ci_low
        or prove <= 0
    ):
        raise PromotionError("portfolio ledger values are invalid")
    if (
        isinstance(proof_bytes, bool)
        or not isinstance(proof_bytes, int)
        or proof_bytes <= 0
        or isinstance(measurement_rounds, bool)
        or not isinstance(measurement_rounds, int)
        or measurement_rounds <= 0
    ):
        raise PromotionError("portfolio proof/measurement counts are invalid")
    return (
        ci_low, ci_high, prove, proof_bytes, measurement_rounds,
    )


def portfolio_resource_candidate(score: dict, dimension: str) -> float | None:
    """Read one absolute candidate value from governed resource evidence."""
    resource_portfolio = score.get("resource_portfolio")
    if resource_portfolio is None:
        return None
    if not isinstance(resource_portfolio, dict):
        raise PromotionError("score.resource_portfolio must be an object")
    entry = resource_portfolio.get(dimension)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise PromotionError(
            f"score.resource_portfolio.{dimension} must be an object"
        )
    candidate = entry.get("candidate_geomean")
    if candidate is None:
        return None
    if (
        isinstance(candidate, bool)
        or not isinstance(candidate, (int, float))
        or not math.isfinite(float(candidate))
        or float(candidate) <= 0
    ):
        raise PromotionError(
            f"score.resource_portfolio.{dimension}.candidate_geomean is invalid"
        )
    return float(candidate)


def decide_outcome(verdict: dict, predecessor_fresh: bool) -> tuple[str, str]:
    """Pure outcome decision (playbook F.5). ``predecessor_fresh`` is whether
    the verdict's predecessor contains the current class head — a stale
    branch may be re-deriving gains the frontier already credited, so its
    significant claim is recorded (neutral) until a paired re-measurement
    against the current frontier proves additivity.

    The old check compared this run's b_median against the head row's
    prove_ms in absolute milliseconds — an unpaired cross-run (and, for
    outside contributors, cross-host) comparison the scoring contract
    forbids everywhere else. A contributor on slower hardware could never
    promote under it, however real their improvement."""
    gates_ok = all(g["pass"] for g in verdict["gates"].values())
    if not gates_ok:
        failing = ",".join(g for g, v in verdict["gates"].items() if not v["pass"])
        return "rejected", f"{failing}:fail"
    holdout = verdict.get("holdout")
    if holdout is not None and not holdout.get("pass"):
        return "rejected", "G1..G5:pass"
    if not verdict["score"]["significant"]:
        return ("neutral" if verdict["score"]["neutral"] else "rejected"), "G1..G5:pass"
    if not predecessor_fresh:
        return "neutral", "G1..G5:pass"
    return "promoted", "G1..G5:pass"


def predecessor_is_fresh(repo: Path, verdict: dict, head) -> bool:
    """True when the verdict's predecessor tree contains the current class
    head (or the class has no head): the paired R was measured on top of
    everything already credited, so promoting it cannot double-count."""
    if head is None:
        return True
    pred = str(verdict.get("predecessor_commit") or "")
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{pred}^{{commit}}"],
        cwd=repo, capture_output=True, text=True,
    )
    if resolved.returncode != 0:
        return False
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", str(head.commit),
         resolved.stdout.strip()],
        cwd=repo, capture_output=True, text=True,
    )
    return ancestor.returncode == 0


def row_from_verdict(submission_id: str, verdict: dict, epoch: int, outcome: str,
                     gates_cell: str, verdict_kind: str,
                     commit: str | None = None) -> dict:
    """Build a ledger row; ``commit`` overrides the verdict's repo_commit
    (the claimed path records the commit that landed the submission)."""
    score = verdict["score"]
    objective = verdict["declared_objective"]
    (
        ci_low, ci_high, prove_ms, proof_bytes, measurement_rounds,
    ) = portfolio_ledger_summary(score)
    peak_rss_mib = portfolio_resource_candidate(score, "peak_rss_mib")
    energy_j = portfolio_resource_candidate(score, "energy_j")
    search_health = verdict.get("search_health")
    measurement_seconds = (
        search_health.get("measurement_wall_seconds")
        if isinstance(search_health, dict) else None
    )
    if (
        isinstance(measurement_seconds, bool)
        or not isinstance(measurement_seconds, (int, float))
        or not math.isfinite(float(measurement_seconds))
        or float(measurement_seconds) <= 0
    ):
        raise PromotionError(
            "verdict search_health.measurement_wall_seconds is required and positive"
        )
    measurement_seconds = float(measurement_seconds)
    holdout = verdict.get("holdout")
    holdout_cell = (
        f"{'pass' if holdout['pass'] else 'fail'};seed={holdout['seed']}"
        if holdout else "none"
    )
    evidence_sha256 = ledger.evidence_sha256(verdict)
    ledger_evidence = verdict.get("ledger_evidence", {})
    if not isinstance(ledger_evidence, dict):
        raise PromotionError("verdict ledger_evidence must be an object")
    if verdict.get("span_constituents") and not ledger_evidence:
        raise PromotionError(
            "span verdict must name explicit Metrics-v2 ledger_evidence"
        )
    evidence_kind = ledger_evidence.get("evidence_kind", "promotion")
    covers = ledger_evidence.get("covers", [])
    credit_replaces = ledger_evidence.get("credit_replaces", [])
    supersedes = ledger_evidence.get("supersedes", "")
    if evidence_kind not in ledger.EVIDENCE_KINDS:
        raise PromotionError("verdict ledger evidence kind is invalid")
    if (
        not isinstance(covers, list)
        or not isinstance(credit_replaces, list)
        or any(not isinstance(value, str) for value in covers + credit_replaces)
    ):
        raise PromotionError("verdict ledger evidence lists must be arrays")
    if not isinstance(supersedes, str):
        raise PromotionError("verdict ledger supersedes must be a string")
    if evidence_kind == "promotion" and (covers or credit_replaces):
        raise PromotionError("promotion evidence cannot cover or replace credit")
    if evidence_kind == "span_audit" and (not covers or credit_replaces):
        raise PromotionError("span evidence requires covers and cannot replace credit")
    if evidence_kind == "direct_audit" and covers:
        raise PromotionError("direct audit evidence cannot carry covers")
    objective_board = objective.get("board", "core_cpu")
    observation = ledger.observation_id(
        submission_id, objective_board, objective["workload_class"]
    )
    row = {
        "schema_version": ledger.SCHEMA_VERSION,
        "harness_commit": verdict["harness_commit"],
        "epoch": epoch,
        "judged_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit or verdict["repo_commit"],
        "scope": verdict["scope"],
        "board": objective_board,
        "workload_class": objective["workload_class"],
        "outcome": outcome,
        "judged_r": float(score["R_geomean"]),
        "ci_low": ci_low,
        "ci_high": ci_high,
        "prove_ms": prove_ms,
        "native_mhz": 0.0,
        # The frozen v1 column cannot encode missing RSS. Zero remains the
        # legacy sentinel; complete runner verdicts always supply the value.
        "peak_rss_mib": peak_rss_mib if peak_rss_mib is not None else 0.0,
        "waits": None,
        "dispatches": None,
        "energy_j": energy_j,
        "gates": gates_cell,
        "holdout": holdout_cell,
        "submission_id": submission_id,
        "predecessor": verdict["predecessor_commit"],
        "supersedes": supersedes,
        "verdict_kind": verdict_kind,
        "row_id": "",
        "observation_id": observation,
        "evidence_kind": evidence_kind,
        "covers": covers,
        "credit_replaces": credit_replaces,
        "evidence_sha256": evidence_sha256,
        "proof_bytes": proof_bytes,
        "measurement_seconds": measurement_seconds,
        "measurement_rounds": measurement_rounds,
    }
    row["row_id"] = ledger.compute_row_id(row)
    return row


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise PromotionError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def landing_commit(repo: Path, submission_id: str) -> str:
    """The first commit that introduced the submission directory — the merged
    change itself, reachable on the mainline forever (merge commits only)."""
    out = _git(
        repo, "log", "--reverse", "--format=%H", "--",
        f"autoresearch/submissions/{submission_id}",
    ).strip().splitlines()
    if not out:
        raise PromotionError(
            f"submission {submission_id} has no landing commit in this history"
        )
    return out[0]


def claimed_verdict_files(sub_dir: Path) -> list[Path]:
    """A submission's verdicts: the primary verdict.json plus one
    verdict-<class>.json or verdict-<board>-<class>.json per additional
    board/class pair the change moved."""
    primary = sub_dir / "verdict.json"
    extras = sorted(sub_dir.glob("verdict-*.json"))
    return [p for p in [primary, *extras] if p.is_file()]


def promote_claimed(repo: Path, submission_id: str,
                    verdict_name: str = "verdict.json") -> dict:
    """Maintainer-as-judge: record one of a merged submission's claimed
    verdicts as an optimistic ledger row (one row per moved class). Returns
    the appended row. Refuses anything that is not a merged, schema-clean
    claimed submission or whose (submission, class) is already recorded."""
    if _git(repo, "status", "--porcelain").strip():
        raise PromotionError(
            "working tree is not clean; promote from a clean checkout of the "
            "merged history"
        )
    sub_dir = repo / "autoresearch" / "submissions" / submission_id
    verdict_path = sub_dir / verdict_name
    if not verdict_path.is_file():
        raise PromotionError(f"no verdict at {verdict_path}")
    verdict = json.loads(verdict_path.read_text())
    if verdict.get("kind") != "claimed":
        raise PromotionError(
            "promote-claimed records claimed verdicts only; judged verdicts "
            "arrive via the signed promote path"
        )
    require_verdict_promotion_eligible(repo, verdict)
    objective = verdict.get("declared_objective") or {}
    verdict_class = objective.get("workload_class")
    verdict_board = objective.get("board", "core_cpu")
    if any(
        r.submission_id == submission_id
        and r.workload_class == verdict_class
        and r.board == verdict_board
        for r in ledger.load(repo)
    ):
        raise PromotionError(
            f"{submission_id} already has a ledger row for {verdict_board}/{verdict_class}"
        )

    objective = verdict["declared_objective"]
    head = frontier.view(
        ledger.load(repo), objective.get("board", "core_cpu"),
        objective["workload_class"],
    ).head
    outcome, gates_cell = decide_outcome(
        verdict, predecessor_is_fresh(repo, verdict, head)
    )
    row = row_from_verdict(
        submission_id, verdict, ledger.current_epoch(repo)["epoch"],
        outcome, gates_cell, verdict_kind="claimed",
        commit=landing_commit(repo, submission_id),
    )
    ledger.append(repo, row)
    _git(repo, "add", str(ledger.ledger_path(repo)))
    _git(
        repo, "commit",
        "-m", f"Ledger: {outcome} (claimed) — {submission_id}",
        "-m", "Optimistic maintainer-adjudicated row from the merged claimed "
              "verdict; a judged run supersedes it. [skip ci]",
    )
    return row
