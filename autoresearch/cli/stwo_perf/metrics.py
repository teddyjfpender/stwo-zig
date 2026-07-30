"""Pure Metrics-v2 scoring and audit scheduling over ledger rows.

The engine performs no I/O and uses only the Python standard library. It
turns append-only evidence into disjoint credit events, so an observation can
contribute to the suite score exactly once. Direct audits replace the exact
active credits since the preceding audit and become exact score anchors;
promotions and span audits receive neutralward log-CI shrinkage.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from . import ledger


class MetricsError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditPolicy:
    shrinkage_lambda: float
    span_every: int
    direct_every: int
    span_effect_theta: float
    audit_anchor_commit: str
    # TRACKS §7 era provenance. Populated only when the policy was resolved
    # from a board-effective epoch specification (``ledger.epoch_for_board`` /
    # ``ledger.current_epoch(board=...)``); a global epoch leaves both None and
    # behaves exactly as before.
    board: str | None = None
    era: int | None = None


@dataclass(frozen=True)
class CreditEvent:
    row_id: str
    observation_id: str
    evidence_kind: str
    # Internal coverage is explicit for promotion/span rows and derived for a
    # direct audit from all promotion observations since the preceding audit.
    covers: tuple[str, ...]
    credit_replaces: tuple[str, ...]
    log_credit: float
    point_log_r: float

    @property
    def credited_r(self) -> float:
        return math.exp(self.log_credit)


@dataclass(frozen=True)
class ClassScore:
    epoch: int
    board: str
    workload_class: str
    ratio: float
    log_ratio: float
    audited_ratio: float
    audited_through: str | None
    active_events: tuple[CreditEvent, ...]


@dataclass(frozen=True)
class DueState:
    epoch: int
    board: str
    workload_class: str
    audited_through: str | None
    span_due: bool
    span_reasons: tuple[str, ...]
    span_covers: tuple[str, ...]
    span_point_r: float
    direct_audit_due: bool
    direct_audit_replaces: tuple[str, ...]


@dataclass(frozen=True)
class AuditProjection:
    """Public, deterministic state for one board/class audit cell."""

    effective_score: float
    audited_score: float
    audited_through: str | None
    audit_base: str
    unaudited_tail: tuple[str, ...]
    span_due: bool
    span_overdue_by: int
    span_reasons: tuple[str, ...]
    direct_due: bool
    direct_overdue_by: int
    neutral_observations: int
    span_consumed: int
    span_pending: int
    claimed_observations: int
    judged_observations: int


def _validate_policy(policy: AuditPolicy) -> None:
    if (
        not math.isfinite(policy.shrinkage_lambda)
        or policy.shrinkage_lambda < 0
        or policy.span_every < 1
        or policy.direct_every < 1
        or not 0 < policy.span_effect_theta < 1
        or not re.fullmatch(r"[0-9a-f]{40}", policy.audit_anchor_commit)
    ):
        raise MetricsError("epoch metrics_v2 policy values are invalid")


def policy_from_epoch(epoch: dict) -> AuditPolicy:
    """Build the audit policy of one epoch, global or board-effective.

    A board-effective specification carries an ``era`` view whose per-board
    ``audit_anchor_commit`` override is already merged into ``metrics_v2``
    (TRACKS §7: audit anchors are per board, the global epoch's anchor is the
    fallback). The era's identity is retained here purely as provenance.
    """
    spec = epoch.get("metrics_v2")
    if not isinstance(spec, dict) or spec.get("schema_version") != 2:
        raise MetricsError("epoch does not declare metrics_v2 schema 2")
    era = epoch.get("era")
    if era is not None and not isinstance(era, dict):
        raise MetricsError("epoch era view must be an object")
    try:
        policy = AuditPolicy(
            shrinkage_lambda=float(spec["shrinkage_lambda"]),
            span_every=int(spec["span_audit_every_landed"]),
            direct_every=int(spec["direct_audit_every_landed"]),
            span_effect_theta=float(spec["span_effect_theta"]),
            audit_anchor_commit=str(spec["audit_anchor_commit"]),
            board=str(era["board"]) if era else None,
            era=int(era["era"]) if era else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MetricsError("epoch metrics_v2 policy is incomplete") from exc
    _validate_policy(policy)
    return policy


def neutralward_log_credit(
    judged_r: float,
    ci_low: float,
    ci_high: float,
    shrinkage_lambda: float,
) -> float:
    """Shrink the point estimate toward neutral by its directional CI radius."""
    values = (judged_r, ci_low, ci_high, shrinkage_lambda)
    if not all(math.isfinite(value) for value in values):
        raise MetricsError("ratio, CI, and shrinkage lambda must be finite")
    if (
        judged_r <= 0
        or ci_low <= 0
        or ci_high < ci_low
        or not ci_low <= judged_r <= ci_high
        or shrinkage_lambda < 0
    ):
        raise MetricsError("ratio/CI/shrinkage relationship is invalid")
    point = math.log(judged_r)
    if ci_low <= 1.0 <= ci_high or point == 0.0:
        return 0.0
    radius = (
        math.log(ci_high) - point
        if point < 0.0
        else point - math.log(ci_low)
    )
    magnitude = max(0.0, abs(point) - shrinkage_lambda * radius)
    return math.copysign(magnitude, point) if point else 0.0


def _class_rows(
    rows: list[ledger.Row], epoch: int, board: str, workload_class: str
) -> list[ledger.Row]:
    return [
        row for row in ledger.resolve_corrections(rows)
        if row.epoch == epoch
        and row.board == board
        and row.workload_class == workload_class
    ]


def _crediting(row: ledger.Row) -> bool:
    if row.evidence_kind == "direct_audit":
        return row.gates_passed
    return row.gates_passed and row.outcome == "promoted"


def credited_log_effect(row: ledger.Row, shrinkage_lambda: float) -> float:
    """Return one validated row's score contribution before replacement."""
    if not _crediting(row):
        return 0.0
    if row.evidence_kind == "direct_audit":
        if (
            not all(math.isfinite(value) for value in (
                row.judged_r, row.ci_low, row.ci_high,
            ))
            or row.ci_low <= 0
            or not row.ci_low <= row.judged_r <= row.ci_high
        ):
            raise MetricsError("direct-audit ratio and CI are invalid")
        return math.log(row.judged_r)
    return neutralward_log_credit(
        row.judged_r, row.ci_low, row.ci_high, shrinkage_lambda
    )


def _assert_disjoint(active: dict[str, CreditEvent]) -> None:
    owner: dict[str, str] = {}
    for event in active.values():
        for observation in event.covers:
            previous = owner.setdefault(observation, event.row_id)
            if previous != event.row_id:
                raise MetricsError(
                    f"active credit events {previous} and {event.row_id} overlap"
                )


def _ordered_span(
    row: ledger.Row,
    promotions: dict[str, ledger.Row],
    active: dict[str, CreditEvent],
) -> tuple[str, ...]:
    covered = set(row.covers)
    ordered = tuple(observation for observation in promotions if observation in covered)
    if len(ordered) != len(row.covers) or ordered != tuple(row.covers):
        raise MetricsError(
            f"row {row.row_id}: covers must name earlier promotions in ledger order"
        )
    invalid = [
        observation for observation in ordered
        if not promotions[observation].gates_passed
        or promotions[observation].outcome != "neutral"
    ]
    if invalid:
        raise MetricsError(
            f"row {row.row_id}: span may cover only gate-passing neutral promotions"
        )
    active_observations = {
        observation for event in active.values() for observation in event.covers
    }
    overlap = active_observations.intersection(covered)
    if overlap:
        raise MetricsError(
            f"row {row.row_id}: span overlaps already-credited observations {sorted(overlap)}"
        )
    return ordered


def score_class(
    rows: list[ledger.Row],
    epoch: int,
    board: str,
    workload_class: str,
    *,
    shrinkage_lambda: float,
    audit_anchor_commit: str | None = None,
) -> ClassScore:
    """Build the exact active credit set and its audit-anchored class score."""
    active: dict[str, CreditEvent] = {}
    promotions: dict[str, ledger.Row] = {}
    pending_since_audit: list[str] = []
    span_consumed: set[str] = set()
    audit_events: list[CreditEvent] = []
    audited_through = None

    for row in _class_rows(rows, epoch, board, workload_class):
        if row.evidence_kind == "promotion":
            promotions[row.observation_id] = row
            pending_since_audit.append(row.observation_id)
            if not _crediting(row):
                continue
            log_credit = credited_log_effect(row, shrinkage_lambda)
            event = CreditEvent(
                row.row_id, row.observation_id, row.evidence_kind,
                (row.observation_id,), (), log_credit, math.log(row.judged_r),
            )
            active[event.row_id] = event
            _assert_disjoint(active)
            continue

        if row.evidence_kind == "span_audit":
            _ordered_span(row, promotions, active)
            overlap = span_consumed.intersection(row.covers)
            if overlap:
                raise MetricsError(
                    f"row {row.row_id}: span coverage is not disjoint"
                )
            if row.gates_passed and row.outcome in ("promoted", "neutral"):
                span_consumed.update(row.covers)
            if not _crediting(row):
                continue
            log_credit = credited_log_effect(row, shrinkage_lambda)
            event = CreditEvent(
                row.row_id, row.observation_id, row.evidence_kind,
                tuple(row.covers), (), log_credit, math.log(row.judged_r),
            )
            active[event.row_id] = event
            _assert_disjoint(active)
            continue

        if not _crediting(row):
            if row.credit_replaces:
                raise MetricsError(
                    f"row {row.row_id}: failed direct audit cannot replace credit"
                )
            continue
        expected_predecessor = audited_through or audit_anchor_commit
        if expected_predecessor is None:
            raise MetricsError(
                f"row {row.row_id}: first direct audit has no epoch audit anchor"
            )
        if row.predecessor != expected_predecessor:
            raise MetricsError(
                f"row {row.row_id}: direct audit does not chain from audit anchor"
            )
        expected = tuple(
            event.row_id for event in active.values()
            if event.evidence_kind != "direct_audit"
        )
        if tuple(row.credit_replaces) != expected:
            raise MetricsError(
                f"row {row.row_id}: credit_replaces is not the exact active set; "
                f"expected {expected}"
            )
        for row_id in expected:
            active.pop(row_id)
        point_log = credited_log_effect(row, shrinkage_lambda)
        event = CreditEvent(
            row.row_id, row.observation_id, row.evidence_kind,
            tuple(pending_since_audit), tuple(row.credit_replaces),
            point_log, point_log,
        )
        active[event.row_id] = event
        audit_events.append(event)
        audited_through = row.commit
        pending_since_audit.clear()
        _assert_disjoint(active)

        actual = sum(item.log_credit for item in active.values())
        audited = sum(item.point_log_r for item in audit_events)
        if not math.isclose(actual, audited, rel_tol=0.0, abs_tol=1e-12):
            raise MetricsError(
                f"row {row.row_id}: score at audit point does not equal audit chain"
            )

    log_ratio = sum(event.log_credit for event in active.values())
    audited_log = sum(event.point_log_r for event in audit_events)
    return ClassScore(
        epoch=epoch,
        board=board,
        workload_class=workload_class,
        ratio=math.exp(log_ratio),
        log_ratio=log_ratio,
        audited_ratio=math.exp(audited_log),
        audited_through=audited_through,
        active_events=tuple(active.values()),
    )


def board_suite_score(
    rows: list[ledger.Row],
    epoch: int,
    board: str,
    scored_classes: list[str],
    *,
    policy: AuditPolicy,
) -> dict:
    """Aggregate canonical Metrics-v2 class scores for one manifest board."""
    _validate_policy(policy)
    if not scored_classes or len(scored_classes) != len(set(scored_classes)):
        raise MetricsError("scored_classes must be a unique non-empty list")
    scores = {
        workload_class: score_class(
            rows,
            epoch,
            board,
            workload_class,
            shrinkage_lambda=policy.shrinkage_lambda,
            audit_anchor_commit=policy.audit_anchor_commit,
        )
        for workload_class in scored_classes
    }
    ratio = math.exp(
        sum(score.log_ratio for score in scores.values()) / len(scores)
    )
    audited_ratio = math.exp(
        sum(math.log(score.audited_ratio) for score in scores.values())
        / len(scores)
    )
    return {
        "method": "metrics_v2_scored_class_geomean_v2",
        "epoch": epoch,
        "classes": list(scored_classes),
        "class_ratios": {
            workload_class: score.ratio
            for workload_class, score in scores.items()
        },
        "audited_class_ratios": {
            workload_class: score.audited_ratio
            for workload_class, score in scores.items()
        },
        "active_credit_events": {
            workload_class: len(score.active_events)
            for workload_class, score in scores.items()
        },
        "ratio_geomean": ratio,
        "audited_ratio_geomean": audited_ratio,
        "index": 100.0 * ratio,
        "speedup": 1.0 / ratio,
    }


def due_state(
    rows: list[ledger.Row],
    epoch: int,
    board: str,
    workload_class: str,
    *,
    policy: AuditPolicy,
) -> DueState:
    """Return deterministic span/direct-audit work due for one score cell."""
    _validate_policy(policy)
    score = score_class(
        rows, epoch, board, workload_class,
        shrinkage_lambda=policy.shrinkage_lambda,
        audit_anchor_commit=policy.audit_anchor_commit,
    )
    class_rows = _class_rows(rows, epoch, board, workload_class)
    last_direct_index = max(
        (
            index for index, row in enumerate(class_rows)
            if row.evidence_kind == "direct_audit" and _crediting(row)
        ),
        default=-1,
    )
    post_audit = class_rows[last_direct_index + 1:]
    promotions = [row for row in post_audit if row.evidence_kind == "promotion"]
    measured_by_span = {
        observation
        for row in post_audit
        if row.evidence_kind == "span_audit"
        and row.gates_passed and row.outcome != "rejected"
        for observation in row.covers
    }
    span_pending = [
        row for row in promotions
        if row.gates_passed
        and row.outcome == "neutral"
        and row.observation_id not in measured_by_span
    ]
    point_log = sum(
        math.log(row.judged_r) for row in span_pending if row.judged_r > 0
    )
    threshold_log = -math.log1p(-policy.span_effect_theta)
    reasons = []
    if len(span_pending) >= policy.span_every:
        reasons.append("landed_cadence")
    if abs(point_log) >= threshold_log:
        reasons.append("subfloor_effect")
    direct_replaces = tuple(
        event.row_id for event in score.active_events
        if event.evidence_kind != "direct_audit"
    )
    return DueState(
        epoch=epoch,
        board=board,
        workload_class=workload_class,
        audited_through=score.audited_through,
        span_due=bool(reasons),
        span_reasons=tuple(reasons),
        span_covers=tuple(row.observation_id for row in span_pending),
        span_point_r=math.exp(point_log),
        direct_audit_due=len(promotions) >= policy.direct_every,
        direct_audit_replaces=direct_replaces,
    )


def audit_projection(
    rows: list[ledger.Row],
    epoch: int,
    board: str,
    workload_class: str,
    *,
    policy: AuditPolicy,
) -> AuditProjection:
    """Project score, coverage, evidence share, and cadence from ledger state.

    This intentionally excludes wall-clock and git-graph age. Those are
    deterministic repository projections layered on by the feed producer.
    """
    state = due_state(
        rows, epoch, board, workload_class, policy=policy,
    )
    score = score_class(
        rows,
        epoch,
        board,
        workload_class,
        shrinkage_lambda=policy.shrinkage_lambda,
        audit_anchor_commit=policy.audit_anchor_commit,
    )
    class_rows = _class_rows(rows, epoch, board, workload_class)
    last_direct_index = max(
        (
            index for index, row in enumerate(class_rows)
            if row.evidence_kind == "direct_audit" and _crediting(row)
        ),
        default=-1,
    )
    post_audit = class_rows[last_direct_index + 1:]
    promotions = [row for row in post_audit if row.evidence_kind == "promotion"]
    neutral = [
        row for row in promotions
        if row.gates_passed and row.outcome == "neutral"
    ]
    consumed = {
        observation
        for row in post_audit
        if row.evidence_kind == "span_audit"
        and row.gates_passed
        and row.outcome != "rejected"
        for observation in row.covers
    }
    pending = [row for row in neutral if row.observation_id not in consumed]
    evidence_rows = [
        row for row in class_rows
        if row.evidence_kind in ("promotion", "direct_audit", "span_audit")
    ]
    claimed = sum(row.verdict_kind == "claimed" for row in evidence_rows)
    judged = sum(row.verdict_kind == "judged" for row in evidence_rows)
    return AuditProjection(
        effective_score=score.ratio,
        audited_score=score.audited_ratio,
        audited_through=score.audited_through,
        audit_base=score.audited_through or policy.audit_anchor_commit,
        unaudited_tail=tuple(row.observation_id for row in promotions),
        span_due=state.span_due,
        span_overdue_by=max(0, len(pending) - policy.span_every),
        span_reasons=state.span_reasons,
        direct_due=state.direct_audit_due,
        direct_overdue_by=max(0, len(promotions) - policy.direct_every),
        neutral_observations=len(neutral),
        span_consumed=len(consumed),
        span_pending=len(pending),
        claimed_observations=claimed,
        judged_observations=judged,
    )
