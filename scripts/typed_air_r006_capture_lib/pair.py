"""Paired CPU/Metal planning, resumable capture, and raw receipt replay.

One immutable authority interleaves the two 1/2/4/max-worker lane schedules at
attempt granularity.  Each lane keeps a durable create-only journal; the pair
journal is a derivative commit log and can repair only a missing suffix after
a process interruption.  It can never skip, retry, reorder, or overwrite an
attempt.
"""

from __future__ import annotations

import copy
import datetime as dt
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    write_new,
)
from .contract import (
    ClosureProvider,
    HostProvider,
    PlanSettings,
    SourceProvider,
    WorkloadPaths,
    build_plan,
    global_exact_work_closure,
    host_identity,
    source_identity,
    validate_global_exact_work_closure,
    validate_plan,
)
from .controller import ProcessResult, default_child_runner, run_attempt
from .model import (
    BUNDLE_SCHEMA,
    COOLDOWN_NS,
    DIGEST_RE,
    PLAN_ATTEMPTS,
    SESSION_RE,
    UTC_RE,
    CaptureError,
)
from .orchestration import INSTALL_LANES, host_preflight
from . import post_capture_quieting as quieting
from . import pair_durability as durability
from . import pair_identity
from . import pair_publication as publication
from .preflight import validate_host_preflight


PAIR_PLAN_SCHEMA = "stwo.typed-air.r006-paired-capture-plan.v3"
PAIR_PROGRESS_HEADER_SCHEMA = durability.PAIR_PROGRESS_HEADER_SCHEMA
PAIR_PROGRESS_RECORD_SCHEMA = durability.PAIR_PROGRESS_RECORD_SCHEMA
PAIR_BUNDLE_SCHEMA = "stwo.typed-air.r006-paired-raw-bundle.v2"
PAIR_VALIDATION_SCHEMA = "stwo.typed-air.r006-paired-bundle-validation.v3"
PAIR_LANE_ORDER = INSTALL_LANES
PAIR_ATTEMPTS = len(PAIR_LANE_ORDER) * PLAN_ATTEMPTS

PAIR_PLAN_FIELDS = {
    "schema",
    "schema_version",
    "classification",
    "created_at_utc",
    "session_id",
    "source",
    "global_exact_work_closure",
    "host",
    "host_preflight",
    "lanes",
    "schedule",
    "interleaving",
    "content_sha256",
}
PAIR_SCHEDULE = {
    "strategy": "attempt-ordinal-cpu-then-metal-v1",
    "lane_order": list(PAIR_LANE_ORDER),
    "attempts_per_lane": PLAN_ATTEMPTS,
    "total_attempts": PAIR_ATTEMPTS,
    "fresh_process_per_attempt": True,
    "serial_attempts": True,
    "cooldown_ns_after_each_global_attempt": COOLDOWN_NS,
    "retry_failed_attempts": False,
    "resumption": "durable-complete-attempt-prefix-only",
    "post_capture_quieting": quieting.POST_CAPTURE_QUIETING_POLICY,
}
PAIR_BUNDLE_FIELDS = {
    "schema",
    "schema_version",
    "status",
    "session_id",
    "plan_sha256",
    "started_at_utc",
    "completed_at_utc",
    "planned_attempts",
    "recorded_attempts",
    "verified_attempts",
    "failed_attempts",
    "start_preflight",
    "end_preflight",
    "lanes",
    "pair_journal",
    "attempt_publication_journal",
    "preflight_boundary_journal",
    "cross_lane_identity_workloads",
    "independent_verifier_attempts",
    "exact_work_v4_attempts",
    "content_sha256",
}


Clock = Callable[[], dt.datetime]
PreflightProvider = Callable[[], dict[str, Any]]
ChildRunner = Callable[[Sequence[str], Path, float, Mapping[str, str]], ProcessResult]


@dataclass(frozen=True)
class PairPlanSettings:
    repository: Path
    session_id: str
    power_state: str
    cpu_executable: Path
    metal_executable: Path
    workloads: Mapping[str, WorkloadPaths]
    toolchain: str
    target: str
    cpu_features: str


@dataclass(frozen=True)
class PairCaptureSettings:
    repository: Path
    plan_path: Path
    bundle_path: Path
    execute_frozen_2080_attempt_schedule: bool
    timeout_seconds: float = 86_400.0
    max_new_attempts: int | None = None


def _utc(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        raise CaptureError("paired capture clock returned a naive timestamp")
    return (
        value.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _interleaving(lanes: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for lane_ordinal in range(PLAN_ATTEMPTS):
        for lane in PAIR_LANE_ORDER:
            attempt = lanes[lane]["attempts"][lane_ordinal]
            result.append(
                {
                    "global_ordinal": len(result),
                    "lane": lane,
                    "lane_ordinal": lane_ordinal,
                    "attempt_id": attempt["attempt_id"],
                    "attempt_sha256": content_digest(attempt),
                }
            )
    return result


def _preflight_matches_plan(
    preflight: dict[str, Any],
    host: dict[str, Any],
) -> None:
    evidence = preflight["host"]
    power = host["power_state"]
    if (
        evidence.get("os") != host["os"]
        or evidence.get("logical_cpu_count") != host["logical_cores"]
        or evidence.get("power_source") != power["power_source"]
        or evidence.get("low_power_mode") is not power["low_power_mode"]
    ):
        raise CaptureError("paired plan host and quiet-host preflight disagree")


def build_pair_plan(
    settings: PairPlanSettings,
    *,
    source_provider: SourceProvider = source_identity,
    host_provider: HostProvider = host_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
    preflight_provider: PreflightProvider = host_preflight,
    clock: Clock = lambda: dt.datetime.now(dt.timezone.utc),
) -> dict[str, Any]:
    repository = settings.repository.resolve()
    if SESSION_RE.fullmatch(settings.session_id) is None:
        raise CaptureError("paired R-006 session ID is invalid")
    source = source_provider(repository)
    if (
        type(source) is not dict
        or source.get("clean_status") is not True
        or source.get("ephemeral") is True
    ):
        raise CaptureError("paired normative planning rejects ephemeral or dirty source")
    global_closure = validate_global_exact_work_closure(
        closure_provider(repository)
    )
    host = host_provider(settings.power_state)
    preflight = validate_host_preflight(
        preflight_provider(),
        require_admitted=True,
    )
    _preflight_matches_plan(preflight, host)
    created = _utc(clock)
    executable = {
        "cpu-native": settings.cpu_executable,
        "metal-hybrid": settings.metal_executable,
    }
    lanes: dict[str, dict[str, Any]] = {}
    for lane in PAIR_LANE_ORDER:
        lane_plan = build_plan(
            PlanSettings(
                repository=repository,
                session_id=f"{settings.session_id}.{lane}",
                lane=lane,
                power_state=settings.power_state,
                executable=executable[lane],
                workloads=settings.workloads,
                toolchain=settings.toolchain,
                target=settings.target,
                cpu_features=settings.cpu_features,
            ),
            source_provider=lambda _repository, frozen=source: frozen,
            host_provider=lambda _declaration, frozen=host: frozen,
            closure_provider=lambda _repository, frozen=global_closure: frozen,
            clock=lambda frozen=created: dt.datetime.strptime(
                frozen, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=dt.timezone.utc),
        )
        lanes[lane] = lane_plan
    document: dict[str, Any] = {
        "schema": PAIR_PLAN_SCHEMA,
        "schema_version": 3,
        "classification": "normative-pre-execution-paired-capture-authority",
        "created_at_utc": created,
        "session_id": settings.session_id,
        "source": source,
        "global_exact_work_closure": global_closure,
        "host": host,
        "host_preflight": preflight,
        "lanes": lanes,
        "schedule": copy.deepcopy(PAIR_SCHEDULE),
        "interleaving": _interleaving(lanes),
    }
    document["content_sha256"] = content_digest(document)
    return validate_pair_plan(
        document,
        repository=repository,
        verify_local=False,
        source_provider=lambda _repository, frozen=source: frozen,
        closure_provider=lambda _repository, frozen=global_closure: frozen,
    )


def validate_pair_plan(
    value: Any,
    *,
    repository: Path,
    verify_local: bool,
    source_provider: SourceProvider = source_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
) -> dict[str, Any]:
    plan = exact_object(value, PAIR_PLAN_FIELDS, "paired R-006 capture plan")
    if (
        plan["schema"] != PAIR_PLAN_SCHEMA
        or plan["schema_version"] != 3
        or plan["classification"]
        != "normative-pre-execution-paired-capture-authority"
        or type(plan["created_at_utc"]) is not str
        or UTC_RE.fullmatch(plan["created_at_utc"]) is None
        or type(plan["session_id"]) is not str
        or SESSION_RE.fullmatch(plan["session_id"]) is None
        or plan["schedule"] != PAIR_SCHEDULE
        or type(plan["content_sha256"]) is not str
        or DIGEST_RE.fullmatch(plan["content_sha256"]) is None
        or plan["content_sha256"] != content_digest(plan)
    ):
        raise CaptureError("paired R-006 plan authority changed")
    global_closure = validate_global_exact_work_closure(
        plan["global_exact_work_closure"]
    )
    if verify_local:
        live_closure = validate_global_exact_work_closure(
            closure_provider(repository.resolve())
        )
        if live_closure != global_closure:
            raise CaptureError(
                "P-003 global exact-work closure changed after paired planning"
            )
    validate_host_preflight(plan["host_preflight"], require_admitted=True)
    if type(plan["lanes"]) is not dict or tuple(plan["lanes"]) != PAIR_LANE_ORDER:
        raise CaptureError("paired R-006 lane order changed")
    lanes: dict[str, dict[str, Any]] = plan["lanes"]
    for lane in PAIR_LANE_ORDER:
        lane_plan = validate_plan(
            lanes[lane],
            repository=repository.resolve(),
            verify_local=verify_local,
            source_provider=source_provider,
            closure_provider=lambda _repository, frozen=global_closure: frozen,
        )
        if lane_plan["lane"]["id"] != lane:
            raise CaptureError("paired R-006 lane plan is stored under the wrong lane")
        if lane_plan["session_id"] != f"{plan['session_id']}.{lane}":
            raise CaptureError("paired R-006 lane session identity changed")
        if lane_plan["source"] != plan["source"] or lane_plan["host"] != plan["host"]:
            raise CaptureError("paired R-006 lanes disagree on source or host")
        if lane_plan["global_exact_work_closure"] != global_closure:
            raise CaptureError("paired R-006 lanes disagree on global exact-work closure")
    _preflight_matches_plan(plan["host_preflight"], plan["host"])
    if (
        lanes["cpu-native"]["protocol"] != lanes["metal-hybrid"]["protocol"]
        or lanes["cpu-native"]["workloads"] != lanes["metal-hybrid"]["workloads"]
        or lanes["cpu-native"]["worker_arms"] != lanes["metal-hybrid"]["worker_arms"]
    ):
        raise CaptureError("paired R-006 lanes disagree on protocol, workloads, or workers")
    if plan["interleaving"] != _interleaving(lanes):
        raise CaptureError("paired R-006 attempt interleaving changed")
    return plan


def write_pair_plan_new(path: Path, plan: dict[str, Any]) -> bytes:
    payload = canonical_bytes(plan)
    write_new(path, payload)
    return payload


def load_pair_plan(
    path: Path,
    *,
    repository: Path,
    verify_local: bool,
    source_provider: SourceProvider = source_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read paired R-006 plan") from error
    value = decode_strict(raw)
    if raw != canonical_bytes(value):
        raise CaptureError("paired R-006 plan is not canonical JSON")
    return validate_pair_plan(
        value,
        repository=repository,
        verify_local=verify_local,
        source_provider=source_provider,
        closure_provider=closure_provider,
    )


ResumableLaneJournal = durability.ResumableLaneJournal
PairProgressJournal = durability.PairProgressJournal
_progress_record = durability.progress_record
_completed_interleaving = durability.completed_interleaving


def _lane_manifest(
    plan: dict[str, Any],
    records: list[dict[str, Any]],
    journal: dict[str, Any],
    *,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    verified = sum(record["status"] == "verified" for record in records)
    failed = len(records) - verified
    result: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": 1,
        "status": (
            "CAPTURE_COMPLETE_WITH_FAILURES"
            if failed
            else "CAPTURE_COMPLETE_AWAITING_STATISTICAL_RECEIPT"
        ),
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "planned_attempts": PLAN_ATTEMPTS,
        "recorded_attempts": len(records),
        "verified_attempts": verified,
        "failed_attempts": failed,
        "journal": journal,
    }
    result["content_sha256"] = content_digest(result)
    return result


def _durable_prefix_is_complete(root: Path, plan: dict[str, Any]) -> bool:
    required = (
        root / "pair-journal.ndjson",
        root / publication.PUBLICATION_JOURNAL_NAME,
        root / durability.BOUNDARY_JOURNAL_NAME,
        *(root / lane / "journal.ndjson" for lane in PAIR_LANE_ORDER),
    )
    if any(not (path.exists() or path.is_symlink()) for path in required):
        return False
    lane_records: dict[str, list[dict[str, Any]]] = {}
    for lane in PAIR_LANE_ORDER:
        records = durability.read_journal_regular(
            root / lane / "journal.ndjson", "paired lane completion probe"
        )
        lane_records[lane] = records[1:]
    if any(len(lane_records[lane]) != PLAN_ATTEMPTS for lane in PAIR_LANE_ORDER):
        return False
    publication_summary, _ = publication.read_publication_journal(
        root / publication.PUBLICATION_JOURNAL_NAME,
        plan=plan,
        lane_records=lane_records,
        require_complete=False,
    )
    if (
        publication_summary["committed_attempts"] != PAIR_ATTEMPTS
        or publication_summary["pending"] is not None
    ):
        return False
    expected_progress = _completed_interleaving(plan, lane_records)
    progress = durability.read_journal_regular(
        root / "pair-journal.ndjson", "paired progress completion probe"
    )
    if len(progress) != PAIR_ATTEMPTS + 1 or progress[1:] != expected_progress:
        raise CaptureError("complete paired progress journal is not lane-derived")
    boundary_summary, _ = durability.read_boundary_journal(
        root / durability.BOUNDARY_JOURNAL_NAME,
        plan=plan,
        completed_attempts=PAIR_ATTEMPTS,
        require_complete=False,
    )
    return (
        boundary_summary["open_start"] is None
        and boundary_summary["closed_prefix"] == PAIR_ATTEMPTS
    )


def capture_pair(
    settings: PairCaptureSettings,
    *,
    child_runner: ChildRunner = default_child_runner,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], int] = time.monotonic_ns,
    clock: Clock = lambda: dt.datetime.now(dt.timezone.utc),
    preflight_provider: PreflightProvider = host_preflight,
    source_provider: SourceProvider = source_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
) -> dict[str, Any]:
    if not settings.execute_frozen_2080_attempt_schedule:
        raise CaptureError("paired capture requires its explicit 2080-attempt execution token")
    if settings.timeout_seconds <= 0:
        raise CaptureError("paired capture timeout must be positive")
    if (
        settings.max_new_attempts is not None
        and (type(settings.max_new_attempts) is not int or settings.max_new_attempts <= 0)
    ):
        raise CaptureError("paired capture chunk size must be a positive integer")
    repository = settings.repository.resolve()
    plan = load_pair_plan(
        settings.plan_path,
        repository=repository,
        verify_local=True,
        source_provider=source_provider,
        closure_provider=closure_provider,
    )
    root = settings.bundle_path.absolute()
    plan_bytes = canonical_bytes(plan)
    root_exists = root.exists() or root.is_symlink()
    if root_exists:
        durability.require_regular_directory(root, "paired capture bundle")
        stored_plan = root / "pair-plan.json"
        if not (stored_plan.exists() or stored_plan.is_symlink()):
            if any(root.iterdir()):
                raise CaptureError("resumed paired capture is missing its plan")
            durability.publish_new_or_identical(
                stored_plan, plan_bytes, staging_directory=root.parent
            )
        elif durability.read_regular_bytes(stored_plan, "paired capture plan") != plan_bytes:
            raise CaptureError("resumed paired capture plan bytes changed")
        completed_manifest = root / "pair-bundle.json"
        if completed_manifest.exists() or completed_manifest.is_symlink():
            validate_pair_bundle(repository, root)
            return durability.read_canonical_json_regular(
                completed_manifest, "completed paired capture manifest"
            )
    else:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        durability.publish_new_or_identical(
            root / "pair-plan.json", plan_bytes, staging_directory=root.parent
        )
    durable_complete = _durable_prefix_is_complete(root, plan)
    start_preflight = None
    if not durable_complete:
        start_preflight = quieting.require_admitted_preflight(
            preflight_provider,
            plan["host_preflight"]["host"],
        )
    journals: dict[str, ResumableLaneJournal] = {}
    progress: PairProgressJournal | None = None
    boundaries: durability.PreflightBoundaryJournal | None = None
    publications: publication.AttemptPublicationJournal | None = None
    try:
        publications = publication.AttemptPublicationJournal(root, plan)
        publication_state = publications.summary(
            lane_records=None, require_complete=False
        )["pending"]
        if publication_state is not None and publication_state["phase"] == "intent":
            raise CaptureError(
                "catastrophic interruption left an unresolved attempt intent; "
                "the child may already have executed, so start a fresh paired bundle"
            )
        for lane in PAIR_LANE_ORDER:
            pending_record = None
            if (
                publication_state is not None
                and publication_state["phase"] == "prepared"
                and publication_state["schedule"]["lane"] == lane
            ):
                pending_record = publication_state["record"]
            journals[lane] = ResumableLaneJournal(
                root / lane,
                plan["lanes"][lane],
                canonical_bytes(plan["lanes"][lane]),
                repository=repository,
                pending_record=pending_record,
            )
        lane_records = {
            lane: journals[lane].completed_records for lane in PAIR_LANE_ORDER
        }
        completed = _completed_interleaving(plan, lane_records)
        publications.summary(lane_records=lane_records, require_complete=False)
        progress = PairProgressJournal(
            root, plan, lane_records, started_at_utc=_utc(clock)
        )
        if publication_state is not None and publication_state["phase"] == "prepared":
            scheduled = publication_state["schedule"]
            lane = scheduled["lane"]
            if len(journals[lane].completed_records) == scheduled["lane_ordinal"]:
                sealed = journals[lane].append(publication_state["record"])
                if sealed != publication_state["record"]:
                    raise CaptureError("prepared attempt changed during lane recovery")
                journals[lane].completed_records.append(sealed)
                progress.append(_progress_record(scheduled, sealed), sealed=True)
            publications.commit(scheduled)
            completed = _completed_interleaving(plan, lane_records)
        publications.summary(lane_records=lane_records, require_complete=False)
        boundaries = durability.PreflightBoundaryJournal(root, plan, len(completed))
        if durable_complete:
            if len(completed) != PAIR_ATTEMPTS:
                raise CaptureError("durable completion probe changed during replay")
            boundaries.summary(
                completed_attempts=len(completed), require_complete=True
            )
            invocation_open = False
        else:
            assert start_preflight is not None
            invocation_open = boundaries.admit(start_preflight, len(completed))
        new_attempts = 0
        for scheduled in plan["interleaving"][len(completed) :]:
            if (
                settings.max_new_attempts is not None
                and new_attempts >= settings.max_new_attempts
            ):
                break
            lane = scheduled["lane"]
            lane_plan = plan["lanes"][lane]
            attempt = lane_plan["attempts"][scheduled["lane_ordinal"]]
            publications.begin(scheduled, root / lane, attempt)
            record = run_attempt(
                journal=journals[lane],
                plan=lane_plan,
                attempt=attempt,
                timeout_seconds=settings.timeout_seconds,
                child_runner=child_runner,
                monotonic=monotonic,
                utc_clock=clock,
                record_stager=lambda value, frozen=scheduled: publications.prepare(
                    frozen, value
                ),
            )
            pending = publications.summary(
                lane_records=None, require_complete=False
            )["pending"]
            if pending is None or pending["phase"] != "prepared":
                raise CaptureError("attempt returned without a prepared publication")
            sealed = journals[lane].append(record)
            if sealed != pending["record"]:
                raise CaptureError("prepared attempt differs from its lane commit")
            journals[lane].completed_records.append(sealed)
            progress.append(_progress_record(scheduled, sealed), sealed=True)
            publications.commit(scheduled)
            completed.append(_progress_record(scheduled, sealed))
            new_attempts += 1
            if len(completed) < PAIR_ATTEMPTS:
                sleeper(COOLDOWN_NS / 1_000_000_000)
        complete = len(completed) == PAIR_ATTEMPTS
        if invocation_open:
            validate_pair_plan(
                plan,
                repository=repository,
                verify_local=True,
                source_provider=source_provider,
                closure_provider=closure_provider,
            )
            checkpoint_preflight = quieting.await_admitted_post_capture_preflight(
                provider=preflight_provider,
                expected_host=plan["host_preflight"]["host"],
                sleeper=sleeper,
                monotonic=monotonic,
            )
            boundaries.checkpoint(checkpoint_preflight, len(completed))
        boundary_summary = boundaries.summary(
            completed_attempts=len(completed), require_complete=complete
        )
        publications.summary(lane_records=lane_records, require_complete=complete)
        journal_identities = {
            lane: journals[lane].close() for lane in PAIR_LANE_ORDER
        }
        progress_identity = progress.close()
        publication_identity = publications.close()
        boundary_identity = boundaries.close()
    except BaseException:
        for journal in journals.values():
            journal.abandon()
        if progress is not None:
            progress.abandon()
        if publications is not None:
            publications.abandon()
        if boundaries is not None:
            boundaries.abandon()
        raise
    counts = {
        lane: len(journals[lane].completed_records) for lane in PAIR_LANE_ORDER
    }
    if not complete:
        return {
            "schema": "stwo.typed-air.r006-paired-capture-checkpoint.v1",
            "status": "CAPTURE_PAUSED_AT_DURABLE_PREFIX",
            "session_id": plan["session_id"],
            "plan_sha256": plan["content_sha256"],
            "completed_attempts": len(completed),
            "remaining_attempts": PAIR_ATTEMPTS - len(completed),
            "lane_attempts": counts,
            "new_attempts": new_attempts,
            "checkpoint_preflight": boundary_summary["final_preflight"],
            "attempt_publication_journal": publication_identity,
            "preflight_boundary_journal": boundary_identity,
            "normative_performance_receipt": False,
        }
    start_boundary = boundary_summary["first_preflight"]
    end_boundary = boundary_summary["final_preflight"]
    if start_boundary is None or end_boundary is None:
        raise CaptureError("complete paired capture lacks preflight boundaries")
    completed_at = end_boundary["captured_at_utc"]
    cross_lane_identities = len(
        pair_identity.validate_pair_identity_authority(
            plan,
            {
                lane: journals[lane].completed_records
                for lane in PAIR_LANE_ORDER
            },
            PAIR_LANE_ORDER,
        )
    )
    lane_summaries: dict[str, dict[str, Any]] = {}
    lane_payloads: dict[str, bytes] = {}
    verified = 0
    failed = 0
    exact_work = 0
    independent = 0
    for lane in PAIR_LANE_ORDER:
        records = journals[lane].completed_records
        manifest = _lane_manifest(
            plan["lanes"][lane],
            records,
            journal_identities[lane],
            started_at=progress.header["started_at_utc"],
            completed_at=completed_at,
        )
        lane_payloads[lane] = canonical_bytes(manifest)
        lane_verified = sum(record["status"] == "verified" for record in records)
        lane_failed = PLAN_ATTEMPTS - lane_verified
        verified += lane_verified
        failed += lane_failed
        exact_work += sum(
            record["status"] == "verified"
            and record["metrics"] is not None
            and "work_disclosure" in record["metrics"]
            for record in records
        )
        independent += sum(
            record["independent_verification"]["status"] == "verified"
            for record in records
        )
        lane_summaries[lane] = {
            "path": lane,
            "plan_sha256": plan["lanes"][lane]["content_sha256"],
            "attempts": len(records),
            "verified_attempts": lane_verified,
            "failed_attempts": lane_failed,
            "journal": journal_identities[lane],
            "bundle_sha256": manifest["content_sha256"],
        }
    result: dict[str, Any] = {
        "schema": PAIR_BUNDLE_SCHEMA,
        "schema_version": 2,
        "status": (
            "CAPTURE_COMPLETE_WITH_FAILURES"
            if failed
            else "CAPTURE_COMPLETE_AWAITING_STATISTICAL_RECEIPT"
        ),
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "started_at_utc": progress.header["started_at_utc"],
        "completed_at_utc": completed_at,
        "planned_attempts": PAIR_ATTEMPTS,
        "recorded_attempts": PAIR_ATTEMPTS,
        "verified_attempts": verified,
        "failed_attempts": failed,
        "start_preflight": start_boundary,
        "end_preflight": end_boundary,
        "lanes": lane_summaries,
        "pair_journal": progress_identity,
        "attempt_publication_journal": publication_identity,
        "preflight_boundary_journal": boundary_identity,
        "cross_lane_identity_workloads": cross_lane_identities,
        "independent_verifier_attempts": independent,
        "exact_work_v4_attempts": exact_work,
    }
    result["content_sha256"] = content_digest(result)
    durability.publish_pair_manifests(
        root, lane_payloads, canonical_bytes(result)
    )
    return result


def validate_pair_bundle(
    repository: Path,
    bundle_path: Path,
    *,
    include_snapshot: bool = False,
) -> dict[str, Any]:
    from .pair_validation import validate_pair_bundle as validate

    return validate(
        repository, bundle_path, include_snapshot=include_snapshot
    )
