"""Paired CPU/Metal planning, resumable capture, and raw receipt replay.

One immutable authority interleaves the two 1/2/4/max-worker lane schedules at
attempt granularity.  Each lane keeps a durable create-only journal; the pair
journal is a derivative commit log and can repair only a missing suffix after
a process interruption.  It can never skip, retry, reorder, or overwrite an
attempt.
"""

from __future__ import annotations

import datetime as dt
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_file,
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
from .controller import (
    JOURNAL_HEADER_SCHEMA,
    FileInventory,
    Journal,
    ProcessResult,
    _journal,
    _validate_record,
    default_child_runner,
    run_attempt,
    validate_bundle,
)
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
from .preflight import validate_host_preflight


PAIR_PLAN_SCHEMA = "stwo.typed-air.r006-paired-capture-plan.v2"
PAIR_PROGRESS_HEADER_SCHEMA = "stwo.typed-air.r006-pair-progress-header.v1"
PAIR_PROGRESS_RECORD_SCHEMA = "stwo.typed-air.r006-pair-progress-record.v1"
PAIR_BUNDLE_SCHEMA = "stwo.typed-air.r006-paired-raw-bundle.v1"
PAIR_VALIDATION_SCHEMA = "stwo.typed-air.r006-paired-bundle-validation.v1"
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
        "schema_version": 2,
        "classification": "normative-pre-execution-paired-capture-authority",
        "created_at_utc": created,
        "session_id": settings.session_id,
        "source": source,
        "global_exact_work_closure": global_closure,
        "host": host,
        "host_preflight": preflight,
        "lanes": lanes,
        "schedule": dict(PAIR_SCHEDULE),
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
        or plan["schema_version"] != 2
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


class ResumableLaneJournal(Journal):
    """A lane journal that reopens only an authenticated attempt prefix."""

    completed_records: list[dict[str, Any]]

    def __init__(
        self,
        bundle: Path,
        plan: dict[str, Any],
        plan_bytes: bytes,
    ) -> None:
        if not bundle.exists():
            super().__init__(bundle, plan, plan_bytes)
            self.completed_records = []
            return
        self.bundle = bundle.resolve()
        if self.bundle.is_symlink() or not self.bundle.is_dir():
            raise CaptureError("resumed R-006 lane bundle is not a regular directory")
        if (self.bundle / "bundle.json").exists():
            raise CaptureError("cannot resume an already completed R-006 lane bundle")
        inventory = FileInventory(self.bundle)
        if inventory.root_file("plan.json") != plan_bytes:
            raise CaptureError("resumed R-006 lane plan bytes changed")
        journal_raw = inventory.root_file("journal.ndjson")
        records = _journal(self.bundle / "journal.ndjson")
        if not records or canonical_bytes(records[0]) not in journal_raw:
            raise CaptureError("resumed R-006 lane journal lacks its header")
        header = exact_object(
            records[0],
            {
                "schema",
                "session_id",
                "plan_sha256",
                "planned_attempts",
                "content_sha256",
            },
            "resumed lane journal header",
        )
        if (
            header["schema"] != JOURNAL_HEADER_SCHEMA
            or header["session_id"] != plan["session_id"]
            or header["plan_sha256"] != plan["content_sha256"]
            or header["planned_attempts"] != PLAN_ATTEMPTS
        ):
            raise CaptureError("resumed R-006 lane journal header changed")
        prior = records[1:]
        if len(prior) > PLAN_ATTEMPTS:
            raise CaptureError("resumed R-006 lane journal exceeds its plan")
        for attempt, record in zip(plan["attempts"], prior, strict=False):
            _validate_record(
                record,
                plan=plan,
                attempt=attempt,
                inventory=inventory,
            )
        inventory.finish()
        descriptor = os.open(self.bundle / "journal.ndjson", os.O_WRONLY | os.O_APPEND)
        self.path = self.bundle / "journal.ndjson"
        self.output = os.fdopen(descriptor, "wb", buffering=0)
        self.closed = False
        self.records = len(records)
        self.completed_records = prior


class PairProgressJournal:
    def __init__(
        self,
        root: Path,
        plan: dict[str, Any],
        lane_records: Mapping[str, list[dict[str, Any]]],
        *,
        clock: Clock,
    ) -> None:
        self.path = root / "pair-journal.ndjson"
        self.closed = False
        expected = _completed_interleaving(plan, lane_records)
        if not self.path.exists():
            if expected:
                raise CaptureError(
                    "paired progress journal is missing after lane attempts were recorded"
                )
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            self.output = os.fdopen(descriptor, "wb", buffering=0)
            self.records: list[dict[str, Any]] = []
            self.header = self.append(
                {
                    "schema": PAIR_PROGRESS_HEADER_SCHEMA,
                    "session_id": plan["session_id"],
                    "plan_sha256": plan["content_sha256"],
                    "planned_attempts": PAIR_ATTEMPTS,
                    "started_at_utc": _utc(clock),
                }
            )
        else:
            records = _journal(self.path)
            if not records:
                raise CaptureError("paired R-006 progress journal is empty")
            header = exact_object(
                records[0],
                {
                    "schema",
                    "session_id",
                    "plan_sha256",
                    "planned_attempts",
                    "started_at_utc",
                    "content_sha256",
                },
                "paired progress header",
            )
            if (
                header["schema"] != PAIR_PROGRESS_HEADER_SCHEMA
                or header["session_id"] != plan["session_id"]
                or header["plan_sha256"] != plan["content_sha256"]
                or header["planned_attempts"] != PAIR_ATTEMPTS
                or type(header["started_at_utc"]) is not str
                or UTC_RE.fullmatch(header["started_at_utc"]) is None
            ):
                raise CaptureError("paired R-006 progress header changed")
            self.header = header
            self.records = records
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND)
            self.output = os.fdopen(descriptor, "wb", buffering=0)
        recorded = self.records[1:]
        if len(recorded) > len(expected):
            raise CaptureError("paired progress journal is ahead of lane evidence")
        for actual, derived in zip(recorded, expected):
            if actual != derived:
                raise CaptureError("paired progress journal differs from lane evidence")
        for record in expected[len(recorded) :]:
            self.append(record, sealed=True)

    def append(self, value: dict[str, Any], *, sealed: bool = False) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("paired progress journal is closed")
        record = dict(value)
        if not sealed:
            record["content_sha256"] = content_digest(record)
        elif record.get("content_sha256") != content_digest(record):
            raise CaptureError("derived paired progress record is not sealed")
        self.output.write(canonical_bytes(record))
        os.fsync(self.output.fileno())
        self.records.append(record)
        return record

    def close(self) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("paired progress journal closed twice")
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True
        size, digest = sha256_file(self.path)
        return {
            "path": "pair-journal.ndjson",
            "bytes": size,
            "sha256": digest,
            "records": len(self.records),
        }

    def abandon(self) -> None:
        if self.closed:
            return
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True


def _progress_record(
    schedule: dict[str, Any],
    lane_record: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": PAIR_PROGRESS_RECORD_SCHEMA,
        "global_ordinal": schedule["global_ordinal"],
        "lane": schedule["lane"],
        "lane_ordinal": schedule["lane_ordinal"],
        "attempt_id": schedule["attempt_id"],
        "attempt_record_sha256": lane_record["content_sha256"],
        "attempt_status": lane_record["status"],
        "completed_at_utc": lane_record["completed_at_utc"],
    }
    result["content_sha256"] = content_digest(result)
    return result


def _completed_interleaving(
    plan: dict[str, Any],
    lane_records: Mapping[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    consumed = {lane: 0 for lane in PAIR_LANE_ORDER}
    result: list[dict[str, Any]] = []
    for scheduled in plan["interleaving"]:
        lane = scheduled["lane"]
        index = consumed[lane]
        if index >= len(lane_records[lane]):
            break
        if scheduled["lane_ordinal"] != index:
            raise CaptureError("paired lane records are not a global schedule prefix")
        result.append(_progress_record(scheduled, lane_records[lane][index]))
        consumed[lane] += 1
    if any(consumed[lane] != len(lane_records[lane]) for lane in PAIR_LANE_ORDER):
        raise CaptureError("paired lane journals do not form one interleaved prefix")
    return result


def _live_preflight(
    plan: dict[str, Any],
    provider: PreflightProvider,
) -> dict[str, Any]:
    current = validate_host_preflight(provider(), require_admitted=True)
    if current["host"] != plan["host_preflight"]["host"]:
        raise CaptureError("paired R-006 host identity changed since planning")
    return current


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


def _cross_lane_identity_count(
    plan: dict[str, Any],
    lane_records: Mapping[str, list[dict[str, Any]]],
) -> int:
    identities: dict[str, dict[str, Any]] = {}
    for lane in PAIR_LANE_ORDER:
        for attempt, record in zip(
            plan["lanes"][lane]["attempts"],
            lane_records[lane],
            strict=True,
        ):
            if record["status"] != "verified":
                continue
            workload = attempt["workload_id"]
            prior = identities.setdefault(workload, record["identity"])
            if prior != record["identity"]:
                raise CaptureError(
                    f"CPU/Metal proof identity changed for paired workload {workload}"
                )
    return len(identities)


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
    start_preflight = _live_preflight(plan, preflight_provider)
    root = settings.bundle_path.resolve()
    plan_bytes = settings.plan_path.read_bytes()
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise CaptureError("paired capture bundle is not a regular directory")
        if (root / "pair-bundle.json").exists():
            raise CaptureError("paired capture bundle is already complete")
        if (root / "pair-plan.json").read_bytes() != plan_bytes:
            raise CaptureError("resumed paired capture plan bytes changed")
    else:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        write_new(root / "pair-plan.json", plan_bytes)
    journals: dict[str, ResumableLaneJournal] = {}
    progress: PairProgressJournal | None = None
    try:
        for lane in PAIR_LANE_ORDER:
            journals[lane] = ResumableLaneJournal(
                root / lane,
                plan["lanes"][lane],
                canonical_bytes(plan["lanes"][lane]),
            )
        lane_records = {
            lane: journals[lane].completed_records for lane in PAIR_LANE_ORDER
        }
        completed = _completed_interleaving(plan, lane_records)
        progress = PairProgressJournal(root, plan, lane_records, clock=clock)
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
            record = run_attempt(
                journal=journals[lane],
                plan=lane_plan,
                attempt=attempt,
                timeout_seconds=settings.timeout_seconds,
                child_runner=child_runner,
                monotonic=monotonic,
                utc_clock=clock,
            )
            sealed = journals[lane].append(record)
            journals[lane].completed_records.append(sealed)
            progress.append(_progress_record(scheduled, sealed), sealed=True)
            completed.append(_progress_record(scheduled, sealed))
            new_attempts += 1
            if len(completed) < PAIR_ATTEMPTS:
                sleeper(COOLDOWN_NS / 1_000_000_000)
        complete = len(completed) == PAIR_ATTEMPTS
        validate_pair_plan(
            plan,
            repository=repository,
            verify_local=True,
            source_provider=source_provider,
            closure_provider=closure_provider,
        )
        checkpoint_preflight = _live_preflight(plan, preflight_provider)
        end_preflight = checkpoint_preflight if complete else None
        journal_identities = {
            lane: journals[lane].close() for lane in PAIR_LANE_ORDER
        }
        progress_identity = progress.close()
    except BaseException:
        for journal in journals.values():
            journal.abandon()
        if progress is not None:
            progress.abandon()
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
            "checkpoint_preflight": checkpoint_preflight,
            "normative_performance_receipt": False,
        }
    completed_at = _utc(clock)
    cross_lane_identities = _cross_lane_identity_count(
        plan,
        {
            lane: journals[lane].completed_records for lane in PAIR_LANE_ORDER
        },
    )
    lane_summaries: dict[str, dict[str, Any]] = {}
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
        write_new(root / lane / "bundle.json", canonical_bytes(manifest))
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
        "schema_version": 1,
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
        "start_preflight": start_preflight,
        "end_preflight": end_preflight,
        "lanes": lane_summaries,
        "pair_journal": progress_identity,
        "cross_lane_identity_workloads": cross_lane_identities,
        "independent_verifier_attempts": independent,
        "exact_work_v4_attempts": exact_work,
    }
    result["content_sha256"] = content_digest(result)
    write_new(root / "pair-bundle.json", canonical_bytes(result))
    return result


def validate_pair_bundle(repository: Path, bundle_path: Path) -> dict[str, Any]:
    from .pair_validation import validate_pair_bundle as validate

    return validate(repository, bundle_path)
