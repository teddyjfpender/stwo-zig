"""Durable journals and byte-idempotent finalization for paired R-006 capture."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_bytes,
    sha256_file,
)
from .controller import (
    JOURNAL_HEADER_SCHEMA,
    FileInventory,
    Journal,
    _validate_record,
    validate_bundle,
)
from .model import MAX_STREAM_BYTES, PLAN_ATTEMPTS, UTC_RE, CaptureError
from .orchestration import INSTALL_LANES
from .preflight import validate_host_preflight


PAIR_PROGRESS_HEADER_SCHEMA = "stwo.typed-air.r006-pair-progress-header.v1"
PAIR_PROGRESS_RECORD_SCHEMA = "stwo.typed-air.r006-pair-progress-record.v1"
BOUNDARY_HEADER_SCHEMA = "stwo.typed-air.r006-preflight-boundary-header.v1"
BOUNDARY_RECORD_SCHEMA = "stwo.typed-air.r006-preflight-boundary-record.v1"
BOUNDARY_JOURNAL_NAME = "preflight-boundaries.ndjson"
PAIR_LANE_ORDER = INSTALL_LANES

_BOUNDARY_HEADER_FIELDS = {
    "schema",
    "session_id",
    "plan_sha256",
    "planned_attempts",
    "content_sha256",
}
_BOUNDARY_RECORD_FIELDS = {
    "schema",
    "invocation_index",
    "boundary",
    "completed_attempts",
    "preflight",
    "content_sha256",
}


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def require_regular_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CaptureError(f"cannot inspect {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CaptureError(f"{label} is not a non-symlink directory")


def _open_existing_regular(path: Path, flags: int, label: str) -> int:
    try:
        before = path.lstat()
    except OSError as error:
        raise CaptureError(f"cannot inspect {label}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise CaptureError(f"{label} is not a non-symlink regular file")
    guarded_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, guarded_flags)
    except OSError as error:
        raise CaptureError(f"cannot open {label} without following links") from error
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise CaptureError(f"{label} changed during no-follow admission")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_regular_bytes(path: Path, label: str) -> bytes:
    descriptor = _open_existing_regular(path, os.O_RDONLY, label)
    try:
        with os.fdopen(descriptor, "rb") as source:
            return source.read()
    except OSError as error:
        raise CaptureError(f"cannot read {label}") from error


def read_canonical_json_regular(path: Path, label: str) -> dict[str, Any]:
    raw = read_regular_bytes(path, label)
    value = decode_strict(raw)
    if type(value) is not dict or raw != canonical_bytes(value):
        raise CaptureError(f"{label} is not canonical JSON")
    return value


def _read_journal_stream(source: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    while raw := source.readline(MAX_STREAM_BYTES + 1):
        if len(raw) > MAX_STREAM_BYTES or not raw.endswith(b"\n"):
            raise CaptureError("R-006 journal record exceeds its bound")
        value = decode_strict(raw)
        if type(value) is not dict or raw != canonical_bytes(value):
            raise CaptureError("R-006 journal is not canonical NDJSON")
        digest = value.get("content_sha256")
        if type(digest) is not str or digest != content_digest(value):
            raise CaptureError("R-006 journal record digest mismatch")
        records.append(value)
    return records


def read_journal_regular(path: Path, label: str) -> list[dict[str, Any]]:
    descriptor = _open_existing_regular(path, os.O_RDONLY, label)
    try:
        with os.fdopen(descriptor, "rb") as source:
            return _read_journal_stream(source)
    except OSError as error:
        raise CaptureError(f"cannot read {label}") from error


def _open_journal_append(path: Path, label: str) -> tuple[Any, list[dict[str, Any]]]:
    descriptor = _open_existing_regular(path, os.O_RDWR | os.O_APPEND, label)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as source:
            records = _read_journal_stream(source)
        return os.fdopen(descriptor, "wb", buffering=0), records
    except BaseException:
        os.close(descriptor)
        raise


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CaptureError("cannot durably publish R-006 evidence directory entry") from error


def _create_journal(path: Path, label: str) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        _fsync_directory(path.parent)
        output = os.fdopen(descriptor, "wb", buffering=0)
        descriptor = None
        return output
    except OSError as error:
        raise CaptureError(f"cannot create exclusive {label}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _append(output: Any, records: list[dict[str, Any]], value: dict[str, Any]) -> dict[str, Any]:
    record = dict(value)
    record["content_sha256"] = content_digest(record)
    try:
        output.write(canonical_bytes(record))
        os.fsync(output.fileno())
    except OSError as error:
        raise CaptureError("cannot durably append paired R-006 journal") from error
    records.append(record)
    return record


def _identity(path: Path, relative: str, records: int) -> dict[str, Any]:
    size, digest = sha256_file(path)
    return {"path": relative, "bytes": size, "sha256": digest, "records": records}


def journal_identity(
    records: list[dict[str, Any]], relative: str
) -> dict[str, Any]:
    raw = b"".join(canonical_bytes(record) for record in records)
    return {
        "path": relative,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "records": len(records),
    }


def publish_new_or_identical(
    path: Path, payload: bytes, *, staging_directory: Path
) -> bool:
    """Atomically create evidence, or accept only an identical regular file."""

    require_regular_directory(path.parent, "R-006 evidence parent")
    if _lexists(path):
        if read_regular_bytes(path, f"existing {path.name}") != payload:
            raise CaptureError(f"existing R-006 evidence differs: {path.name}")
        return False
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".r006-{path.name}.", suffix=".tmp", dir=staging_directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if read_regular_bytes(path, f"concurrently published {path.name}") != payload:
                raise CaptureError(f"concurrent R-006 evidence differs: {path.name}")
            return False
        _fsync_directory(path.parent)
        return True
    except OSError as error:
        raise CaptureError(f"cannot publish R-006 evidence: {path.name}") from error
    finally:
        temporary.unlink(missing_ok=True)


def progress_record(
    schedule: dict[str, Any], lane_record: dict[str, Any]
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


def completed_interleaving(
    plan: dict[str, Any], lane_records: Mapping[str, list[dict[str, Any]]]
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
        result.append(progress_record(scheduled, lane_records[lane][index]))
        consumed[lane] += 1
    if any(consumed[lane] != len(lane_records[lane]) for lane in PAIR_LANE_ORDER):
        raise CaptureError("paired lane journals do not form one interleaved prefix")
    return result


class ResumableLaneJournal(Journal):
    """A lane journal that reopens only an authenticated attempt prefix."""

    completed_records: list[dict[str, Any]]

    def __init__(
        self,
        bundle: Path,
        plan: dict[str, Any],
        plan_bytes: bytes,
        *,
        repository: Path,
        pending_record: dict[str, Any] | None = None,
    ) -> None:
        self.sealed_manifest: dict[str, Any] | None = None
        if not _lexists(bundle):
            super().__init__(bundle, plan, plan_bytes)
            self.completed_records = []
            return
        require_regular_directory(bundle, "resumed R-006 lane bundle")
        self.bundle = bundle.absolute()
        manifest_path = self.bundle / "bundle.json"
        if _lexists(manifest_path):
            if pending_record is not None:
                raise CaptureError("finalized lane conflicts with a pending publication")
            validate_bundle(repository, self.bundle)
            manifest = read_canonical_json_regular(manifest_path, "completed lane manifest")
            records = read_journal_regular(
                self.bundle / "journal.ndjson", "completed lane journal"
            )
            self.path = self.bundle / "journal.ndjson"
            self.output = None
            self.closed = False
            self.records = len(records)
            self.completed_records = records[1:]
            self.sealed_manifest = manifest
            return
        inventory = FileInventory(self.bundle)
        if inventory.root_file("plan.json") != plan_bytes:
            raise CaptureError("resumed R-006 lane plan bytes changed")
        journal_raw = inventory.root_file("journal.ndjson")
        records = read_journal_regular(
            self.bundle / "journal.ndjson", "resumed R-006 lane journal"
        )
        if not records or journal_raw != b"".join(canonical_bytes(item) for item in records):
            raise CaptureError("resumed R-006 lane journal lacks its header")
        header = exact_object(
            records[0],
            {"schema", "session_id", "plan_sha256", "planned_attempts", "content_sha256"},
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
            _validate_record(record, plan=plan, attempt=attempt, inventory=inventory)
        if pending_record is not None:
            ordinal = pending_record.get("ordinal")
            if type(ordinal) is not int or not 0 <= ordinal < len(plan["attempts"]):
                raise CaptureError("pending attempt publication has an invalid ordinal")
            if ordinal < len(prior):
                if prior[ordinal] != pending_record:
                    raise CaptureError("pending publication differs from its lane record")
            elif ordinal == len(prior):
                _validate_record(
                    pending_record,
                    plan=plan,
                    attempt=plan["attempts"][ordinal],
                    inventory=inventory,
                )
            else:
                raise CaptureError("pending publication skips its lane prefix")
        inventory.finish()
        self.path = self.bundle / "journal.ndjson"
        self.output, opened_records = _open_journal_append(
            self.path, "resumed R-006 lane journal"
        )
        if opened_records != records:
            self.output.close()
            raise CaptureError("resumed R-006 lane journal changed during admission")
        self.closed = False
        self.records = len(records)
        self.completed_records = prior

    def append(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.sealed_manifest is not None:
            raise CaptureError("cannot append a finalized R-006 lane journal")
        return super().append(value)

    def retain(self, relative: str, raw: bytes) -> dict[str, Any]:
        if self.sealed_manifest is not None:
            raise CaptureError("cannot retain evidence in a finalized R-006 lane")
        return super().retain(relative, raw)

    def close(self) -> dict[str, Any]:
        if self.sealed_manifest is not None:
            if self.closed:
                raise CaptureError("R-006 finalized lane journal closed twice")
            self.closed = True
            return self.sealed_manifest["journal"]
        return super().close()

    def abandon(self) -> None:
        if self.sealed_manifest is not None:
            self.closed = True
            return
        super().abandon()


class PairProgressJournal:
    def __init__(
        self,
        root: Path,
        plan: dict[str, Any],
        lane_records: Mapping[str, list[dict[str, Any]]],
        *,
        started_at_utc: str,
    ) -> None:
        self.path = root / "pair-journal.ndjson"
        self.closed = False
        expected = completed_interleaving(plan, lane_records)
        if not _lexists(self.path):
            if expected:
                raise CaptureError(
                    "paired progress journal is missing after lane attempts were recorded"
                )
            self.output = _create_journal(self.path, "paired progress journal")
            self.records: list[dict[str, Any]] = []
            self.header = self.append(
                {
                    "schema": PAIR_PROGRESS_HEADER_SCHEMA,
                    "session_id": plan["session_id"],
                    "plan_sha256": plan["content_sha256"],
                    "planned_attempts": len(plan["interleaving"]),
                    "started_at_utc": started_at_utc,
                }
            )
        else:
            self.output, records = _open_journal_append(
                self.path, "paired progress journal"
            )
            if not records:
                self.output.close()
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
                or header["planned_attempts"] != len(plan["interleaving"])
                or type(header["started_at_utc"]) is not str
                or UTC_RE.fullmatch(header["started_at_utc"]) is None
            ):
                self.output.close()
                raise CaptureError("paired R-006 progress header changed")
            self.header = header
            self.records = records
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
        if sealed:
            if record.get("content_sha256") != content_digest(record):
                raise CaptureError("derived paired progress record is not sealed")
            try:
                self.output.write(canonical_bytes(record))
                os.fsync(self.output.fileno())
            except OSError as error:
                raise CaptureError("cannot durably append paired progress journal") from error
            self.records.append(record)
            return record
        return _append(self.output, self.records, record)

    def close(self) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("paired progress journal closed twice")
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True
        return _identity(self.path, "pair-journal.ndjson", len(self.records))

    def abandon(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True


def validate_boundary_records(
    records: list[dict[str, Any]],
    *,
    plan: dict[str, Any],
    completed_attempts: int,
    require_complete: bool,
) -> dict[str, Any]:
    planned = len(plan["interleaving"])
    if type(completed_attempts) is not int or not 0 <= completed_attempts <= planned:
        raise CaptureError("paired preflight boundary durable prefix is invalid")
    if not records:
        raise CaptureError("paired preflight boundary journal is empty")
    header = exact_object(records[0], _BOUNDARY_HEADER_FIELDS, "preflight boundary header")
    if (
        header["schema"] != BOUNDARY_HEADER_SCHEMA
        or header["session_id"] != plan["session_id"]
        or header["plan_sha256"] != plan["content_sha256"]
        or header["planned_attempts"] != planned
    ):
        raise CaptureError("paired preflight boundary header changed")
    expected_host = plan["host_preflight"]["host"]
    next_invocation = 0
    closed_prefix = 0
    open_start: dict[str, Any] | None = None
    first_preflight: dict[str, Any] | None = None
    final_preflight: dict[str, Any] | None = None
    recoveries = 0
    for value in records[1:]:
        record = exact_object(
            value, _BOUNDARY_RECORD_FIELDS, "preflight boundary record"
        )
        index = record["invocation_index"]
        prefix = record["completed_attempts"]
        boundary = record["boundary"]
        if (
            type(index) is not int
            or index < 0
            or type(prefix) is not int
            or not 0 <= prefix <= planned
            or boundary not in {"start", "checkpoint", "recovery"}
        ):
            raise CaptureError("paired preflight boundary record is malformed")
        preflight = validate_host_preflight(record["preflight"], require_admitted=True)
        if preflight["host"] != expected_host:
            raise CaptureError("paired preflight boundary host identity drifted")
        if boundary == "start":
            if open_start is not None or index != next_invocation or prefix != closed_prefix:
                raise CaptureError("paired preflight start is out of sequence")
            if prefix == planned:
                raise CaptureError("paired preflight journal starts after completion")
            open_start = record
            next_invocation += 1
            if first_preflight is None:
                first_preflight = preflight
            continue
        if (
            open_start is None
            or index != open_start["invocation_index"]
            or prefix < open_start["completed_attempts"]
        ):
            raise CaptureError("paired preflight close is out of sequence")
        if boundary == "recovery":
            recoveries += 1
        closed_prefix = prefix
        final_preflight = preflight
        open_start = None
    if open_start is None:
        if completed_attempts != closed_prefix:
            raise CaptureError("attempt evidence advanced outside a preflight invocation")
    elif completed_attempts < open_start["completed_attempts"]:
        raise CaptureError("attempt evidence regressed inside a preflight invocation")
    if require_complete and (open_start is not None or closed_prefix != planned):
        raise CaptureError("paired preflight boundary journal is not complete")
    return {
        "header": header,
        "first_preflight": first_preflight,
        "final_preflight": final_preflight,
        "closed_prefix": closed_prefix,
        "open_start": open_start,
        "invocations": next_invocation,
        "recoveries": recoveries,
        "records": len(records),
    }


class PreflightBoundaryJournal:
    def __init__(self, root: Path, plan: dict[str, Any], completed_attempts: int) -> None:
        self.path = root / BOUNDARY_JOURNAL_NAME
        self.plan = plan
        self.closed = False
        if not _lexists(self.path):
            if completed_attempts:
                raise CaptureError(
                    "preflight boundary journal is missing after attempts were recorded"
                )
            self.output = _create_journal(self.path, "preflight boundary journal")
            self.records: list[dict[str, Any]] = []
            _append(
                self.output,
                self.records,
                {
                    "schema": BOUNDARY_HEADER_SCHEMA,
                    "session_id": plan["session_id"],
                    "plan_sha256": plan["content_sha256"],
                    "planned_attempts": len(plan["interleaving"]),
                },
            )
        else:
            self.output, self.records = _open_journal_append(
                self.path, "preflight boundary journal"
            )
        self.summary(completed_attempts=completed_attempts, require_complete=False)

    def summary(
        self, *, completed_attempts: int, require_complete: bool
    ) -> dict[str, Any]:
        return validate_boundary_records(
            self.records,
            plan=self.plan,
            completed_attempts=completed_attempts,
            require_complete=require_complete,
        )

    def admit(self, preflight: dict[str, Any], completed_attempts: int) -> bool:
        validate_host_preflight(preflight, require_admitted=True)
        if preflight["host"] != self.plan["host_preflight"]["host"]:
            raise CaptureError("paired preflight boundary host identity drifted")
        summary = self.summary(
            completed_attempts=completed_attempts, require_complete=False
        )
        open_start = summary["open_start"]
        if open_start is not None:
            _append(
                self.output,
                self.records,
                {
                    "schema": BOUNDARY_RECORD_SCHEMA,
                    "invocation_index": open_start["invocation_index"],
                    "boundary": "recovery",
                    "completed_attempts": completed_attempts,
                    "preflight": preflight,
                },
            )
            summary = self.summary(
                completed_attempts=completed_attempts, require_complete=False
            )
        if completed_attempts == len(self.plan["interleaving"]):
            return False
        _append(
            self.output,
            self.records,
            {
                "schema": BOUNDARY_RECORD_SCHEMA,
                "invocation_index": summary["invocations"],
                "boundary": "start",
                "completed_attempts": completed_attempts,
                "preflight": preflight,
            },
        )
        return True

    def checkpoint(self, preflight: dict[str, Any], completed_attempts: int) -> None:
        validate_host_preflight(preflight, require_admitted=True)
        if preflight["host"] != self.plan["host_preflight"]["host"]:
            raise CaptureError("paired preflight boundary host identity drifted")
        summary = self.summary(
            completed_attempts=completed_attempts, require_complete=False
        )
        open_start = summary["open_start"]
        if open_start is None:
            raise CaptureError("paired preflight checkpoint lacks an open invocation")
        _append(
            self.output,
            self.records,
            {
                "schema": BOUNDARY_RECORD_SCHEMA,
                "invocation_index": open_start["invocation_index"],
                "boundary": "checkpoint",
                "completed_attempts": completed_attempts,
                "preflight": preflight,
            },
        )

    def close(self) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("preflight boundary journal closed twice")
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True
        return _identity(self.path, BOUNDARY_JOURNAL_NAME, len(self.records))

    def abandon(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True


def read_boundary_journal(
    path: Path,
    *,
    plan: dict[str, Any],
    completed_attempts: int,
    require_complete: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    records = read_journal_regular(path, "preflight boundary journal")
    summary = validate_boundary_records(
        records,
        plan=plan,
        completed_attempts=completed_attempts,
        require_complete=require_complete,
    )
    return summary, journal_identity(records, BOUNDARY_JOURNAL_NAME)


def publish_pair_manifests(
    root: Path,
    lane_payloads: Mapping[str, bytes],
    root_payload: bytes,
    *,
    after_publish: Callable[[str], None] | None = None,
) -> None:
    for lane in PAIR_LANE_ORDER:
        publish_new_or_identical(
            root / lane / "bundle.json",
            lane_payloads[lane],
            staging_directory=root.parent,
        )
        if after_publish is not None:
            after_publish(lane)
    publish_new_or_identical(
        root / "pair-bundle.json", root_payload, staging_directory=root.parent
    )
    if after_publish is not None:
        after_publish("root")
