"""Create and independently replay the immutable C-013 CPU capture plan."""

from __future__ import annotations

import datetime as dt
import mmap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from . import schedule
from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    load_strict,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .model import (
    CaptureError,
    CORPUS_DIGESTS,
    CORPUS_MANIFEST_SHA256,
    DIGEST_RE,
    ENVIRONMENT,
    GIT_OID_RE,
    PLAN_SCHEMA,
    PLAN_SCHEMA_VERSION,
    PRIMARY_TARGET,
    PROTOCOL_PATH,
    PROTOCOL_SHA256,
    PROTOCOL_SCHEMA,
    SCHEDULE_SHA256,
    SESSION_RE,
)
from .provenance import (
    artifact_identity,
    host_identity,
    run_tool,
    source_identity,
    validate_host_identity,
)
from .statistics import calibration_gate


EXECUTABLE_IDS = frozenset(
    {"calibration_child", "poseidon2_proof_child", "corpus_manifest_tool"}
)
ELF_IDS = frozenset(
    {
        "calibration_elf",
        "core_only_software_elf",
        "core_only_precompile_elf",
        "balanced_core_and_poseidon2_software_elf",
        "balanced_core_and_poseidon2_precompile_elf",
        "poseidon2_dominant_software_elf",
        "poseidon2_dominant_precompile_elf",
    }
)
ARTIFACT_IDS = EXECUTABLE_IDS | ELF_IDS
REQUIRED_EXECUTABLE_MARKERS = {
    "calibration_child": b"stwo.c013.aa-proof-child.v2",
    "poseidon2_proof_child": b"stwo.c013.poseidon2-cpu-proof-child.v3",
    "corpus_manifest_tool": b"stwo.c013.poseidon2-corpus-manifest.v1",
}
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ONE_CALL_INPUT_SHA256 = "eb07af873dd1211b8e033da3093a2c51c1a8dee325e13e9497dbda1549222d4b"
ONE_CALL_OUTPUT_SHA256 = "0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06"

ROOT_FIELDS = {
    "schema",
    "schema_version",
    "classification",
    "created_at_utc",
    "session_id",
    "protocol",
    "schedule",
    "source",
    "host",
    "lane",
    "security",
    "primary_target",
    "environment",
    "artifacts",
    "corpus_manifest",
    "calibration_gate",
    "attempts",
    "content_sha256",
}
ARTIFACT_FIELDS = {"path", "bytes", "sha256"}
ATTEMPT_FIELDS = {
    "global_ordinal",
    "kind",
    "sample_index",
    "phase",
    "arm",
    "round",
    "pair_index",
    "position",
    "cell_index",
    "shape",
    "calls",
    "executable_id",
    "elf_id",
    "input_bytes",
    "output_bytes",
    "input_sha256",
    "output_sha256",
}


@dataclass(frozen=True)
class PlanSettings:
    repository: Path
    session_id: str
    power_state: str
    artifacts: Mapping[str, Path]


SourceProvider = Callable[[Path], dict[str, object]]
HostProvider = Callable[[str], dict[str, object]]
ToolRunner = Callable[[Path, Path], bytes]
Clock = Callable[[], dt.datetime]


def default_artifacts(repository: Path) -> dict[str, Path]:
    root = repository.resolve()
    guest = root / "vectors/riscv_guests/poseidon2_m31_permute_v1"
    suffix = Path("riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1")
    return {
        "calibration_child": root / "zig-out/bin/riscv-c013-aa-proof-child",
        "poseidon2_proof_child": root / "zig-out/bin/riscv-poseidon2-proof-child",
        "corpus_manifest_tool": root / "zig-out/bin/riscv-c013-corpus-manifest",
        "calibration_elf": root / "vectors/riscv_elfs/multi_shard_addi.elf",
        "core_only_software_elf": guest / "target-core-only" / suffix,
        "core_only_precompile_elf": guest / "target-core-only-precompile" / suffix,
        "balanced_core_and_poseidon2_software_elf": guest / "target-balanced" / suffix,
        "balanced_core_and_poseidon2_precompile_elf": guest / "target-balanced-precompile" / suffix,
        "poseidon2_dominant_software_elf": guest / "target" / suffix,
        "poseidon2_dominant_precompile_elf": guest / "target-precompile" / suffix,
    }


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise CaptureError("capture-plan clock must be timezone-aware")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _protocol(repository: Path) -> dict[str, object]:
    path = repository.resolve() / PROTOCOL_PATH
    document = load_strict(path)
    if type(document) is not dict or document.get("schema") != PROTOCOL_SCHEMA:
        raise CaptureError("typed-AIR protocol schema identity drifted")
    milestones = document.get("milestones")
    if type(milestones) is not list:
        raise CaptureError("typed-AIR protocol milestones are missing")
    m6 = next(
        (item for item in milestones if type(item) is dict and item.get("id") == "M6"),
        None,
    )
    if m6 is None or any(
        m6.get("primary_target", {}).get(key) != expected
        for key, expected in PRIMARY_TARGET.items()
    ):
        raise CaptureError("M6 primary target differs from the C-013 plan authority")
    size, digest = sha256_file(path)
    if digest != PROTOCOL_SHA256:
        raise CaptureError("typed-AIR performance protocol bytes changed")
    return {
        "path": PROTOCOL_PATH,
        "bytes": size,
        "sha256": digest,
        "schema": PROTOCOL_SCHEMA,
        "milestone": "M6",
    }


def _artifacts(paths: Mapping[str, Path]) -> dict[str, dict[str, object]]:
    if set(paths) != ARTIFACT_IDS:
        raise CaptureError(
            f"capture artifact set drifted; missing={sorted(ARTIFACT_IDS - set(paths))}, "
            f"unknown={sorted(set(paths) - ARTIFACT_IDS)}"
        )
    result = {
        name: artifact_identity(path, executable=name in EXECUTABLE_IDS)
        for name, path in sorted(paths.items())
    }
    resolved = [identity["path"] for identity in result.values()]
    if len(resolved) != len(set(resolved)):
        raise CaptureError("capture artifact paths must not alias")
    _require_current_executables(result)
    return result


def _require_current_executables(
    artifacts: Mapping[str, Mapping[str, object]],
) -> None:
    for name, marker in REQUIRED_EXECUTABLE_MARKERS.items():
        try:
            with Path(str(artifacts[name]["path"])).open("rb") as binary:
                with mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as image:
                    found = image.find(marker) >= 0
        except OSError as error:
            raise CaptureError(f"cannot inspect capture executable: {name}") from error
        if not found:
            raise CaptureError(
                f"capture executable {name} lacks the current protocol marker; "
                "install the ReleaseFast C-013 capture artifacts before planning"
            )


def _corpus_manifest(raw: bytes) -> dict[str, object]:
    document = exact_object(
        decode_strict(raw),
        {"schema", "generator", "seed", "call_counts", "records"},
        "corpus manifest",
    )
    expected = {
        "schema": "stwo.c013.poseidon2-corpus-manifest.v1",
        "generator": "poseidon2-software-precompile-equivalence-v1",
        "seed": "stwo-typed-air-m6-poseidon2-v1",
        "call_counts": list(schedule.CALL_COUNTS),
    }
    for key, value in expected.items():
        if document[key] != value or type(document[key]) is not type(value):
            raise CaptureError(f"corpus manifest {key} identity drifted")
    records = document["records"]
    if type(records) is not list or len(records) != len(schedule.CALL_COUNTS):
        raise CaptureError("corpus manifest record cardinality drifted")
    for calls, item in zip(schedule.CALL_COUNTS, records, strict=True):
        record = exact_object(
            item,
            {"calls", "input_bytes", "output_bytes", "input_sha256", "output_sha256"},
            "corpus record",
        )
        exact = {
            "calls": calls,
            "input_bytes": 4 + calls * 64,
            "output_bytes": calls * 64,
        }
        for key, value in exact.items():
            if type(record[key]) is not int or record[key] != value:
                raise CaptureError(f"corpus record {calls} {key} drifted")
        for key in ("input_sha256", "output_sha256"):
            if type(record[key]) is not str or DIGEST_RE.fullmatch(record[key]) is None:
                raise CaptureError(f"corpus record {calls} {key} is not a digest")
    canonical = canonical_bytes(document)
    for record in records:
        expected_input, expected_output = CORPUS_DIGESTS[record["calls"]]
        if (
            record["input_sha256"] != expected_input
            or record["output_sha256"] != expected_output
        ):
            raise CaptureError(
                f"corpus digest pins drifted at calls={record['calls']}"
            )
    if sha256_bytes(canonical) != CORPUS_MANIFEST_SHA256:
        raise CaptureError("complete corpus-manifest identity drifted")
    return {"document_sha256": sha256_bytes(canonical), "document": document}


def _elf_id(shape: str, arm: str) -> str:
    return f"{shape}_{arm}_elf"


def _attempt_records(corpus_manifest: dict[str, object]) -> list[dict[str, object]]:
    document = corpus_manifest["document"]
    assert isinstance(document, dict)
    records = document["records"]
    assert isinstance(records, list)
    by_calls = {item["calls"]: item for item in records}
    result: list[dict[str, object]] = []
    for attempt in schedule.all_attempts():
        if attempt.kind == "calibration":
            record = {
                "global_ordinal": attempt.global_ordinal,
                "kind": attempt.kind,
                "sample_index": attempt.sample_index,
                "phase": attempt.phase,
                "arm": attempt.arm,
                "round": attempt.round,
                "pair_index": attempt.pair_index,
                "position": attempt.position,
                "cell_index": None,
                "shape": None,
                "calls": None,
                "executable_id": "calibration_child",
                "elf_id": "calibration_elf",
                "input_bytes": 0,
                "output_bytes": 0,
                "input_sha256": EMPTY_SHA256,
                "output_sha256": EMPTY_SHA256,
            }
        else:
            assert attempt.calls is not None and attempt.shape is not None
            corpus = by_calls[attempt.calls]
            record = {
                "global_ordinal": attempt.global_ordinal,
                "kind": attempt.kind,
                "sample_index": attempt.sample_index,
                "phase": attempt.phase,
                "arm": attempt.arm,
                "round": attempt.round,
                "pair_index": attempt.pair_index,
                "position": attempt.position,
                "cell_index": attempt.cell_index,
                "shape": attempt.shape,
                "calls": attempt.calls,
                "executable_id": "poseidon2_proof_child",
                "elf_id": _elf_id(attempt.shape, attempt.arm),
                "input_bytes": corpus["input_bytes"],
                "output_bytes": corpus["output_bytes"],
                "input_sha256": corpus["input_sha256"],
                "output_sha256": corpus["output_sha256"],
            }
        result.append(record)
    return result


def build_plan(
    settings: PlanSettings,
    *,
    source_provider: SourceProvider = source_identity,
    host_provider: HostProvider = host_identity,
    tool_runner: ToolRunner = run_tool,
    clock: Clock = _utc_now,
) -> dict[str, object]:
    repository = settings.repository.resolve()
    if not repository.is_dir():
        raise CaptureError(f"repository root is missing: {repository}")
    if SESSION_RE.fullmatch(settings.session_id) is None:
        raise CaptureError("session ID must be a stable 1-128 character token")
    schedule.validate_authority()
    artifacts = _artifacts(settings.artifacts)
    corpus_tool = Path(str(artifacts["corpus_manifest_tool"]["path"]))
    corpus_manifest = _corpus_manifest(tool_runner(corpus_tool, repository))
    host = host_provider(settings.power_state)
    validate_host_identity(host)
    if host["os"] != "Darwin":
        raise CaptureError(
            "C-013 CPU capture currently requires Darwin v6 resource counters"
        )
    document: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_SCHEMA_VERSION,
        "classification": "pre-execution-capture-authority",
        "created_at_utc": _timestamp(clock()),
        "session_id": settings.session_id,
        "protocol": _protocol(repository),
        "schedule": {
            "sha256": SCHEDULE_SHA256,
            "calibration_attempts": schedule.CALIBRATION_ATTEMPTS,
            "m6_attempts": schedule.M6_ATTEMPTS,
            "global_attempts": schedule.GLOBAL_ATTEMPTS,
            "cooldown_ns": schedule.COOLDOWN_NS,
            "order": "calibration-first-then-shape-major-call-minor",
        },
        "source": source_provider(repository),
        "host": host,
        "lane": "cpu-native",
        "security": "secure",
        "primary_target": dict(PRIMARY_TARGET),
        "environment": dict(ENVIRONMENT),
        "artifacts": artifacts,
        "corpus_manifest": corpus_manifest,
        "calibration_gate": calibration_gate(repository),
        "attempts": _attempt_records(corpus_manifest),
    }
    document["content_sha256"] = content_digest(document)
    validate_plan(document, repository=repository, verify_local=False)
    return document


def _validate_source(value: Any) -> dict[str, object]:
    source = exact_object(
        value,
        {"repository", "commit", "tree", "clean", "status_porcelain"},
        "capture source",
    )
    if source["repository"] != "https://github.com/teddyjfpender/stwo-zig":
        raise CaptureError("capture repository identity drifted")
    for key in ("commit", "tree"):
        if type(source[key]) is not str or GIT_OID_RE.fullmatch(source[key]) is None:
            raise CaptureError(f"capture source {key} is not a Git object ID")
    if source["clean"] is not True or source["status_porcelain"] != []:
        raise CaptureError("capture source must be a clean immutable snapshot")
    return source


def _validate_artifacts(value: Any, *, verify_local: bool) -> dict[str, Any]:
    artifacts = exact_object(value, set(ARTIFACT_IDS), "capture artifacts")
    paths: list[str] = []
    for name in sorted(ARTIFACT_IDS):
        identity = exact_object(artifacts[name], ARTIFACT_FIELDS, f"artifact {name}")
        path = Path(identity["path"])
        if not path.is_absolute() or ".." in path.parts:
            raise CaptureError(f"artifact {name} path is not absolute and normalized")
        if type(identity["bytes"]) is not int or identity["bytes"] <= 0:
            raise CaptureError(f"artifact {name} byte count is invalid")
        if type(identity["sha256"]) is not str or DIGEST_RE.fullmatch(identity["sha256"]) is None:
            raise CaptureError(f"artifact {name} digest is invalid")
        paths.append(str(path))
        if verify_local:
            current = artifact_identity(path, executable=name in EXECUTABLE_IDS)
            if current != identity:
                raise CaptureError(f"artifact {name} changed after plan creation")
    if len(paths) != len(set(paths)):
        raise CaptureError("capture artifact paths alias")
    if verify_local:
        _require_current_executables(artifacts)
    return artifacts


def validate_plan(
    value: Any,
    *,
    repository: Path,
    verify_local: bool,
    source_provider: SourceProvider = source_identity,
) -> dict[str, object]:
    plan = exact_object(value, ROOT_FIELDS, "capture plan")
    exact = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_SCHEMA_VERSION,
        "classification": "pre-execution-capture-authority",
        "lane": "cpu-native",
        "security": "secure",
        "primary_target": PRIMARY_TARGET,
        "environment": ENVIRONMENT,
    }
    for key, expected in exact.items():
        if type(plan[key]) is not type(expected) or plan[key] != expected:
            raise CaptureError(f"capture plan {key} identity drifted")
    if SESSION_RE.fullmatch(plan["session_id"]) is None:
        raise CaptureError("capture plan session ID is invalid")
    timestamp = plan["created_at_utc"]
    if type(timestamp) is not str or not timestamp.endswith("Z"):
        raise CaptureError("capture plan timestamp is not canonical UTC")

    expected_protocol = _protocol(repository)
    if plan["protocol"] != expected_protocol:
        raise CaptureError("capture plan protocol identity changed")
    expected_schedule = {
        "sha256": SCHEDULE_SHA256,
        "calibration_attempts": 80,
        "m6_attempts": 1_440,
        "global_attempts": 1_520,
        "cooldown_ns": 1_000_000_000,
        "order": "calibration-first-then-shape-major-call-minor",
    }
    if plan["schedule"] != expected_schedule:
        raise CaptureError("capture plan schedule identity changed")
    schedule.validate_authority()

    source = _validate_source(plan["source"])
    if verify_local and source_provider(repository.resolve()) != source:
        raise CaptureError("capture source changed after plan creation")
    host = validate_host_identity(plan["host"])
    if host["os"] != "Darwin":
        raise CaptureError("capture plan lacks the required Darwin resource adapter")
    _validate_artifacts(plan["artifacts"], verify_local=verify_local)
    corpus_manifest = exact_object(
        plan["corpus_manifest"],
        {"document_sha256", "document"},
        "bound corpus manifest",
    )
    replayed = _corpus_manifest(canonical_bytes(corpus_manifest["document"]))
    if corpus_manifest != replayed:
        raise CaptureError("bound corpus manifest digest changed")
    if plan["calibration_gate"] != calibration_gate(repository):
        raise CaptureError("A/A statistical authority identity changed")
    attempts = plan["attempts"]
    if type(attempts) is not list or len(attempts) != schedule.GLOBAL_ATTEMPTS:
        raise CaptureError("capture attempt list cardinality changed")
    for item in attempts:
        exact_object(item, ATTEMPT_FIELDS, "capture attempt")
    if attempts != _attempt_records(corpus_manifest):
        raise CaptureError("capture attempt list differs from the frozen schedule")
    if type(plan["content_sha256"]) is not str or DIGEST_RE.fullmatch(plan["content_sha256"]) is None:
        raise CaptureError("capture plan content digest is invalid")
    if plan["content_sha256"] != content_digest(plan):
        raise CaptureError("capture plan content digest mismatch")
    return plan


def write_plan_new(path: Path, plan: dict[str, object]) -> bytes:
    payload = canonical_bytes(plan)
    write_new(path, payload)
    return payload


def load_and_validate_plan(
    path: Path,
    *,
    repository: Path,
    verify_local: bool = True,
) -> dict[str, object]:
    raw = path.read_bytes()
    plan = decode_strict(raw)
    validate_plan(plan, repository=repository.resolve(), verify_local=verify_local)
    if raw != canonical_bytes(plan):
        raise CaptureError("capture plan is not in canonical JSON encoding")
    return plan
