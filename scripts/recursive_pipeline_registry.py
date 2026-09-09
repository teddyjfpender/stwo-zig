"""Typed stage registry and the single generic Zig worker protocol.

The production adapter has no AIR-specific branches.  Key derivation, build,
and cold-open validation are all delegated to one persistent Zig worker.  The
Python mock is explicitly test-only.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from typing import Any

from scripts import recursive_pipeline_protocol as protocol


WORKER_REQUEST_SCHEMA = "stwo.recursive-pipeline-worker-request.v1"
WORKER_RESPONSE_SCHEMA = "stwo.recursive-pipeline-worker-response.v1"
MOCK_PROFILE_SCHEMA = "stwo.recursive-pipeline-mock-profile.v1"
MOCK_VALIDATION_SCHEMA = "stwo.recursive-pipeline-mock-validation.v1"
STAGE_DESCRIPTION_SCHEMA = "stwo.recursive-pipeline-stage-description.v1"
WORKER_CANDIDATE_REF_SCHEMA = "stwo.recursive-pipeline-worker-candidate-ref.v1"


@dataclass
class Candidate:
    output: bytes | None
    profile_receipt: dict[str, Any]
    stdout: bytes = b""
    stderr: bytes = b""
    output_ref: dict[str, Any] | None = None
    output_path: Path | None = None


@dataclass
class DerivedKeys:
    semantic: dict[str, Any]
    execution: dict[str, Any]
    semantic_bytes: bytes
    execution_bytes: bytes


@dataclass
class Lease:
    adapter: "StageAdapter"
    token: str
    output_ref: dict[str, Any]
    released: bool = False

    def close(self) -> None:
        if not self.released:
            self.adapter.release(self)
            self.released = True


@dataclass
class ColdOpen:
    validation_receipt: dict[str, Any]
    lease: Lease
    stage_manifest_ref: dict[str, Any] | None = None
    stage_manifest: bytes | None = None


class StageAdapter:
    validator_version: int
    inline_artifacts: bool = False
    max_parallelism: int = 1

    def describe(self, node: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def derive(
        self, campaign_namespace: str, node: dict[str, Any],
        ordered_inputs: list[dict[str, Any]],
        execution_authorities: dict[str, str],
    ) -> DerivedKeys:
        raise NotImplementedError

    def build(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        dependency_leases: list[Lease], attempt_directory: Path,
    ) -> Candidate:
        raise NotImplementedError

    def cold_open(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        output_ref: dict[str, Any], output: bytes | None, *, output_path: Path,
        dependency_stage_manifest_refs: list[dict[str, Any]],
        stage_manifest_ref: dict[str, Any] | None, mode: str,
    ) -> ColdOpen:
        raise NotImplementedError

    def release(self, lease: Lease) -> None:
        raise NotImplementedError

    def diagnostic_log(self) -> bytes:
        return b""

    def close(self) -> None:
        pass


class ZigWorkerAdapter(StageAdapter):
    """Persistent framed subprocess; fresh capabilities stay inside Zig."""

    def __init__(
        self, command: list[str], *, cwd: Path, validator_version: int,
        object_root: Path,
        maximum_response_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        protocol.require(bool(command) and all(type(item) is str and item for item in command),
                         "recursive pipeline worker command differs")
        protocol.require(validator_version > 0, "worker validator version differs")
        self.command = list(command)
        self.cwd = cwd
        self.object_root = object_root
        self.validator_version = validator_version
        self.maximum_response_bytes = maximum_response_bytes
        self.process: subprocess.Popen[bytes] | None = None
        self.sequence = 0
        self.descriptions: dict[tuple[int, int], dict[str, Any]] = {}
        log_root = object_root.parent.parent / "worker-logs"
        log_root.mkdir(mode=0o700, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix="worker-", suffix=".stderr.log",
                                            dir=log_root)
        os.fchmod(descriptor, 0o600)
        self.stderr_path = Path(name)
        self.stderr_output = os.fdopen(descriptor, "ab", buffering=0)

    def describe(self, node: dict[str, Any]) -> dict[str, Any]:
        key = (node["stage_kind"], node["stage_schema_version"])
        if key not in self.descriptions:
            payload = self._request("describe", {
                "stage_kind": key[0], "stage_schema_version": key[1],
            })
            protocol.exact(payload, {"description"}, "worker describe result")
            description = payload["description"]
            validate_stage_description(description, node)
            self.descriptions[key] = description
        return self.descriptions[key]

    def _start(self) -> None:
        if self.process is not None:
            return
        self.process = subprocess.Popen(
            self.command,
            cwd=self.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr_output,
            start_new_session=True,
        )

    def _request(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._start()
        process = self.process
        assert process is not None and process.stdin is not None and process.stdout is not None
        sequence = self.sequence
        self.sequence += 1
        request = protocol.seal({
            "schema": WORKER_REQUEST_SCHEMA,
            "sequence": sequence,
            "action": action,
            "payload": payload,
        })
        process.stdin.write(protocol.canonical_bytes(request))
        process.stdin.flush()
        raw = process.stdout.readline(self.maximum_response_bytes + 1)
        if not (0 < len(raw) <= self.maximum_response_bytes and raw.endswith(b"\n")):
            tail = self._stderr_tail()
            raise protocol.PipelineError(
                f"recursive pipeline worker response framing differs; stderr_tail={tail!r}"
            )
        response = protocol.parse_canonical(
            raw, lambda value: protocol.validate_seal(value, "worker response"),
            "worker response",
        )
        protocol.exact(response, {
            "schema", "sequence", "action", "status", "payload",
            "content_sha256",
        }, "worker response")
        protocol.require(response["schema"] == WORKER_RESPONSE_SCHEMA
                         and response["sequence"] == sequence
                         and response["action"] == action
                         and response["status"] in ("ok", "error")
                         and type(response["payload"]) is dict,
                         "recursive pipeline worker response differs")
        if response["status"] == "error":
            consumed = response["payload"].get("consumed_lease_ids", [])
            protocol.require(consumed == [],
                             "failed worker action consumed live leases")
            error_name = response["payload"].get("error")
            protocol.require(type(error_name) is str and error_name,
                             "worker error response differs")
            raise protocol.PipelineError(f"recursive pipeline worker: {error_name}")
        return response["payload"]

    def derive(
        self, campaign_namespace: str, node: dict[str, Any],
        ordered_inputs: list[dict[str, Any]],
        execution_authorities: dict[str, str],
    ) -> DerivedKeys:
        payload = self._request("derive", {
            "campaign_namespace_sha256": campaign_namespace,
            "node": node,
            "ordered_inputs": ordered_inputs,
            "execution_authorities": execution_authorities,
        })
        protocol.exact(payload, {
            "semantic_key_hex", "execution_key_hex", "semantic_projection",
            "execution_projection",
        },
                       "worker derive result")
        try:
            semantic_bytes = bytes.fromhex(payload["semantic_key_hex"])
            execution_bytes = bytes.fromhex(payload["execution_key_hex"])
        except (TypeError, ValueError) as error:
            raise protocol.PipelineError("worker key wire encoding differs") from error
        semantic = protocol.decode_semantic_key(semantic_bytes)
        execution = protocol.decode_execution_key(execution_bytes)
        protocol.validate_execution_key(execution, semantic)
        protocol.require(payload["semantic_projection"] == semantic
                         and payload["execution_projection"] == execution,
                         "worker key diagnostic projection differs")
        return DerivedKeys(semantic, execution, semantic_bytes, execution_bytes)

    def build(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        dependency_leases: list[Lease], attempt_directory: Path,
    ) -> Candidate:
        output_path = attempt_directory / "output.bin"
        profile_path = attempt_directory / "profile.json"
        candidate_ref_path = attempt_directory / "candidate-ref.json"
        lease_ids = [lease.token for lease in dependency_leases]
        payload = self._request("build", {
            "node": node,
            "ordered_inputs": ordered_inputs,
            "semantic_key": semantic,
            "execution_key": execution,
            "dependency_lease_ids": lease_ids,
            "input_object_paths": [
                str(self._object_path(item["blob"])) for item in ordered_inputs
            ],
            "output_path": str(output_path),
            "profile_receipt_path": str(profile_path),
            "candidate_ref_path": str(candidate_ref_path),
        })
        protocol.exact(payload, {
            "output_path", "output_ref", "profile_receipt_path",
            "candidate_ref_path", "consumed_lease_ids",
        },
                       "worker build result")
        protocol.require(payload["output_path"] == str(output_path)
                         and payload["profile_receipt_path"] == str(profile_path),
                         "worker build paths differ")
        protocol.require(payload["candidate_ref_path"] == str(candidate_ref_path),
                         "worker candidate-ref path differs")
        protocol.require(payload["consumed_lease_ids"] == lease_ids,
                         "worker consumed lease set differs")
        output_ref = protocol.validate_blob_ref(
            payload["output_ref"], "worker output reference",
        )
        protocol.require(output_ref["kind"] == node["output_kind"]
                         and output_ref["schema_version"]
                         == node["output_schema_version"],
                         "worker output codec differs")
        custody = _read_canonical(candidate_ref_path, "worker candidate reference")
        protocol.exact(custody, {
            "schema", "output_ref", "content_sha256",
        }, "worker candidate reference")
        protocol.require(custody["schema"] == WORKER_CANDIDATE_REF_SCHEMA
                         and protocol.validate_blob_ref(
                             custody["output_ref"], "worker candidate output",
                         ) == output_ref,
                         "worker candidate reference differs")
        for lease in dependency_leases:
            lease.released = True
        return Candidate(
            output=None,
            profile_receipt=_read_canonical(profile_path, "worker profile receipt"),
            stderr=self._read_worker_log(),
            output_ref=output_ref,
            output_path=output_path,
        )

    def cold_open(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        output_ref: dict[str, Any], output: bytes | None, *, output_path: Path,
        dependency_stage_manifest_refs: list[dict[str, Any]],
        stage_manifest_ref: dict[str, Any] | None, mode: str,
    ) -> ColdOpen:
        protocol.require(mode in ("shallow", "cold", "fresh", "root"),
                         "worker validation mode differs")
        payload = self._request("coldOpen", {
            "node": node,
            "ordered_inputs": ordered_inputs,
            "semantic_key": semantic,
            "execution_key": execution,
            "output_ref": output_ref,
            "output_path": str(self._object_path(output_ref)),
            "dependency_stage_manifest_refs": dependency_stage_manifest_refs,
            "stage_manifest_ref": stage_manifest_ref,
            "validator_version": self.validator_version,
            "mode": mode,
        })
        protocol.exact(payload, {
            "validation_receipt", "lease_id", "stage_manifest_ref",
        },
                       "worker coldOpen result")
        receipt = payload["validation_receipt"]
        protocol.require(type(receipt) is dict,
                         "worker validation receipt differs")
        protocol.validate_seal(receipt, "worker validation receipt")
        token = payload["lease_id"]
        protocol.require(type(token) is str and token,
                         "worker lease id differs")
        manifest_ref = protocol.validate_blob_ref(
            payload["stage_manifest_ref"], "worker stage manifest reference",
        )
        protocol.require(manifest_ref["kind"] == 4
                         and manifest_ref["schema_version"] == 1,
                         "worker stage manifest codec differs")
        return ColdOpen(
            receipt, Lease(self, token, output_ref),
            stage_manifest_ref=manifest_ref,
        )

    def _object_path(self, ref: dict[str, Any]) -> Path:
        protocol.validate_blob_ref(ref, "worker object reference")
        return self.object_root / ref["sha256"][:2] / f"{ref['sha256']}.blob"

    def release(self, lease: Lease) -> None:
        payload = self._request("closeLease", {"lease_id": lease.token})
        protocol.exact(payload, set(), "worker closeLease result")

    def close(self) -> None:
        process = self.process
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        self._request("shutdown", {})
                    except (BrokenPipeError, protocol.PipelineError):
                        process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            finally:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
                self.process = None
        if not self.stderr_output.closed:
            self.stderr_output.flush()
            os.fsync(self.stderr_output.fileno())
            self.stderr_output.close()

    def _read_worker_log(self) -> bytes:
        self.stderr_output.flush()
        return _read_regular(self.stderr_path, "recursive pipeline worker stderr")

    def diagnostic_log(self) -> bytes:
        return self._read_worker_log()

    def _stderr_tail(self) -> str:
        raw = self._read_worker_log()
        return raw[-4096:].decode("utf-8", errors="backslashreplace")


class MockStageAdapter(StageAdapter):
    """Deterministic test backend; never enroll this adapter in production."""

    inline_artifacts = True

    def __init__(
        self, execution_authorities: dict[str, str], *, validator_version: int = 1,
        build_delay_seconds: float = 0.0, max_parallelism: int = 64,
    ) -> None:
        self.execution_authorities = dict(execution_authorities)
        self.validator_version = validator_version
        protocol.require(build_delay_seconds >= 0 and max_parallelism > 0,
                         "mock worker scheduling options differ")
        self.build_delay_seconds = build_delay_seconds
        self.max_parallelism = max_parallelism
        self.build_count = 0
        self.validate_count = 0
        self.release_count = 0
        self._next_lease = 0
        self._live: set[str] = set()
        self._lock = threading.Lock()
        self.active_builds = 0
        self.max_active_builds = 0

    def describe(self, node: dict[str, Any]) -> dict[str, Any]:
        return validate_stage_description(protocol.seal({
            "schema": STAGE_DESCRIPTION_SCHEMA,
            "stage_kind": node["stage_kind"],
            "stage_schema_version": node["stage_schema_version"],
            "output_kind": node["output_kind"],
            "output_schema_version": node["output_schema_version"],
            "minimum_cpu_tokens": node["cpu_tokens"],
            "minimum_rss_tokens": node["rss_tokens"],
            "root_cold_open_transitive": True,
        }), node)

    def derive(
        self, campaign_namespace: str, node: dict[str, Any],
        ordered_inputs: list[dict[str, Any]],
        execution_authorities: dict[str, str],
    ) -> DerivedKeys:
        semantic = protocol.mock_semantic_key(
            campaign_namespace=campaign_namespace,
            node=node,
            ordered_inputs=ordered_inputs,
        )
        execution = protocol.mock_execution_key(semantic, execution_authorities)
        return DerivedKeys(
            semantic, execution, protocol.semantic_key_bytes(semantic),
            protocol.execution_key_bytes(execution),
        )

    def build(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        dependency_leases: list[Lease], attempt_directory: Path,
    ) -> Candidate:
        with self._lock:
            for lease in dependency_leases:
                protocol.require(not lease.released and lease.token in self._live,
                                 "mock dependency lease is not live")
            self.build_count += 1
            candidate_ordinal = self.build_count
            self.active_builds += 1
            self.max_active_builds = max(self.max_active_builds, self.active_builds)
        if self.build_delay_seconds:
            time.sleep(self.build_delay_seconds)
        output = protocol.canonical_bytes({
            "schema": "stwo.recursive-pipeline-mock-output.v1",
            "node_id": node["node_id"],
            "semantic_key_sha256": semantic["identity_sha256"],
            "candidate_ordinal": candidate_ordinal,
            "ordered_input_sha256": [
                item["blob"]["sha256"] for item in ordered_inputs
            ],
        })
        profile = protocol.seal({
            "schema": MOCK_PROFILE_SCHEMA,
            "node_id": node["node_id"],
            "semantic_key_sha256": semantic["identity_sha256"],
            "execution_key_sha256": execution["identity_sha256"],
            "wall_ns": 1,
            "user_ns": 0,
            "system_ns": 0,
            "peak_rss_bytes": node["rss_tokens"],
            "cpu_tokens": node["cpu_tokens"],
            "cache_status": "executed",
            "candidate_ordinal": candidate_ordinal,
        })
        with self._lock:
            for lease in dependency_leases:
                self._live.remove(lease.token)
                lease.released = True
            self.active_builds -= 1
        return Candidate(output=output, profile_receipt=profile)

    def cold_open(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        output_ref: dict[str, Any], output: bytes | None, *, output_path: Path,
        dependency_stage_manifest_refs: list[dict[str, Any]],
        stage_manifest_ref: dict[str, Any] | None, mode: str,
    ) -> ColdOpen:
        protocol.require(mode in ("shallow", "cold", "fresh", "root"),
                         "mock validation mode differs")
        protocol.require(output is not None,
                         "mock cold-open requires inline artifact bytes")
        with self._lock:
            self.validate_count += 1
        protocol.require(protocol.sha256_bytes(output) == output_ref["sha256"]
                         and len(output) == output_ref["byte_count"],
                         "mock output identity differs")
        parsed = protocol.parse_canonical(
            output,
            lambda value: protocol.exact(value, {
                "schema", "node_id", "semantic_key_sha256",
                "candidate_ordinal", "ordered_input_sha256",
            }, "mock output"),
            "mock output",
        )
        protocol.require(parsed["schema"] == "stwo.recursive-pipeline-mock-output.v1"
                         and parsed["node_id"] == node["node_id"]
                         and parsed["semantic_key_sha256"]
                         == semantic["identity_sha256"]
                         and type(parsed["candidate_ordinal"]) is int
                         and parsed["candidate_ordinal"] > 0
                         and parsed["ordered_input_sha256"] == [
                             item["blob"]["sha256"] for item in ordered_inputs
                         ], "mock output semantics differ")
        with self._lock:
            token = f"mock-lease-{self._next_lease:08d}"
            self._next_lease += 1
            self._live.add(token)
        receipt = protocol.seal({
            "schema": MOCK_VALIDATION_SCHEMA,
            "node_id": node["node_id"],
            "semantic_key_sha256": semantic["identity_sha256"],
            "output_sha256": output_ref["sha256"],
            "validator_version": self.validator_version,
            "mode": mode,
            "valid": True,
        })
        manifest = protocol.mock_stage_manifest_bytes(
            node=node, semantic=semantic, execution=execution,
            ordered_inputs=ordered_inputs, output_ref=output_ref,
            dependency_stage_manifest_refs=dependency_stage_manifest_refs,
        )
        return ColdOpen(
            receipt, Lease(self, token, output_ref), stage_manifest=manifest,
        )

    def release(self, lease: Lease) -> None:
        with self._lock:
            protocol.require(lease.token in self._live, "mock lease is not live")
            self._live.remove(lease.token)
            self.release_count += 1


class StageRegistry:
    def __init__(self, *, allow_mock: bool = False) -> None:
        self.allow_mock = allow_mock
        self.adapters: dict[str, StageAdapter] = {}

    def register(self, name: str, adapter: StageAdapter) -> None:
        protocol.require(type(name) is str and name and name not in self.adapters,
                         "pipeline adapter registration differs")
        if isinstance(adapter, MockStageAdapter):
            protocol.require(self.allow_mock, "mock pipeline adapter is not admitted")
        else:
            protocol.require(isinstance(adapter, ZigWorkerAdapter),
                             "production adapter must be a Zig worker")
        self.adapters[name] = adapter

    def get(self, name: str) -> StageAdapter:
        try:
            return self.adapters[name]
        except KeyError as error:
            raise protocol.PipelineError(f"unknown pipeline adapter: {name}") from error

    def close(self) -> None:
        for adapter in self.adapters.values():
            adapter.close()

    def max_parallelism(self) -> int:
        protocol.require(bool(self.adapters), "pipeline registry is empty")
        return min(adapter.max_parallelism for adapter in self.adapters.values())


def validate_stage_description(
    value: Any, node: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "stage_kind", "stage_schema_version", "output_kind",
        "output_schema_version", "minimum_cpu_tokens", "minimum_rss_tokens",
        "root_cold_open_transitive", "content_sha256",
    }, "pipeline stage description")
    protocol.require(value["schema"] == STAGE_DESCRIPTION_SCHEMA,
                     "pipeline stage description schema differs")
    for field in (
        "stage_kind", "stage_schema_version", "output_kind",
        "output_schema_version", "minimum_cpu_tokens", "minimum_rss_tokens",
    ):
        protocol.require(type(value[field]) is int and value[field] > 0,
                         f"pipeline stage description {field} differs")
    protocol.require(type(value["root_cold_open_transitive"]) is bool,
                     "pipeline root cold-open declaration differs")
    protocol.validate_seal(value, "pipeline stage description")
    if node is not None:
        for field in (
            "stage_kind", "stage_schema_version", "output_kind",
            "output_schema_version",
        ):
            protocol.require(value[field] == node[field],
                             f"pipeline stage description {field} mismatch")
        protocol.require(value["minimum_cpu_tokens"] <= node["cpu_tokens"]
                         and value["minimum_rss_tokens"] <= node["rss_tokens"],
                         "pipeline stage resource declaration is insufficient")
    return value


def _read_regular(path: Path, where: str) -> bytes:
    try:
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        after = os.fstat(descriptor)
        protocol.require(before.st_ino == after.st_ino and before.st_dev == after.st_dev,
                         f"{where} changed during open")
        with os.fdopen(descriptor, "rb") as source:
            return source.read()
    except OSError as error:
        raise protocol.PipelineError(f"cannot read {where}") from error


def _read_canonical(path: Path, where: str) -> dict[str, Any]:
    raw = _read_regular(path, where)
    return protocol.parse_canonical(
        raw, lambda value: protocol.validate_seal(value, where), where,
    )
