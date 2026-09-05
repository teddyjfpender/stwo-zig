"""Shared-layout CAS and append-only run references for recursive pipelines."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Iterator

from scripts import ethereum_block_proof_store as durable
from scripts import ethereum_block_proof_protocol as proof_protocol
from scripts import recursive_pipeline_protocol as protocol


MAX_OBJECT_BYTES = 128 * 1024 * 1024 * 1024
CACHE_RECORD_KIND = 1
CACHE_RECORD_SCHEMA_VERSION = 2
PIPELINE_MANIFEST_KIND = 1
PIPELINE_MANIFEST_SCHEMA_VERSION = 3
RUN_REF_SCHEMA = "stwo.recursive-pipeline-run-ref.v1"
CAS_OBJECT_MODE = 0o400


def _mkdir(path: Path) -> None:
    if not os.path.lexists(path):
        try:
            path.mkdir(mode=0o700)
            durable._fsync_directory(path.parent)
        except FileExistsError:
            pass
        except OSError as error:
            raise protocol.PipelineError(
                "cannot create recursive pipeline directory"
            ) from error
    durable.require_directory(path, "recursive pipeline directory")


def _node_component(node_id: str) -> str:
    protocol.require(protocol.NODE_ID.fullmatch(node_id) is not None and "@" not in node_id,
                     "pipeline node id cannot be mapped to storage")
    return node_id.replace("/", "@")


class Workspace:
    """Private, create-only workspace with a process-independent object layout."""

    def __init__(
        self, root: Path, *, create: bool = False, read_only: bool = False,
    ) -> None:
        protocol.require(not (create and read_only),
                         "pipeline workspace mode differs")
        self.root = root.absolute()
        if create and not os.path.lexists(self.root):
            self.root.mkdir(mode=0o700)
            durable._fsync_directory(self.root.parent)
        durable.require_directory(self.root, "recursive pipeline workspace")
        self.staging = self.root / ".staging"
        self.objects = self.root / "objects"
        self.sha_objects = self.objects / "sha256"
        self.manifests = self.root / "manifests"
        self.campaigns = self.root / "campaigns"
        self.runs = self.root / "runs"
        self.cache = self.root / "cache"
        self.semantic_cache = self.cache / "semantic"
        for path in (
            self.staging, self.objects, self.sha_objects, self.manifests,
            self.campaigns,
            self.runs, self.cache, self.semantic_cache,
        ):
            if read_only:
                durable.require_directory(path, "recursive pipeline directory")
            else:
                _mkdir(path)

    def object_path(self, sha256: str) -> Path:
        protocol.digest(sha256, "object sha256")
        return self.sha_objects / sha256[:2] / f"{sha256}.blob"

    def put_blob(
        self, raw: bytes, *, kind: int, schema_version: int,
        format_version: int = 1,
    ) -> dict[str, Any]:
        protocol.require(len(raw) <= MAX_OBJECT_BYTES, "pipeline object exceeds byte bound")
        digest = protocol.sha256_bytes(raw)
        prefix = self.sha_objects / digest[:2]
        _mkdir(prefix)
        path = self.object_path(digest)
        ref = protocol.blob_ref(
            kind=kind,
            format_version=format_version,
            schema_version=schema_version,
            byte_count=len(raw),
            sha256=digest,
        )
        self._publish_blob_bytes(path, raw, ref)
        return ref

    def read_blob(self, ref: dict[str, Any], where: str = "pipeline object") -> bytes:
        protocol.validate_blob_ref(ref, where)
        descriptor = self._open_blob(ref, where)
        try:
            with os.fdopen(descriptor, "rb") as source:
                raw = source.read(MAX_OBJECT_BYTES + 1)
        except OSError as error:
            raise protocol.PipelineError(f"cannot read {where}") from error
        protocol.require(len(raw) == ref["byte_count"]
                         and protocol.sha256_bytes(raw) == ref["sha256"],
                         f"{where} identity differs")
        return raw

    def validate_blob(
        self, ref: dict[str, Any], where: str = "pipeline object",
    ) -> Path:
        protocol.validate_blob_ref(ref, where)
        path = self.object_path(ref["sha256"])
        descriptor = self._open_blob(ref, where)
        hasher = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "rb") as source:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    protocol.require(size <= MAX_OBJECT_BYTES,
                                     f"{where} exceeds byte bound")
                    hasher.update(chunk)
        except OSError as error:
            raise protocol.PipelineError(f"cannot stream {where}") from error
        protocol.require(size == ref["byte_count"]
                         and hasher.hexdigest() == ref["sha256"],
                         f"{where} identity differs")
        return path

    def stat_blob(
        self, ref: dict[str, Any], where: str = "pipeline object",
    ) -> Path:
        """Check custody without hashing bytes; the Zig worker cold-opens them.

        Production proof bytes are never hashed or interpreted by Python.  This
        check only closes path/type/size substitution before passing the exact
        shared-CAS path and typed BlobRef to the worker.
        """
        protocol.validate_blob_ref(ref, where)
        path = self.object_path(ref["sha256"])
        descriptor = self._open_blob(ref, where)
        try:
            stat = os.fstat(descriptor)
            protocol.require(stat.st_size == ref["byte_count"],
                             f"{where} byte count differs")
        finally:
            os.close(descriptor)
        return path

    def put_file(
        self, source_path: Path, *, kind: int, schema_version: int,
        format_version: int = 1,
    ) -> dict[str, Any]:
        descriptor = durable._open_regular(
            source_path, os.O_RDONLY, "pipeline candidate artifact",
        )
        hasher = hashlib.sha256()
        size = 0
        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".pipeline-object.", suffix=".tmp", dir=self.staging,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "rb") as source, os.fdopen(
                temporary_descriptor, "wb",
            ) as output:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    protocol.require(size <= MAX_OBJECT_BYTES,
                                     "pipeline object exceeds byte bound")
                    hasher.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fchmod(output.fileno(), CAS_OBJECT_MODE)
                os.fsync(output.fileno())
            ref = protocol.blob_ref(
                kind=kind, format_version=format_version,
                schema_version=schema_version, byte_count=size,
                sha256=hasher.hexdigest(),
            )
            prefix = self.sha_objects / ref["sha256"][:2]
            _mkdir(prefix)
            destination = self.object_path(ref["sha256"])
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                self.validate_blob(ref, "existing pipeline object")
            durable._fsync_directory(prefix)
            return ref
        except OSError as error:
            raise protocol.PipelineError("cannot ingest pipeline object") from error
        finally:
            temporary.unlink(missing_ok=True)

    def _open_blob(self, ref: dict[str, Any], where: str) -> int:
        path = self.object_path(ref["sha256"])
        descriptor = durable._open_regular(path, os.O_RDONLY, where)
        try:
            metadata = os.fstat(descriptor)
            protocol.require(
                stat.S_ISREG(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == CAS_OBJECT_MODE,
                f"{where} is not immutable mode 0400",
            )
            protocol.require(
                metadata.st_size == ref["byte_count"],
                f"{where} byte count differs",
            )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _publish_blob_bytes(
        self, path: Path, raw: bytes, ref: dict[str, Any],
    ) -> None:
        if os.path.lexists(path):
            protocol.require(
                self.read_blob(ref, "existing pipeline object") == raw,
                "existing pipeline object bytes differ",
            )
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".pipeline-object.", suffix=".tmp", dir=self.staging,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fchmod(output.fileno(), CAS_OBJECT_MODE)
                os.fsync(output.fileno())
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                protocol.require(
                    self.read_blob(ref, "concurrent pipeline object") == raw,
                    "concurrent pipeline object bytes differ",
                )
            durable._fsync_directory(path.parent)
        except OSError as error:
            raise protocol.PipelineError("cannot publish pipeline object") from error
        finally:
            temporary.unlink(missing_ok=True)

    def publish_manifest(self, manifest: dict[str, Any]) -> Path:
        protocol.validate_pipeline_manifest(manifest)
        raw = protocol.canonical_bytes(manifest)
        path = self.manifests / f"{manifest['content_sha256']}.json"
        durable.publish_new_or_identical(path, raw, staging_directory=self.staging)
        self.put_blob(
            raw, kind=PIPELINE_MANIFEST_KIND,
            schema_version=PIPELINE_MANIFEST_SCHEMA_VERSION,
        )
        return path

    def read_manifest(self, identity: str) -> dict[str, Any]:
        protocol.digest(identity, "pipeline manifest identity")
        raw = durable.read_regular(
            self.manifests / f"{identity}.json",
            "pipeline manifest",
            maximum=durable.MAX_JSON_BYTES,
        )
        result = protocol.parse_canonical(
            raw, protocol.validate_pipeline_manifest, "pipeline manifest",
        )
        protocol.require(result["content_sha256"] == identity,
                         "pipeline manifest selector differs")
        return result

    def publish_campaign_document(self, value: dict[str, Any]) -> Path:
        protocol.validate_seal(value, "campaign document")
        identity = value["content_sha256"]
        path = self.campaigns / f"{identity}.json"
        raw = protocol.canonical_bytes(value)
        durable.publish_new_or_identical(path, raw, staging_directory=self.staging)
        self.put_blob(raw, kind=1, schema_version=4)
        return path

    def read_campaign_document(
        self, identity: str, validator: Any,
    ) -> dict[str, Any]:
        protocol.digest(identity, "campaign document identity")
        raw = durable.read_regular(
            self.campaigns / f"{identity}.json", "campaign document",
            maximum=durable.MAX_JSON_BYTES,
        )
        result = protocol.parse_canonical(raw, validator, "campaign document")
        protocol.require(result["content_sha256"] == identity,
                         "campaign document selector differs")
        return result

    def prepare_run(self, run_id: str, manifest: dict[str, Any]) -> Path:
        protocol.require(type(run_id) is str and protocol.NODE_ID.fullmatch(run_id),
                         "pipeline run id differs")
        run_root = self.runs / run_id
        _mkdir(run_root)
        for name in ("stages", "refs"):
            _mkdir(run_root / name)
        durable.publish_new_or_identical(
            run_root / "manifest.json",
            protocol.canonical_bytes(manifest),
            staging_directory=self.staging,
        )
        durable.publish_new_or_identical(
            run_root / ".lock", b"", staging_directory=self.staging,
        )
        return run_root

    def open_run(self, run_id: str, manifest: dict[str, Any]) -> Path:
        protocol.require(type(run_id) is str and protocol.NODE_ID.fullmatch(run_id),
                         "pipeline run id differs")
        run_root = self.runs / run_id
        durable.require_directory(run_root, "recursive pipeline run")
        durable.require_directory(run_root / "stages", "pipeline stages")
        durable.require_directory(run_root / "refs", "pipeline refs")
        durable.read_regular(run_root / ".lock", "pipeline run lock", maximum=0)
        raw = durable.read_regular(
            run_root / "manifest.json", "pipeline run manifest",
            maximum=durable.MAX_JSON_BYTES,
        )
        protocol.require(raw == protocol.canonical_bytes(manifest),
                         "pipeline run manifest differs")
        return run_root

    @contextmanager
    def run_lock(self, run_id: str, *, exclusive: bool) -> Iterator[None]:
        run_root = self.runs / run_id
        durable.require_directory(run_root, "recursive pipeline run")
        descriptor = durable._open_regular(
            run_root / ".lock", os.O_RDWR if exclusive else os.O_RDONLY,
            "pipeline run lock",
        )
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise protocol.PipelineError("pipeline run is already locked") from error
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def stage_root(self, run_id: str, node_id: str) -> Path:
        path = self.runs / run_id / "stages" / _node_component(node_id)
        _mkdir(path)
        return path

    def cache_directory(self, semantic_sha256: str) -> Path:
        protocol.digest(semantic_sha256, "semantic cache identity")
        prefix = self.semantic_cache / semantic_sha256[:2]
        _mkdir(prefix)
        path = prefix / semantic_sha256
        _mkdir(path)
        return path

    def publish_cache_record(self, value: dict[str, Any]) -> tuple[dict[str, Any], Path]:
        validate_cache_record(value)
        raw = protocol.canonical_bytes(value)
        directory = self.cache_directory(value["semantic_key_sha256"])
        name = f"candidate-{value['content_sha256']}.json"
        path = directory / name
        durable.publish_new_or_identical(path, raw, staging_directory=self.staging)
        ref = self.put_blob(
            raw, kind=CACHE_RECORD_KIND,
            schema_version=CACHE_RECORD_SCHEMA_VERSION,
        )
        return ref, path

    def cache_records(self, semantic_sha256: str) -> Iterator[dict[str, Any]]:
        directory = self.cache_directory(semantic_sha256)
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            raw = durable.read_regular(path, "pipeline cache record",
                                       maximum=durable.MAX_JSON_BYTES)
            record = protocol.parse_canonical(raw, validate_cache_record,
                                              "pipeline cache record")
            protocol.require(record["semantic_key_sha256"] == semantic_sha256
                             and path.name
                             == f"candidate-{record['content_sha256']}.json",
                             "pipeline cache record selector differs")
            yield record

    def cache_record_by_identity(
        self, semantic_sha256: str, record_sha256: str,
    ) -> dict[str, Any]:
        protocol.digest(record_sha256, "pipeline cache record identity")
        for record in self.cache_records(semantic_sha256):
            if record["content_sha256"] == record_sha256:
                return record
        raise protocol.PipelineError("selected pipeline cache record is absent")

    def publish_run_ref(
        self, run_id: str, node_id: str, cache_record: dict[str, Any],
    ) -> dict[str, Any]:
        validate_cache_record(cache_record)
        directory = self.runs / run_id / "refs" / _node_component(node_id)
        _mkdir(directory)
        generations = sorted(directory.glob("generation-*.json"))
        if generations:
            current = self.read_run_ref(run_id, node_id)
            if (current["cache_record_sha256"] == cache_record["content_sha256"]
                    and current["semantic_key_sha256"]
                    == cache_record["semantic_key_sha256"]):
                return current
        generation = len(generations)
        value = protocol.seal({
            "schema": RUN_REF_SCHEMA,
            "node_id": node_id,
            "generation": generation,
            "semantic_key_sha256": cache_record["semantic_key_sha256"],
            "execution_key_sha256": cache_record["execution_key_sha256"],
            "cache_record_sha256": cache_record["content_sha256"],
            "output_artifact": cache_record["output_artifact"],
            "stage_manifest": cache_record["stage_manifest"],
            "stage_result": cache_record["stage_result"],
        })
        validate_run_ref(value, node_id, generation)
        durable.publish_new_or_identical(
            directory / f"generation-{generation:06d}.json",
            protocol.canonical_bytes(value),
            staging_directory=self.staging,
        )
        return value

    def read_run_ref(self, run_id: str, node_id: str) -> dict[str, Any]:
        directory = self.runs / run_id / "refs" / _node_component(node_id)
        durable.require_directory(directory, "pipeline run reference directory")
        generations = sorted(directory.glob("generation-*.json"))
        protocol.require(bool(generations), f"pipeline node {node_id} has no selected ref")
        protocol.require(
            [path.name for path in generations]
            == [f"generation-{index:06d}.json"
                for index in range(len(generations))],
            "pipeline run reference generations differ",
        )
        raw = durable.read_regular(generations[-1], "pipeline run reference",
                                   maximum=durable.MAX_JSON_BYTES)
        return protocol.parse_canonical(
            raw,
            lambda value: validate_run_ref(value, node_id, len(generations) - 1),
            "pipeline run reference",
        )

    def maybe_run_ref(self, run_id: str, node_id: str) -> dict[str, Any] | None:
        try:
            return self.read_run_ref(run_id, node_id)
        except (FileNotFoundError, protocol.PipelineError,
                proof_protocol.ProofProtocolError):
            return None


def validate_cache_record(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "node_id", "semantic_key_sha256", "execution_key_sha256",
        "semantic_key", "execution_key", "output_artifact", "stage_manifest",
        "stage_result", "validation_receipt", "validator_log",
        "profile_receipt", "validator_version", "content_sha256",
    }, "pipeline cache record")
    protocol.require(value["schema"] == protocol.CACHE_RECORD_SCHEMA,
                     "pipeline cache record schema differs")
    protocol.require(type(value["node_id"]) is str
                     and protocol.NODE_ID.fullmatch(value["node_id"]),
                     "pipeline cache node differs")
    protocol.digest(value["semantic_key_sha256"], "cache semantic key")
    protocol.digest(value["execution_key_sha256"], "cache execution key")
    for field in ("semantic_key", "execution_key", "output_artifact",
                  "stage_manifest", "stage_result", "validation_receipt",
                  "validator_log", "profile_receipt"):
        protocol.validate_blob_ref(value[field], f"cache {field}")
    expected_codecs = {
        "semantic_key": (2, 1),
        "execution_key": (3, 1),
        "stage_manifest": (4, 1),
        "stage_result": (7, 1),
        "validation_receipt": (5, 1),
        "profile_receipt": (6, 1),
        "validator_log": (1, 1),
    }
    for field, (kind, schema) in expected_codecs.items():
        protocol.require(value[field]["kind"] == kind
                         and value[field]["schema_version"] == schema,
                         f"cache {field} codec differs")
    protocol.require(type(value["validator_version"]) is int
                     and value["validator_version"] > 0,
                     "cache validator version differs")
    return protocol.validate_seal(value, "pipeline cache record")


def validate_run_ref(
    value: Any, expected_node: str | None = None,
    expected_generation: int | None = None,
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "node_id", "generation", "semantic_key_sha256",
        "execution_key_sha256", "cache_record_sha256", "output_artifact",
        "stage_manifest", "stage_result", "content_sha256",
    }, "pipeline run reference")
    protocol.require(value["schema"] == RUN_REF_SCHEMA,
                     "pipeline run reference schema differs")
    protocol.require(type(value["node_id"]) is str
                     and protocol.NODE_ID.fullmatch(value["node_id"]),
                     "pipeline run reference node differs")
    protocol.require(type(value["generation"]) is int and value["generation"] >= 0,
                     "pipeline run reference generation differs")
    if expected_node is not None:
        protocol.require(value["node_id"] == expected_node,
                         "pipeline run reference node mismatch")
    if expected_generation is not None:
        protocol.require(value["generation"] == expected_generation,
                         "pipeline run reference generation mismatch")
    for field in ("semantic_key_sha256", "execution_key_sha256",
                  "cache_record_sha256"):
        protocol.digest(value[field], f"pipeline run ref {field}")
    protocol.validate_blob_ref(value["output_artifact"], "run output artifact")
    protocol.validate_blob_ref(value["stage_manifest"], "run stage manifest")
    protocol.require(value["stage_manifest"]["kind"] == 4
                     and value["stage_manifest"]["schema_version"] == 1,
                     "run stage manifest codec differs")
    protocol.validate_blob_ref(value["stage_result"], "run stage result")
    return protocol.validate_seal(value, "pipeline run reference")
