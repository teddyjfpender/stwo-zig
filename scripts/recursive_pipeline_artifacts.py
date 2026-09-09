"""Streaming artifact custody helpers mixed into the pipeline Runner."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_protocol as proof_protocol
from scripts import ethereum_block_proof_store as durable
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_store as store_mod


STAGE_RESULT_SCHEMA = "stwo.recursive-pipeline-stage-result.v1"
STAGE_RESULT_KIND = 7
PROFILE_RECEIPT_KIND = 6
VALIDATION_RECEIPT_KIND = 5
LOG_KIND = 1
CONTROL_SCHEMA_VERSION = 1


def validate_stage_result(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "node_id", "attempt_index", "semantic_key",
        "execution_key", "ordered_inputs", "output_artifact",
        "profile_receipt", "stdout_log", "stderr_log", "content_sha256",
    }, "pipeline stage result")
    protocol.require(value["schema"] == STAGE_RESULT_SCHEMA,
                     "pipeline stage result schema differs")
    protocol.require(type(value["node_id"]) is str
                     and protocol.NODE_ID.fullmatch(value["node_id"]),
                     "pipeline stage result node differs")
    protocol.require(type(value["attempt_index"]) is int
                     and value["attempt_index"] >= 0,
                     "pipeline stage result attempt differs")
    for field in (
        "semantic_key", "execution_key", "output_artifact",
        "profile_receipt", "stdout_log", "stderr_log",
    ):
        protocol.validate_blob_ref(value[field], f"stage result {field}")
    expected = {
        "semantic_key": (2, 1), "execution_key": (3, 1),
        "profile_receipt": (6, 1), "stdout_log": (1, 1),
        "stderr_log": (1, 1),
    }
    for field, (kind, schema) in expected.items():
        protocol.require(value[field]["kind"] == kind
                         and value[field]["schema_version"] == schema,
                         f"stage result {field} codec differs")
    protocol.require(type(value["ordered_inputs"]) is list,
                     "pipeline stage result inputs differ")
    for index, item in enumerate(value["ordered_inputs"]):
        protocol._validate_role_ref(item, f"stage result input {index}")
    return protocol.validate_seal(value, "pipeline stage result")


class ArtifactCustodyMixin:
    workspace: store_mod.Workspace
    registry: registry_mod.StageRegistry

    def _publish_candidate_files(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        attempt_index: int, directory: Path, candidate: registry_mod.Candidate,
        semantic_ref: dict[str, Any], execution_ref: dict[str, Any],
    ) -> dict[str, Any]:
        protocol.validate_seal(candidate.profile_receipt, "stage profile receipt")
        paths = {
            "output": directory / "output.bin",
            "candidate_ref": directory / "candidate-ref.json",
            "profile": directory / "profile.json",
            "stdout": directory / "stdout.log",
            "stderr": directory / "stderr.log",
        }
        if candidate.output_ref is None:
            protocol.require(candidate.output is not None,
                             "inline pipeline output is absent")
            durable.publish_new_or_identical(
                paths["output"], candidate.output,
                staging_directory=self.workspace.staging,
            )
            output_ref = self.workspace.put_blob(
                candidate.output, kind=node["output_kind"],
                schema_version=node["output_schema_version"],
            )
        else:
            protocol.require(candidate.output is None
                             and candidate.output_path == paths["output"],
                             "worker output custody path differs")
            output_ref = protocol.validate_blob_ref(
                candidate.output_ref, "worker output artifact",
            )
            protocol.require(output_ref["kind"] == node["output_kind"]
                             and output_ref["schema_version"]
                             == node["output_schema_version"],
                             "worker output codec differs")
            self.workspace.stat_blob(output_ref, "worker output CAS object")
        durable.publish_new_or_identical(
            paths["profile"], protocol.canonical_bytes(candidate.profile_receipt),
            staging_directory=self.workspace.staging,
        )
        for name, payload in (("stdout", candidate.stdout),
                              ("stderr", candidate.stderr)):
            durable.publish_new_or_identical(
                paths[name], payload, staging_directory=self.workspace.staging,
            )
        profile_ref = self.workspace.put_blob(
            protocol.canonical_bytes(candidate.profile_receipt),
            kind=PROFILE_RECEIPT_KIND, schema_version=CONTROL_SCHEMA_VERSION,
        )
        stdout_ref = self.workspace.put_blob(
            durable.read_regular(paths["stdout"], "pipeline stdout log"),
            kind=LOG_KIND, schema_version=CONTROL_SCHEMA_VERSION,
        )
        stderr_ref = self.workspace.put_blob(
            durable.read_regular(paths["stderr"], "pipeline stderr log"),
            kind=LOG_KIND, schema_version=CONTROL_SCHEMA_VERSION,
        )
        stage = protocol.seal({
            "schema": STAGE_RESULT_SCHEMA,
            "node_id": node["node_id"],
            "attempt_index": attempt_index,
            "semantic_key": semantic_ref,
            "execution_key": execution_ref,
            "ordered_inputs": ordered_inputs,
            "output_artifact": output_ref,
            "profile_receipt": profile_ref,
            "stdout_log": stdout_ref,
            "stderr_log": stderr_ref,
        })
        validate_stage_result(stage)
        stage_raw = protocol.canonical_bytes(stage)
        durable.publish_new_or_identical(
            directory / "stage-result.json", stage_raw,
            staging_directory=self.workspace.staging,
        )
        stage_ref = self.workspace.put_blob(
            stage_raw, kind=STAGE_RESULT_KIND,
            schema_version=CONTROL_SCHEMA_VERSION,
        )
        return {
            "semantic_key": semantic_ref,
            "execution_key": execution_ref,
            "output_artifact": output_ref,
            "stage_result": stage_ref,
            "profile_receipt": profile_ref,
        }

    def _read_candidate_files(
        self, directory: Path, node: dict[str, Any],
        adapter: registry_mod.StageAdapter,
    ) -> registry_mod.Candidate | None:
        output = directory / "output.bin"
        profile = directory / "profile.json"
        if not os.path.lexists(output) or not os.path.lexists(profile):
            return None
        try:
            candidate_ref_path = directory / "candidate-ref.json"
            if os.path.lexists(candidate_ref_path):
                candidate_ref = protocol.parse_canonical(
                    durable.read_regular(
                        candidate_ref_path, "recoverable worker candidate reference",
                        maximum=durable.MAX_JSON_BYTES,
                    ),
                    lambda value: protocol.validate_seal(
                        value, "recoverable worker candidate reference",
                    ),
                    "recoverable worker candidate reference",
                )
                protocol.exact(candidate_ref, {
                    "schema", "output_ref", "content_sha256",
                }, "recoverable worker candidate reference")
                protocol.require(
                    candidate_ref["schema"]
                    == registry_mod.WORKER_CANDIDATE_REF_SCHEMA,
                    "recoverable worker candidate schema differs",
                )
                output_ref = protocol.validate_blob_ref(
                    candidate_ref["output_ref"],
                    "recoverable worker output reference",
                )
                protocol.require(output_ref["kind"] == node["output_kind"]
                                 and output_ref["schema_version"]
                                 == node["output_schema_version"],
                                 "recoverable worker output codec differs")
                self.workspace.stat_blob(
                    output_ref, "recoverable worker output CAS object",
                )
            else:
                protocol.require(
                    adapter.inline_artifacts,
                    "worker candidate reference is absent",
                )
                output_ref = self.workspace.put_file(
                    output, kind=node["output_kind"],
                    schema_version=node["output_schema_version"],
                )
            profile_raw = durable.read_regular(
                profile, "recoverable pipeline profile", maximum=durable.MAX_JSON_BYTES,
            )
            profile_value = protocol.parse_canonical(
                profile_raw,
                lambda value: protocol.validate_seal(value, "pipeline profile"),
                "pipeline profile",
            )
            stdout_path = directory / "stdout.log"
            stderr_path = directory / "stderr.log"
            stdout_raw = (durable.read_regular(stdout_path, "recoverable stdout")
                          if os.path.lexists(stdout_path) else b"")
            stderr_raw = (durable.read_regular(stderr_path, "recoverable stderr")
                          if os.path.lexists(stderr_path) else b"")
            return registry_mod.Candidate(
                None, profile_value, stdout_raw, stderr_raw,
                output_ref=output_ref, output_path=output,
            )
        except (OSError, ValueError, proof_protocol.ProofProtocolError):
            return None

    def _refs_from_record(self, record: dict[str, Any]) -> dict[str, Any]:
        for field in ("output_artifact", "stage_result", "profile_receipt"):
            protocol.require(record[field] is not None,
                             "pipeline attempt output references are absent")
        stage = self._read_stage_result(record["stage_result"])
        protocol.require(stage["output_artifact"] == record["output_artifact"]
                         and stage["profile_receipt"] == record["profile_receipt"],
                         "pipeline attempt stage references differ")
        return {
            "semantic_key": stage["semantic_key"],
            "execution_key": stage["execution_key"],
            "output_artifact": record["output_artifact"],
            "stage_result": record["stage_result"],
            "profile_receipt": record["profile_receipt"],
        }

    def _cache_record(
        self, node: dict[str, Any], semantic: dict[str, Any],
        execution: dict[str, Any], refs: dict[str, Any],
        stage_manifest_ref: dict[str, Any], validation_ref: dict[str, Any],
        validation_log_ref: dict[str, Any],
        validator_version: int,
    ) -> dict[str, Any]:
        value = protocol.seal({
            "schema": protocol.CACHE_RECORD_SCHEMA,
            "node_id": node["node_id"],
            "semantic_key_sha256": semantic["identity_sha256"],
            "execution_key_sha256": execution["identity_sha256"],
            "semantic_key": refs["semantic_key"],
            "execution_key": refs["execution_key"],
            "output_artifact": refs["output_artifact"],
            "stage_manifest": stage_manifest_ref,
            "stage_result": refs["stage_result"],
            "validation_receipt": validation_ref,
            "validator_log": validation_log_ref,
            "profile_receipt": refs["profile_receipt"],
            "validator_version": validator_version,
        })
        return store_mod.validate_cache_record(value)

    def _validation_ref(self, receipt: dict[str, Any]) -> dict[str, Any]:
        protocol.validate_seal(receipt, "pipeline validation receipt")
        return self.workspace.put_blob(
            protocol.canonical_bytes(receipt), kind=VALIDATION_RECEIPT_KIND,
            schema_version=CONTROL_SCHEMA_VERSION,
        )

    def _validation_log_ref(
        self, adapter: registry_mod.StageAdapter,
    ) -> dict[str, Any]:
        return self.workspace.put_blob(
            adapter.diagnostic_log(), kind=LOG_KIND,
            schema_version=CONTROL_SCHEMA_VERSION,
        )

    def _cold_open_refs(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        output_ref: dict[str, Any], adapter: registry_mod.StageAdapter,
        mode: str, *,
        dependency_stage_manifest_refs: list[dict[str, Any]] | None = None,
        stage_manifest_ref: dict[str, Any] | None = None,
    ) -> registry_mod.ColdOpen:
        output_path = (self.workspace.validate_blob(
            output_ref, "pipeline output artifact",
        ) if adapter.inline_artifacts else self.workspace.stat_blob(
            output_ref, "pipeline output artifact",
        ))
        output = (self.workspace.read_blob(
            output_ref, "pipeline output artifact",
        ) if adapter.inline_artifacts else None)
        opened = adapter.cold_open(
            node, ordered_inputs, semantic, execution, output_ref, output,
            output_path=output_path,
            dependency_stage_manifest_refs=dependency_stage_manifest_refs or [],
            stage_manifest_ref=stage_manifest_ref, mode=mode,
        )
        protocol.require(
            (opened.stage_manifest_ref is None) != (opened.stage_manifest is None),
            "pipeline cold-open stage manifest custody differs",
        )
        if opened.stage_manifest_ref is None:
            protocol.require(adapter.inline_artifacts,
                             "production worker did not publish stage manifest")
            opened.stage_manifest_ref = self.workspace.put_blob(
                opened.stage_manifest or b"", kind=4, schema_version=1,
            )
        else:
            protocol.require(opened.stage_manifest is None,
                             "worker returned duplicate stage manifest custody")
            self.workspace.stat_blob(
                opened.stage_manifest_ref, "worker stage manifest CAS object",
            )
        return opened

    def _cold_open_record(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], record: dict[str, Any], mode: str,
        *, adapter: registry_mod.StageAdapter | None = None,
    ) -> registry_mod.ColdOpen:
        store_mod.validate_cache_record(record)
        stage = self._read_stage_result(record["stage_result"])
        protocol.require(stage["ordered_inputs"] == ordered_inputs
                         and stage["output_artifact"] == record["output_artifact"]
                         and stage["semantic_key"] == record["semantic_key"]
                         and stage["execution_key"] == record["execution_key"]
                         and stage["profile_receipt"] == record["profile_receipt"],
                         "cached stage result differs")
        execution = self._read_execution(record["execution_key"], semantic)
        return self._cold_open_refs(
            node, ordered_inputs, semantic, execution,
            record["output_artifact"],
            adapter or self.registry.get(node["adapter"]), mode,
            stage_manifest_ref=record["stage_manifest"],
        )

    def _read_semantic(self, record: dict[str, Any]) -> dict[str, Any]:
        protocol.require(record["semantic_key"]["kind"] == 2
                         and record["semantic_key"]["schema_version"] == 1,
                         "semantic key codec differs")
        raw = self.workspace.read_blob(record["semantic_key"], "semantic key wire")
        semantic = protocol.decode_semantic_key(raw)
        protocol.require(semantic["identity_sha256"]
                         == record["semantic_key_sha256"],
                         "cache semantic identity differs")
        return semantic

    def _read_execution(
        self, ref: dict[str, Any], semantic: dict[str, Any],
    ) -> dict[str, Any]:
        protocol.require(ref["kind"] == 3 and ref["schema_version"] == 1,
                         "execution key codec differs")
        raw = self.workspace.read_blob(ref, "execution key wire")
        execution = protocol.decode_execution_key(raw)
        return protocol.validate_execution_key(execution, semantic)

    def _read_stage_result(self, ref: dict[str, Any]) -> dict[str, Any]:
        protocol.require(ref["kind"] == STAGE_RESULT_KIND
                         and ref["schema_version"] == CONTROL_SCHEMA_VERSION,
                         "pipeline stage result codec differs")
        raw = self.workspace.read_blob(ref, "pipeline stage result")
        return protocol.parse_canonical(raw, validate_stage_result,
                                        "pipeline stage result")

    def _stage_inputs(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read_stage_result(record["stage_result"])["ordered_inputs"]
