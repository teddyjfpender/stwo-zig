"""Focused-product validation and historical identity transitions."""

from __future__ import annotations

from typing import Any

try:
    from scripts.benchmark_product_contract_lib import (
        ProductEvidenceError,
        comparable_identity,
        revision_identity,
        validate_product_identity,
        validate_receipt,
    )
except ModuleNotFoundError:
    from benchmark_product_contract_lib import (
        ProductEvidenceError,
        comparable_identity,
        revision_identity,
        validate_product_identity,
        validate_receipt,
    )

from .common import DeltaError, IncompatibleReports, require_list, require_object


NATIVE_PROTOCOL_V5 = "native_proof_cross_backend_matrix_v5"
NATIVE_PROTOCOL_V6 = "native_proof_cross_backend_matrix_v6"
LEGACY_V5_PRODUCT_ALIASES = {
    "cpu": {
        "historical_executable": "native-proof-bench-cpu",
        "focused_product": "stwo-native-cpu",
        "backend": "cpu",
    },
    "metal": {
        "historical_executable": "native-proof-bench-metal",
        "focused_product": "stwo-native-metal",
        "backend": "metal",
    },
}


def validate_native_v6_report(report: dict[str, Any], label: str) -> None:
    receipts = require_object(report.get("product_receipts"), f"{label}.product_receipts")
    if set(receipts) != {"cpu", "metal"}:
        raise DeltaError(f"{label}.product_receipts must contain CPU and Metal")
    configuration = require_object(report.get("configuration"), f"{label}.configuration")
    binaries = require_object(configuration.get("binaries"), f"{label}.configuration.binaries")
    host_environment = require_object(
        configuration.get("host_environment"), f"{label}.configuration.host_environment"
    )
    rows = require_list(report.get("rows"), f"{label}.rows")
    for lane in ("cpu", "metal"):
        binary = require_object(binaries.get(lane), f"{label}.configuration.binaries.{lane}")
        identities: list[dict[str, Any]] = []
        try:
            for index, value in enumerate(rows):
                row = require_object(value, f"{label}.rows[{index}]")
                lanes = require_object(row.get("lanes"), f"{label}.rows[{index}].lanes")
                lane_row = require_object(
                    lanes.get(lane), f"{label}.rows[{index}].lanes.{lane}"
                )
                identities.append(
                    validate_product_identity(lane_row.get("product_identity"), lane)
                )
            if not identities or any(identity != identities[0] for identity in identities[1:]):
                raise DeltaError(f"{label} {lane} product identity changed between rows")
            receipt = validate_receipt(
                receipts[lane],
                lane=lane,
                evidence_kind="benchmark",
                expected_identity=identities[0],
                expected_executable_sha256=binary.get("sha256"),
                expected_host_device=host_environment,
            )
            _validate_measurements(receipt, rows, lane, label)
            if receipt["promotion_eligible"] is not _formal_ready(configuration, rows):
                raise DeltaError(f"{label} {lane} receipt promotion state is inconsistent")
        except ProductEvidenceError as error:
            raise DeltaError(f"{label} {lane} product evidence is invalid: {error}") from error


def _validate_measurements(
    receipt: dict[str, Any], rows: list[Any], lane: str, label: str
) -> None:
    measurements = receipt["measurements"]
    if len(measurements) != len(rows):
        raise DeltaError(f"{label} {lane} receipt row count differs")
    for index, (row_value, measurement) in enumerate(zip(rows, measurements, strict=True)):
        row = require_object(row_value, f"{label}.rows[{index}]")
        workload = require_object(row.get("workload"), f"{label}.rows[{index}].workload")
        expected_workload = {**workload, "descriptor_sha256": row.get("descriptor_sha256")}
        if measurement["workload"] != expected_workload:
            raise DeltaError(f"{label} {lane} receipt workload differs at row {index}")
        if measurement["numerator"] != {
            "unit": workload.get("native_unit"),
            "units": workload.get("native_units"),
        }:
            raise DeltaError(f"{label} {lane} receipt numerator differs at row {index}")
        lanes = require_object(row.get("lanes"), f"{label}.rows[{index}].lanes")
        lane_row = require_object(lanes.get(lane), f"{label}.rows[{index}].lanes.{lane}")
        proof = require_object(lane_row.get("proof"), f"{label}.rows[{index}].lanes.{lane}.proof")
        status = measurement["proof_status"]
        if (
            status["verified_samples"] != proof.get("verified_samples")
            or status["byte_identical_samples"] != proof.get("all_samples_byte_identical")
            or status["proof_sha256"] != row.get("proof_digest_sha256")
            or status["cross_backend_canonical_equality"] is not row.get("proof_parity")
        ):
            raise DeltaError(f"{label} {lane} receipt proof status differs at row {index}")
        eligibility = measurement["eligibility_status"]
        if (
            eligibility["headline_eligible"] is not row.get("headline_eligible")
            or eligibility["stability_satisfied"]
            is not require_object(
                row.get("stability"), f"{label}.rows[{index}].stability"
            ).get("satisfied")
            or eligibility["evidence_class"] != lane_row.get("evidence_class")
            or eligibility["profiled"] is not lane_row.get("profiled")
        ):
            raise DeltaError(f"{label} {lane} receipt eligibility differs at row {index}")


def _formal_ready(configuration: dict[str, Any], rows: list[Any]) -> bool:
    return (
        configuration.get("formal") is True
        and all(row.get("headline_eligible") is True for row in rows)
        and all(
            isinstance(row.get("stability"), dict)
            and row["stability"].get("satisfied") is True
            for row in rows
        )
        and all(
            isinstance(row.get("rust_oracle"), dict)
            and row["rust_oracle"].get("verified") is True
            for row in rows
        )
    )


def product_identity_transition(
    baseline: dict[str, Any],
    current: dict[str, Any],
    protocols: tuple[object, object],
) -> dict[str, Any] | None:
    if protocols == (NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6):
        return {
            "kind": "explicit_historical_alias",
            "source_protocol": NATIVE_PROTOCOL_V5,
            "target_protocol": NATIVE_PROTOCOL_V6,
            "aliases": LEGACY_V5_PRODUCT_ALIASES,
            "semantic_timing_change": "none",
        }
    if protocols != (NATIVE_PROTOCOL_V6, NATIVE_PROTOCOL_V6):
        return None
    result: dict[str, Any] = {
        "kind": "canonical_focused_products",
        "products": {},
        "artifact_revisions": {},
    }
    for lane in ("cpu", "metal"):
        identities = []
        for report, label in ((baseline, "baseline"), (current, "current")):
            rows = require_list(report.get("rows"), f"{label}.rows")
            first = require_object(rows[0], f"{label}.rows[0]")
            lanes = require_object(first.get("lanes"), f"{label}.rows[0].lanes")
            lane_row = require_object(lanes.get(lane), f"{label}.rows[0].lanes.{lane}")
            try:
                identity = validate_product_identity(lane_row.get("product_identity"), lane)
            except ProductEvidenceError as error:
                raise DeltaError(f"{label} {lane} product identity is invalid: {error}") from error
            identities.append(identity)
        stable = comparable_identity(identities[0])
        if stable != comparable_identity(identities[1]):
            raise IncompatibleReports(
                f"native focused product configuration differs for lane {lane}"
            )
        result["products"][lane] = stable
        revisions = {
            label: revision_identity(identity)
            for label, identity in zip(
                ("baseline", "current"), identities, strict=True
            )
        }
        configurations = []
        for report, label in ((baseline, "baseline"), (current, "current")):
            configuration = require_object(
                report.get("configuration"), f"{label}.configuration"
            )
            binaries = require_object(
                configuration.get("binaries"), f"{label}.configuration.binaries"
            )
            binary = require_object(binaries.get(lane), f"{label}.binaries.{lane}")
            configurations.append(binary)
        artifact_changed = (
            revisions["baseline"]["runtime_artifacts"]
            != revisions["current"]["runtime_artifacts"]
            or revisions["baseline"]["aot_manifest"]
            != revisions["current"]["aot_manifest"]
        )
        source_fields = (
            "implementation_repository",
            "implementation_commit",
            "implementation_tree",
            "implementation_dirty",
            "dirty_content_sha256",
        )
        source_unchanged = all(
            revisions["baseline"][field] == revisions["current"][field]
            for field in source_fields
        )
        binary_unchanged = configurations[0].get("sha256") == configurations[1].get(
            "sha256"
        )
        if artifact_changed and source_unchanged and binary_unchanged:
            raise DeltaError(
                f"{lane} runtime artifacts changed without a source or executable revision"
            )
        result["artifact_revisions"][lane] = revisions
    return result


def product_receipt_revision(report: dict[str, Any]) -> dict[str, Any] | None:
    receipts = report.get("product_receipts")
    if not isinstance(receipts, dict):
        return None
    return {
        lane: {
            "receipt_sha256": receipt.get("receipt_sha256"),
            "product_identity_sha256": receipt.get("product_identity", {}).get(
                "identity_sha256"
            ),
            "executable_sha256": receipt.get("executable_sha256"),
        }
        for lane, receipt in sorted(receipts.items())
        if isinstance(receipt, dict)
    }
