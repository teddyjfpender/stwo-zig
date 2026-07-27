"""Archived producer-linked smoke profile parsers.

The executable fast profile is retired; these validators remain so historical
bundle fixtures can be inspected.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import contracts


PRODUCER_SCHEMA = "riscv-release-bundle-v3"
EXHAUSTIVE_SCHEMAS = {"riscv_cli_evidence_v1", "riscv_cli_evidence_v2"}
REQUIRED_COVERAGE = {
    "exhaustive_gate": "PASS",
    "cross_shard_cli_smoke": "PASS",
    "benchmark_cli_smoke": "PASS",
    "oracle_boundaries": "11/11",
}
PROOF_WIRE_MUTATIONS = {"trailing", "truncated", "length-bomb"}
HOSTILE_ARTIFACT_MUTATIONS = {
    "corrupt-json", "legacy-schema-v2", "duplicate-header", "unknown-field",
    "omitted-claim", "release-relabel",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require_file_entry(
    files: Mapping[str, Any], name: str, bundle: Path,
) -> tuple[Path, Mapping[str, Any]]:
    entry = files.get(name)
    if not isinstance(entry, dict):
        raise contracts.ContractError(f"producer receipt: missing file entry {name}")
    digest = contracts.require_sha256(entry.get("sha256"), f"producer receipt.files.{name}")
    size = entry.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise contracts.ContractError(f"producer receipt: invalid size for {name}")
    path = bundle / name
    if not path.is_file():
        raise contracts.ContractError(f"producer receipt: bundled file is missing: {name}")
    if path.stat().st_size != size or sha256_file(path) != digest:
        raise contracts.ContractError(f"producer receipt: bundled file drifted: {name}")
    return path, entry


def _require_failed_results(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise contracts.ContractError(f"producer receipt: {label} coverage is incomplete")
    if any(not isinstance(result, dict) or result.get("returncode") == 0
           for result in value.values()):
        raise contracts.ContractError(f"producer receipt: {label} contains an accepted mutation")


def validate_exhaustive_summary(
    summary: Mapping[str, Any], *, phase: str, candidate_commit: str,
    executable_sha256: str,
) -> None:
    """Require the prior producer to have run the checks omitted by fast mode."""
    if summary.get("schema") not in EXHAUSTIVE_SCHEMAS:
        raise contracts.ContractError("producer receipt: unknown exhaustive smoke schema")
    if summary.get("schema") == "riscv_cli_evidence_v2" and \
            summary.get("profile") != "exhaustive":
        raise contracts.ContractError("producer receipt: linked smoke was not exhaustive")
    expected_status = "not_release_gated" if phase == "candidate" else "release_gated"
    if summary.get("phase") != phase or summary.get("release_status") != expected_status:
        raise contracts.ContractError("producer receipt: exhaustive smoke phase drifted")
    if summary.get("implementation_commit") != candidate_commit or \
            summary.get("implementation_dirty") is not False:
        raise contracts.ContractError("producer receipt: exhaustive smoke source identity drifted")
    if summary.get("executable_sha256") != executable_sha256:
        raise contracts.ContractError("producer receipt: exhaustive smoke executable drifted")
    if summary.get("total_steps") != 131_078:
        raise contracts.ContractError("producer receipt: exhaustive smoke is not cross-shard")
    if summary.get("independent_verify_returncode") != 0:
        raise contracts.ContractError("producer receipt: exhaustive proof was not independently verified")
    if summary.get("tamper_returncode") in (None, 0):
        raise contracts.ContractError("producer receipt: exhaustive statement tamper was accepted")
    if summary.get("benchmark_verify_receipt_sha256") is None:
        raise contracts.ContractError("producer receipt: exhaustive benchmark verification is missing")
    for field in (
        "artifact_sha256", "report_sha256", "benchmark_report_sha256",
        "benchmark_artifact_sha256", "verify_receipt_sha256",
        "benchmark_verify_receipt_sha256",
    ):
        contracts.require_sha256(summary.get(field), f"producer receipt.summary.{field}")
    _require_failed_results(
        summary.get("proof_wire_mutation_returncodes"),
        PROOF_WIRE_MUTATIONS,
        "proof-wire mutation",
    )
    _require_failed_results(
        summary.get("hostile_artifact_results"),
        HOSTILE_ARTIFACT_MUTATIONS,
        "hostile-artifact mutation",
    )
    boundary = summary.get("boundary_rejection_results")
    if not isinstance(boundary, dict) or not boundary:
        raise contracts.ContractError("producer receipt: exhaustive boundary matrix is missing")


def validate_producer_receipt(
    receipt_path: Path, cli: Path, *, phase: str, candidate_commit: str,
    implementation_dirty: bool,
) -> dict[str, object]:
    """Authenticate a prebuilt CLI and exhaustive evidence for a fast smoke."""
    if implementation_dirty:
        raise contracts.ContractError("fast profile requires a clean checkout")
    receipt_path = receipt_path.resolve()
    try:
        receipt = contracts.strict_json_object(
            receipt_path.read_text(encoding="utf-8"), "producer receipt",
        )
    except OSError as error:
        raise contracts.ContractError(f"producer receipt: cannot read manifest: {error}") from error
    if receipt.get("schema") != PRODUCER_SCHEMA:
        raise contracts.ContractError("producer receipt: unknown schema")
    if receipt.get("phase") != phase or receipt.get("candidate_commit") != candidate_commit:
        raise contracts.ContractError("producer receipt: phase or candidate drifted")
    if receipt.get("coverage") != REQUIRED_COVERAGE:
        raise contracts.ContractError("producer receipt: exhaustive coverage is not exact")
    producer = receipt.get("producer")
    if not isinstance(producer, dict) or not producer:
        raise contracts.ContractError("producer receipt: GitHub producer identity is missing")
    release_policy = receipt.get("release_policy")
    if not isinstance(release_policy, dict) or \
            release_policy.get("schema") != "riscv-release-policy-match-v1" or \
            release_policy.get("candidate_commit") != candidate_commit:
        raise contracts.ContractError("producer receipt: trusted release policy is missing")
    domains = receipt.get("domains")
    if not isinstance(domains, dict) or not domains:
        raise contracts.ContractError("producer receipt: content domains are missing")
    files = receipt.get("files")
    if not isinstance(files, dict):
        raise contracts.ContractError("producer receipt: file manifest is missing")
    bundle = receipt_path.parent
    bundled_cli, cli_entry = _require_file_entry(files, "bin/stwo-zig", bundle)
    summary_path, summary_entry = _require_file_entry(files, "cli/summary.json", bundle)
    if bundled_cli.resolve() != cli.resolve():
        raise contracts.ContractError("producer receipt: --cli is not the bundled executable")
    executable_sha256 = str(cli_entry["sha256"])
    summary = contracts.strict_json_object(
        summary_path.read_text(encoding="utf-8"), "producer exhaustive summary",
    )
    validate_exhaustive_summary(
        summary,
        phase=phase,
        candidate_commit=candidate_commit,
        executable_sha256=executable_sha256,
    )
    return {
        "schema": PRODUCER_SCHEMA,
        "manifest_path": str(receipt_path),
        "manifest_sha256": sha256_file(receipt_path),
        "phase": phase,
        "candidate_commit": candidate_commit,
        "coverage": dict(REQUIRED_COVERAGE),
        "producer_sha256": canonical_sha256(producer),
        "release_policy_sha256": canonical_sha256(release_policy),
        "domains_sha256": canonical_sha256(domains),
        "executable": dict(cli_entry),
        "exhaustive_summary": {
            **dict(summary_entry),
            "schema": summary["schema"],
        },
    }
