"""Generate a bounded diagnostic microbenchmark schedule from replayed evidence."""

from __future__ import annotations

import argparse
import copy
from fractions import Fraction
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_incremental_profile_v2_evidence as profile_evidence  # noqa: E402
import ethereum_block_provider_hpc_evidence as zig_support  # noqa: E402
import ethereum_block_provider_raw_batch_evidence as batch_evidence  # noqa: E402
import ethereum_block_provider_raw_pair_evidence as pair_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.optimization-microbenchmark-schedule.v2"
MAX_TASK_SECONDS = 60
FORBIDDEN_ARG_TOKENS = (
    "--proof", "full-proof", "full_block_proof", "block-proof-controller",
    "ethereum-block-leaf-producer", "parent-produce", "aggregate-proof",
    "recursive-prove",
)


class MicrobenchmarkScheduleError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MicrobenchmarkScheduleError(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    path = Path(value["path"])
    _require(path.is_absolute() and value == _identity(path, where),
             f"{where} identity differs")
    return value


def _impact(numerator: int, denominator: int) -> dict[str, int]:
    _require(type(numerator) is int and type(denominator) is int
             and 0 < numerator < denominator,
             "microbenchmark scheduling impact differs")
    return {
        "numerator": numerator,
        "denominator": denominator,
        "millionths": numerator * 1_000_000 // denominator,
    }


def _opportunity_model(
    profile_value: dict[str, Any], batch_value: dict[str, Any],
) -> dict[str, Any]:
    models = profile_value["models"]
    measured = batch_value["measured"]
    geometry = Fraction(
        models["changed_only_combined_main_cells"],
        models["fixed_legacy_main_cells"],
    )
    concurrency = Fraction(
        measured["proof_batch_concurrent_wall_ns"],
        measured["proof_batch_serial_wall_ns"],
    )
    combined = geometry * concurrency
    return {
        "schema": "stwo.ethereum.optimization-stage-opportunity-model.v1",
        "status": "conditional-provider-stage-upper-bound-only",
        "stage": "provider-base-proof-stage",
        "composition_rule": "multiply-independent-dimensionless-stage-factors",
        "factors": [
            {
                "kind": "exact-work-volume-cell-ratio",
                "scope": "changed-only-d6-poseidon-plus-bridge-vs-fixed-445",
                "numerator": geometry.numerator,
                "denominator": geometry.denominator,
                "measurement_class": "exact-artifact-derived-geometry",
            },
            {
                "kind": "measured-fixed-work-batch-wall-ratio",
                "scope": "n4-log16-provider-proof-batch",
                "numerator": concurrency.numerator,
                "denominator": concurrency.denominator,
                "measurement_class": "measured-stage-local-wall",
            },
        ],
        "independence": {
            "dimensions": ["provider-work-volume", "provider-job-concurrency"],
            "assumption": (
                "concurrency-efficiency-remains-constant-after-work-volume-and-"
                "proof-shape-change"
            ),
            "production_validated": False,
        },
        "conditional_remaining_provider_stage_fraction": {
            "numerator": combined.numerator,
            "denominator": combined.denominator,
        },
        "conditional_reduction_millionths": (
            (combined.denominator - combined.numerator) * 1_000_000
            // combined.denominator
        ),
        "measured_provider_stage_combination": False,
        "measured_end_to_end_wall_ns": None,
        "modeled_end_to_end_wall_ns": None,
        "proof_complete": None,
        "fresh_verification": None,
        "production_promotion_eligible": False,
    }


def _safe_argv(argv: list[str], expected: list[str], where: str) -> None:
    _require(argv == expected and argv
             and all(type(argument) is str and argument for argument in argv),
             f"{where} argv differs")
    normalized = "\n".join(argv).lower()
    _require(not any(token in normalized for token in FORBIDDEN_ARG_TOKENS),
             f"{where} contains a forbidden full-proof command")


def _profile_lead(path: Path, run_root: Path) -> dict[str, Any]:
    path = path.absolute()
    value = profile_evidence.load(path)
    models = value["models"]
    reduction = models["main_cell_reduction"]
    task_root = run_root / "task-001-incremental-profile-v2"
    adapter = BENCHMARK_DIR / "ethereum_block_incremental_profile_v2_evidence.py"
    tape_directory = Path(value["tapes"][0]["path"]).parent
    argv = [
        str(Path(sys.executable).resolve()), str(adapter.absolute()), "capture",
        "--tool", value["tool"]["path"],
        "--tool-source", value["tool_source"]["path"],
        "--tape-directory", str(tape_directory),
        "--segment-count", str(value["aggregate"]["segment_count"]),
        "--timeout-seconds", str(MAX_TASK_SECONDS),
        "--output", str(task_root / "evidence.json"),
        "--staging-directory", str(task_root / "staging"),
    ]
    return {
        "candidate_id": "incremental-memory-changed-only-v2",
        "family": "memory-commitment",
        "scope": "exact-committed-cell-geometry-profiler",
        "source_evidence": _identity(path, "incremental profile V2 evidence"),
        "source_content_sha256": value["content_sha256"],
        "correctness_boundary": {
            "canonical_source_artifacts_replayed": True,
            "proof_correctness": None,
            "fresh_verification": None,
        },
        "impact": {
            "kind": "exact-main-cell-reduction",
            **_impact(reduction["numerator"], reduction["denominator"]),
        },
        "measurement": {
            "source_wall_ns": value["process"]["timing"]["wall_ns"],
            "source_peak_rss_bytes": value["process"][
                "maximum_resident_set_bytes"
            ],
            "estimated_end_to_end_wall_ns": None,
        },
        "execution": {
            "mode": "typed-diagnostic-capture",
            "timeout_seconds": MAX_TASK_SECONDS,
            "launcher": _identity(Path(sys.executable).resolve(), "Python launcher"),
            "adapter": _identity(adapter, "incremental profile V2 adapter"),
            "argv": argv,
            "new_measurement_expected": True,
            "full_proof_forbidden": True,
        },
        "production_promotion_eligible": False,
    }


def _batch_lead(path: Path, run_root: Path) -> dict[str, Any]:
    path = path.absolute()
    value = batch_evidence.load(path)
    measured = value["measured"]
    serial = measured["proof_batch_serial_wall_ns"]
    concurrent = measured["proof_batch_concurrent_wall_ns"]
    adapter = BENCHMARK_DIR / "ethereum_block_provider_raw_batch_evidence.py"
    argv = [
        str(Path(sys.executable).resolve()), str(adapter.absolute()), "replay",
        "--evidence", str(path),
    ]
    return {
        "candidate_id": "provider-raw-batch-concurrency-v2",
        "family": "poseidon-provider",
        "scope": "measured-n-shard-proof-batch-only",
        "source_evidence": _identity(path, "provider raw-batch evidence"),
        "source_content_sha256": value["content_sha256"],
        "correctness_boundary": {
            "canonical_source_artifacts_replayed": True,
            "proof_correctness": True,
            "fresh_verification": True,
        },
        "impact": {
            "kind": "measured-proof-batch-wall-reduction",
            **_impact(serial - concurrent, serial),
        },
        "measurement": {
            "source_wall_ns": measured["typed_total_wall_ns"],
            "source_peak_rss_bytes": measured["peak_physical_footprint_bytes"],
            "estimated_end_to_end_wall_ns": None,
        },
        "execution": {
            "mode": "typed-evidence-replay-only",
            "timeout_seconds": MAX_TASK_SECONDS,
            "launcher": _identity(Path(sys.executable).resolve(), "Python launcher"),
            "adapter": _identity(adapter, "provider raw-batch adapter"),
            "argv": argv,
            "new_measurement_expected": False,
            "unavailable_reason": "producer-argv-was-not-retained",
            "full_proof_forbidden": True,
        },
        "production_promotion_eligible": False,
    }


def _excluded(path: Path) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, "excluded diagnostic", maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and type(value.get("schema")) is str,
             "excluded diagnostic schema differs")
    schema = value["schema"]
    if schema == pair_evidence.RECEIPT_SCHEMA:
        try:
            pair_evidence.provider_support._read_zig(
                path, schema, "excluded provider raw-pair receipt",
            )
        except pair_evidence.provider_support.ProviderHpcEvidenceError as error:
            raise MicrobenchmarkScheduleError(str(error)) from error
        reason = "executable-custody-overwritten-no-immutable-copy"
    elif schema == "stwo.riscv.keccak-adaptive-corpus-projection.v1":
        _require("content_sha256" not in value
                 and value.get("production_active") is False
                 and value.get("proof_or_fresh_verification") is False,
                 "excluded Keccak projection boundary differs")
        reason = "digest-only-source-authorities-and-no-content-seal"
    else:
        raise MicrobenchmarkScheduleError("excluded diagnostic schema differs")
    return {
        "identity": _identity(path, "excluded diagnostic"),
        "schema": schema,
        "reason": reason,
        "ranked": False,
        "production_promotion_eligible": False,
    }


def _expected_argv(lead: dict[str, Any], run_root: Path) -> list[str]:
    evidence_path = Path(lead["source_evidence"]["path"])
    if lead["candidate_id"] == "incremental-memory-changed-only-v2":
        value = profile_evidence.load(evidence_path)
        task_root = run_root / "task-001-incremental-profile-v2"
        adapter = BENCHMARK_DIR / "ethereum_block_incremental_profile_v2_evidence.py"
        return [
            str(Path(sys.executable).resolve()), str(adapter.absolute()), "capture",
            "--tool", value["tool"]["path"],
            "--tool-source", value["tool_source"]["path"],
            "--tape-directory", str(Path(value["tapes"][0]["path"]).parent),
            "--segment-count", str(value["aggregate"]["segment_count"]),
            "--timeout-seconds", str(MAX_TASK_SECONDS),
            "--output", str(task_root / "evidence.json"),
            "--staging-directory", str(task_root / "staging"),
        ]
    _require(lead["candidate_id"] == "provider-raw-batch-concurrency-v2",
             "microbenchmark candidate differs")
    adapter = BENCHMARK_DIR / "ethereum_block_provider_raw_batch_evidence.py"
    return [
        str(Path(sys.executable).resolve()), str(adapter.absolute()), "replay",
        "--evidence", str(evidence_path),
    ]


def build(
    profile_path: Path, batch_path: Path, run_root: Path,
    excluded_paths: list[Path] | None = None,
) -> dict[str, Any]:
    run_root = run_root.absolute()
    profile_path = profile_path.absolute()
    batch_path = batch_path.absolute()
    profile_value = profile_evidence.load(profile_path)
    batch_value = batch_evidence.load(batch_path)
    leads = [
        _profile_lead(profile_path, run_root),
        _batch_lead(batch_path, run_root),
    ]
    leads.sort(key=lambda value: (
        -value["impact"]["millionths"], value["candidate_id"],
    ))
    for index, lead in enumerate(leads, 1):
        lead["schedule_rank"] = index
    return protocol.seal({
        "schema": SCHEMA,
        "status": "bounded-diagnostic-microbenchmark-schedule",
        "run_root": str(run_root),
        "policy": {
            "maximum_task_seconds": MAX_TASK_SECONDS,
            "ranked_only_from_replayed_typed_diagnostics": True,
            "ranking_basis": (
                "within-scope-relative-reduction-for-scheduling-only;"
                "not-a-cross-scope-or-end-to-end-speedup"
            ),
            "full_proof_commands_forbidden": True,
            "whole_block_or_recursive_work_forbidden": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
        "ranked_leads": leads,
        "opportunity_model": _opportunity_model(profile_value, batch_value),
        "excluded_inputs": [
            _excluded(path) for path in (excluded_paths or [])
        ],
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "run_root", "policy", "ranked_leads",
        "opportunity_model", "excluded_inputs", "content_sha256",
    }, "microbenchmark schedule keys differ")
    _require(value["schema"] == SCHEMA
             and value["status"] == "bounded-diagnostic-microbenchmark-schedule"
             and value["content_sha256"] == protocol.content_sha256(value),
             "microbenchmark schedule authority differs")
    run_root = Path(value["run_root"])
    _require(run_root.is_absolute(), "microbenchmark schedule run root differs")
    policy = value["policy"]
    _require(policy == {
        "maximum_task_seconds": MAX_TASK_SECONDS,
        "ranked_only_from_replayed_typed_diagnostics": True,
        "ranking_basis": (
            "within-scope-relative-reduction-for-scheduling-only;"
            "not-a-cross-scope-or-end-to-end-speedup"
        ),
        "full_proof_commands_forbidden": True,
        "whole_block_or_recursive_work_forbidden": True,
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    }, "microbenchmark schedule policy differs")
    leads = value["ranked_leads"]
    _require(type(leads) is list and len(leads) == 2,
             "microbenchmark schedule lead count differs")
    paths: dict[str, Path] = {}
    for index, lead in enumerate(leads, 1):
        _require(type(lead) is dict and lead.get("schedule_rank") == index
                 and lead.get("production_promotion_eligible") is False,
                 f"microbenchmark schedule lead {index} differs")
        identity = _validate_identity(
            lead["source_evidence"], f"microbenchmark lead {index} evidence",
        )
        paths[lead["candidate_id"]] = Path(identity["path"])
        execution = lead["execution"]
        _require(type(execution) is dict
                 and execution["timeout_seconds"] == MAX_TASK_SECONDS
                 and execution["full_proof_forbidden"] is True,
                 f"microbenchmark lead {index} execution differs")
        _validate_identity(execution["launcher"], "microbenchmark launcher")
        _validate_identity(execution["adapter"], "microbenchmark adapter")
        _safe_argv(
            execution["argv"], _expected_argv(lead, run_root),
            f"microbenchmark lead {index}",
        )
    _require(set(paths) == {
        "incremental-memory-changed-only-v2",
        "provider-raw-batch-concurrency-v2",
    }, "microbenchmark schedule candidates differ")
    profile_value = profile_evidence.load(
        paths["incremental-memory-changed-only-v2"]
    )
    batch_value = batch_evidence.load(paths["provider-raw-batch-concurrency-v2"])
    _require(value["opportunity_model"]
             == _opportunity_model(profile_value, batch_value),
             "microbenchmark opportunity model differs")
    expected = build(
        paths["incremental-memory-changed-only-v2"],
        paths["provider-raw-batch-concurrency-v2"],
        run_root,
        [Path(item["identity"]["path"]) for item in value["excluded_inputs"]],
    )
    _require(value == expected, "microbenchmark schedule replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "microbenchmark schedule", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "microbenchmark schedule is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--incremental-profile", type=Path, required=True)
    create.add_argument("--provider-batch", type=Path, required=True)
    create.add_argument("--excluded", type=Path, action="append", default=[])
    create.add_argument("--run-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--schedule", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.schedule)
            return 0
        value = build(
            arguments.incremental_profile, arguments.provider_batch,
            arguments.run_root, arguments.excluded,
        )
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "microbenchmark schedule parent")
        store.require_directory(staging, "microbenchmark schedule staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        MicrobenchmarkScheduleError,
        profile_evidence.IncrementalProfileV2EvidenceError,
        batch_evidence.ProviderRawBatchEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
