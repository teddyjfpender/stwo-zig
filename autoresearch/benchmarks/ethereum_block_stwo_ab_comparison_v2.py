#!/usr/bin/env python3
"""Strict, program-aware Stwo baseline/candidate comparison contract.

The benchmark statement is shared by both arms.  The proved root statement and
the VM final state are program-bound and are therefore validated per arm rather
than required to be byte-identical across different guest executables.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


TRIAL_SCHEMA = "stwo.ethereum.block-stwo-ab-trial.v2"
COMPARISON_SCHEMA = "stwo.ethereum.block-stwo-ab-comparison.v2"
ARMS = ("baseline", "candidate")
STAGES = (
    "execution",
    "witness_generation",
    "proving",
    "proof_serialization",
    "fresh_verification",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
SEMANTIC_STATEMENT_SCHEMA = "stwo.ethereum.block-semantic-statement.v1"


class StwoComparisonV2Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StwoComparisonV2Error(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value) is not None,
             f"{where} differs")
    return value


def _positive(value: Any, where: str) -> int:
    _require(type(value) is int and value > 0, f"{where} differs")
    return value


def _nonnegative(value: Any, where: str) -> int:
    _require(type(value) is int and value >= 0, f"{where} differs")
    return value


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    for field in value:
        _nonnegative(value[field], f"{where}.{field}")
    return value


def _identity(value: Any, where: str, *, reopen: bool) -> dict[str, Any]:
    value = _exact(value, {"path", "bytes", "sha256"}, where)
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where}.path differs")
    _positive(value["bytes"], f"{where}.bytes")
    _sha(value["sha256"], f"{where}.sha256")
    if reopen:
        store.validate_file_identity(
            Path(value["path"]),
            {"bytes": value["bytes"], "sha256": value["sha256"]},
            where,
        )
    return value


def _transport(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"bytes", "sha256", "framing"}, where)
    _positive(value["bytes"], f"{where}.bytes")
    _sha(value["sha256"], f"{where}.sha256")
    _require(type(value["framing"]) is str and value["framing"],
             f"{where}.framing differs")
    return value


def _source(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"commit", "tree", "dirty", "dirty_content_sha256"}, where)
    _require(type(value["commit"]) is str and GIT_ID.fullmatch(value["commit"])
             and type(value["tree"]) is str and GIT_ID.fullmatch(value["tree"])
             and type(value["dirty"]) is bool,
             f"{where} differs")
    if value["dirty"]:
        _sha(value["dirty_content_sha256"], f"{where}.dirty_content_sha256")
    else:
        _require(value["dirty_content_sha256"] is None,
                 f"{where} clean source carries dirty identity")
    return value


def semantic_statement_sha256(benchmark: dict[str, Any]) -> str:
    """Hash the common Stwo semantic statement, excluding filesystem paths."""
    input_identity = benchmark["input"]
    statement = {
        "schema": SEMANTIC_STATEMENT_SCHEMA,
        "chain_id": benchmark["chain_id"],
        "block_number": benchmark["block_number"],
        "block_hash": benchmark["block_hash"],
        "block_state_root": benchmark["block_state_root"],
        "input": {
            "bytes": input_identity["bytes"],
            "sha256": input_identity["sha256"],
            "framing": benchmark["input_framing"],
        },
        "expected_output": benchmark["expected_output"],
    }
    return hashlib.sha256(protocol.canonical_bytes(statement)).hexdigest()


def _benchmark(value: Any, *, reopen: bool) -> dict[str, Any]:
    value = _exact(value, {
        "chain_id", "block_number", "block_hash", "block_state_root", "input",
        "input_framing", "expected_output", "benchmark_statement_sha256",
        "security_identity_sha256", "minimum_security_bits",
    }, "Stwo A/B v2 benchmark")
    _positive(value["chain_id"], "Stwo A/B v2 chain id")
    _positive(value["block_number"], "Stwo A/B v2 block number")
    for field in ("block_hash", "block_state_root", "benchmark_statement_sha256",
                  "security_identity_sha256"):
        _sha(value[field], f"Stwo A/B v2 benchmark {field}")
    _identity(value["input"], "Stwo A/B v2 input", reopen=reopen)
    _require(type(value["input_framing"]) is str and value["input_framing"],
             "Stwo A/B v2 input framing differs")
    _transport(value["expected_output"], "Stwo A/B v2 expected output")
    _positive(value["minimum_security_bits"], "Stwo A/B v2 minimum security bits")
    _require(value["benchmark_statement_sha256"] == semantic_statement_sha256(value),
             "Stwo A/B v2 semantic statement digest differs")
    return value


def _arm_binding(value: Any, where: str, *, reopen: bool) -> dict[str, Any]:
    value = _exact(value, {
        "guest_elf", "source_request", "source_request_sha256",
        "declared_program_root_sha256", "proved_root_statement_sha256",
        "vm_final_state_sha256",
    }, where)
    _identity(value["guest_elf"], f"{where}.guest_elf", reopen=reopen)
    source_request = _identity(
        value["source_request"], f"{where}.source_request", reopen=reopen,
    )
    _require(value["source_request_sha256"] == source_request["sha256"],
             f"{where}.source_request_sha256 differs")
    for field in ("declared_program_root_sha256", "proved_root_statement_sha256",
                  "vm_final_state_sha256"):
        _sha(value[field], f"{where}.{field}")
    return value


def _subject(value: Any, where: str, *, reopen: bool) -> dict[str, Any]:
    value = _exact(value, {
        "source", "product_executable", "verifier_executable", "build_mode",
        "feature_flags", "production_admitted", "process_count", "thread_count",
        "engine_workers", "provider_topology", "coefficient_retention",
    }, where)
    _source(value["source"], f"{where}.source")
    _identity(value["product_executable"], f"{where}.product_executable", reopen=reopen)
    _identity(value["verifier_executable"], f"{where}.verifier_executable", reopen=reopen)
    _require(value["build_mode"] == "ReleaseFast"
             and type(value["production_admitted"]) is bool,
             f"{where} mode differs")
    flags = value["feature_flags"]
    _require(type(flags) is list and flags == sorted(set(flags))
             and all(type(item) is str and item for item in flags),
             f"{where}.feature_flags differ")
    for field in ("process_count", "thread_count", "engine_workers"):
        _positive(value[field], f"{where}.{field}")
    _require(type(value["provider_topology"]) is str and value["provider_topology"]
             and value["coefficient_retention"] in ("always", "never"),
             f"{where} provider configuration differs")
    return value


def _host(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "machine_model", "cpu_model", "cpu_logical_cores", "memory_bytes",
        "operating_system", "power_source", "power_mode", "thermal_state",
        "performance_warning", "interference_observed",
    }, "Stwo A/B v2 host")
    for field in ("machine_model", "cpu_model", "operating_system", "power_source",
                  "power_mode", "thermal_state"):
        _require(type(value[field]) is str and value[field],
                 f"Stwo A/B v2 host {field} differs")
    _positive(value["cpu_logical_cores"], "Stwo A/B v2 logical cores")
    _positive(value["memory_bytes"], "Stwo A/B v2 memory")
    for field in ("performance_warning", "interference_observed"):
        _require(type(value[field]) is bool, f"Stwo A/B v2 host {field} differs")
    return value


def _regime(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "session_sha256", "pair_position", "cold_process_start",
        "cold_artifact_cache", "cold_proof_cache", "timing_scope",
    }, "Stwo A/B v2 trial regime")
    _sha(value["session_sha256"], "Stwo A/B v2 session")
    _require(type(value["pair_position"]) is int and value["pair_position"] in (0, 1),
             "Stwo A/B v2 pair position differs")
    for field in ("cold_process_start", "cold_artifact_cache", "cold_proof_cache"):
        _require(type(value[field]) is bool, f"Stwo A/B v2 regime {field} differs")
    _require(value["timing_scope"] == "process-launch-through-cold-fresh-verification",
             "Stwo A/B v2 timing scope differs")
    return value


def _resource_budget(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "cpu_logical_cores_available", "max_processes", "max_threads",
        "max_engine_workers", "memory_limit_bytes", "hard_timeout_seconds",
    }, "Stwo A/B v2 resource budget")
    for field in value:
        _positive(value[field], f"Stwo A/B v2 resource budget {field}")
    return value


def _proof(value: Any, where: str, *, reopen: bool) -> dict[str, Any]:
    value = _exact(value, {
        "artifact", "proved_root_statement_sha256", "root_sha256",
        "security_identity_sha256", "conservative_security_bits", "codec",
        "fresh_verification_receipt", "fresh_verified", "independent_verifier",
    }, where)
    _identity(value["artifact"], f"{where}.artifact", reopen=reopen)
    for field in ("proved_root_statement_sha256", "root_sha256",
                  "security_identity_sha256"):
        _sha(value[field], f"{where}.{field}")
    _positive(value["conservative_security_bits"], f"{where}.security bits")
    codec = _exact(value["codec"], {
        "framing", "canonical_decode", "roundtrip_exact",
    }, f"{where}.codec")
    _require(type(codec["framing"]) is str and codec["framing"]
             and type(codec["canonical_decode"]) is bool
             and type(codec["roundtrip_exact"]) is bool,
             f"{where}.codec differs")
    _identity(value["fresh_verification_receipt"],
              f"{where}.fresh_verification_receipt", reopen=reopen)
    _require(type(value["fresh_verified"]) is bool
             and type(value["independent_verifier"]) is bool,
             f"{where} verification verdict differs")
    return value


def _correctness(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "semantic_output", "block_state_root", "benchmark_statement_sha256",
        "vm_final_state_sha256", "expected_output_matched", "block_state_matched",
        "benchmark_statement_matched", "arm_binding_matched",
    }, where)
    _transport(value["semantic_output"], f"{where}.semantic_output")
    for field in ("block_state_root", "benchmark_statement_sha256",
                  "vm_final_state_sha256"):
        _sha(value[field], f"{where}.{field}")
    for field in ("expected_output_matched", "block_state_matched",
                  "benchmark_statement_matched", "arm_binding_matched"):
        _require(type(value[field]) is bool, f"{where}.{field} differs")
    return value


def validate_trial(value: Any, *, reopen: bool = True) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "arm", "status", "benchmark", "arm_binding", "subject", "host",
        "trial_regime", "resource_budget", "stages", "total", "peak_rss_bytes",
        "proof", "correctness", "attempt_custody", "eligible", "content_sha256",
    }, "Stwo A/B v2 trial")
    _require(value["schema"] == TRIAL_SCHEMA and value["arm"] in ARMS
             and value["status"] == "cold-fresh-verified-complete",
             "Stwo A/B v2 trial header differs")
    _require(value["content_sha256"] == protocol.content_sha256(value),
             "Stwo A/B v2 trial seal differs")

    benchmark = _benchmark(value["benchmark"], reopen=reopen)
    binding = _arm_binding(
        value["arm_binding"], "Stwo A/B v2 arm binding", reopen=reopen,
    )
    subject = _subject(value["subject"], "Stwo A/B v2 subject", reopen=reopen)
    host = _host(value["host"])
    regime = _regime(value["trial_regime"])
    budget = _resource_budget(value["resource_budget"])
    _require(subject["process_count"] <= budget["max_processes"]
             and subject["thread_count"] <= budget["max_threads"]
             and subject["engine_workers"] <= budget["max_engine_workers"]
             and host["cpu_logical_cores"] == budget["cpu_logical_cores_available"]
             and host["memory_bytes"] <= budget["memory_limit_bytes"],
             "Stwo A/B v2 subject exceeds the resource budget")

    stages = _exact(value["stages"], set(STAGES), "Stwo A/B v2 stages")
    for stage in STAGES:
        _timing(stages[stage], f"Stwo A/B v2 {stage}")
    total = _exact(value["total"], {
        "wall_ns", "user_ns", "system_ns", "measured_stage_wall_ns",
        "unattributed_wall_ns",
    }, "Stwo A/B v2 total")
    for field in total:
        _nonnegative(total[field], f"Stwo A/B v2 total {field}")
    measured_stage_wall = sum(stages[stage]["wall_ns"] for stage in STAGES)
    _require(total["wall_ns"] > 0
             and total["measured_stage_wall_ns"] == measured_stage_wall
             and total["wall_ns"] == measured_stage_wall + total["unattributed_wall_ns"],
             "Stwo A/B v2 total wall does not reconcile")
    _positive(value["peak_rss_bytes"], "Stwo A/B v2 peak RSS")

    proof = _proof(value["proof"], "Stwo A/B v2 proof", reopen=reopen)
    correctness = _correctness(value["correctness"], "Stwo A/B v2 correctness")
    attempts = _exact(value["attempt_custody"], {
        "attempt_count", "successful_attempt_index", "failed_count",
        "indeterminate_count", "terminal_error",
    }, "Stwo A/B v2 attempts")
    _require(all(type(attempts[field]) is int and attempts[field] >= 0 for field in (
        "attempt_count", "successful_attempt_index", "failed_count",
        "indeterminate_count",
    )) and (attempts["terminal_error"] is None
            or type(attempts["terminal_error"]) is str),
             "Stwo A/B v2 attempt custody differs")

    expected_attempts = {
        "attempt_count": 1,
        "successful_attempt_index": 0,
        "failed_count": 0,
        "indeterminate_count": 0,
        "terminal_error": None,
    }
    expected_eligible = (
        subject["production_admitted"] is True
        and host["thermal_state"] == "nominal"
        and host["performance_warning"] is False
        and host["interference_observed"] is False
        and regime["cold_process_start"] is True
        and regime["cold_artifact_cache"] is True
        and regime["cold_proof_cache"] is True
        and proof["proved_root_statement_sha256"]
        == binding["proved_root_statement_sha256"]
        and proof["security_identity_sha256"]
        == benchmark["security_identity_sha256"]
        and proof["conservative_security_bits"] >= benchmark["minimum_security_bits"]
        and proof["codec"]["canonical_decode"] is True
        and proof["codec"]["roundtrip_exact"] is True
        and proof["fresh_verified"] is True
        and proof["independent_verifier"] is True
        and correctness["semantic_output"] == benchmark["expected_output"]
        and correctness["block_state_root"] == benchmark["block_state_root"]
        and correctness["benchmark_statement_sha256"]
        == benchmark["benchmark_statement_sha256"]
        and correctness["vm_final_state_sha256"] == binding["vm_final_state_sha256"]
        and correctness["expected_output_matched"] is True
        and correctness["block_state_matched"] is True
        and correctness["benchmark_statement_matched"] is True
        and correctness["arm_binding_matched"] is True
        and attempts == expected_attempts
    )
    _require(type(value["eligible"]) is bool and value["eligible"] is expected_eligible,
             "Stwo A/B v2 trial eligibility differs")
    return value


def _trial_identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def load_trial(path: Path) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, "Stwo A/B v2 trial", maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(raw == protocol.canonical_bytes(value),
             "Stwo A/B v2 trial is not canonical JSON")
    return validate_trial(value, reopen=True)


def _metric(baseline: int, candidate: int) -> dict[str, Any]:
    _positive(baseline, "Stwo A/B v2 baseline metric")
    _positive(candidate, "Stwo A/B v2 candidate metric")
    return {
        "baseline": baseline,
        "candidate": candidate,
        "speedup": {"numerator": baseline, "denominator": candidate},
        "reduction_ppm": ((baseline - candidate) * 1_000_000) // baseline,
        "target_95_percent_met": candidate * 20 <= baseline,
    }


def build_comparison(baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    baseline = load_trial(baseline_path)
    candidate = load_trial(candidate_path)
    _require(baseline["arm"] == "baseline" and candidate["arm"] == "candidate",
             "Stwo A/B v2 arm order differs")
    _require(baseline["eligible"] is True and candidate["eligible"] is True,
             "Stwo A/B v2 comparison requires two eligible trials")
    _require(baseline["benchmark"] == candidate["benchmark"],
             "Stwo A/B v2 benchmark authorities differ")
    _require(baseline["host"] == candidate["host"], "Stwo A/B v2 hosts differ")
    _require(baseline["resource_budget"] == candidate["resource_budget"],
             "Stwo A/B v2 resource budgets differ")
    baseline_regime = baseline["trial_regime"]
    candidate_regime = candidate["trial_regime"]
    for field in (
        "session_sha256", "cold_process_start", "cold_artifact_cache",
        "cold_proof_cache", "timing_scope",
    ):
        _require(baseline_regime[field] == candidate_regime[field],
                 f"Stwo A/B v2 trial regime {field} differs")
    _require({baseline_regime["pair_position"], candidate_regime["pair_position"]}
             == {0, 1}, "Stwo A/B v2 pair positions differ")
    _require(baseline["correctness"]["semantic_output"]
             == candidate["correctness"]["semantic_output"]
             and baseline["correctness"]["block_state_root"]
             == candidate["correctness"]["block_state_root"]
             and baseline["correctness"]["benchmark_statement_sha256"]
             == candidate["correctness"]["benchmark_statement_sha256"],
             "Stwo A/B v2 semantic correctness differs")

    metrics = {
        stage: _metric(
            baseline["stages"][stage]["wall_ns"],
            candidate["stages"][stage]["wall_ns"],
        ) for stage in STAGES
    }
    metrics["total_wall"] = _metric(
        baseline["total"]["wall_ns"], candidate["total"]["wall_ns"],
    )
    metrics["peak_rss"] = _metric(
        baseline["peak_rss_bytes"], candidate["peak_rss_bytes"],
    )
    metrics["proof_bytes"] = _metric(
        baseline["proof"]["artifact"]["bytes"],
        candidate["proof"]["artifact"]["bytes"],
    )
    return protocol.seal({
        "schema": COMPARISON_SCHEMA,
        "status": "apples-to-apples-complete",
        "baseline_trial": _trial_identity(baseline_path, "Stwo A/B v2 baseline trial"),
        "candidate_trial": _trial_identity(candidate_path, "Stwo A/B v2 candidate trial"),
        "benchmark": copy.deepcopy(baseline["benchmark"]),
        "host": copy.deepcopy(baseline["host"]),
        "trial_regime": {
            "session_sha256": baseline_regime["session_sha256"],
            "baseline_pair_position": baseline_regime["pair_position"],
            "candidate_pair_position": candidate_regime["pair_position"],
            "cold_process_start": True,
            "cold_artifact_cache": True,
            "cold_proof_cache": True,
            "timing_scope": baseline_regime["timing_scope"],
        },
        "resource_budget": copy.deepcopy(baseline["resource_budget"]),
        "baseline_subject": copy.deepcopy(baseline["subject"]),
        "candidate_subject": copy.deepcopy(candidate["subject"]),
        "program_bound_authority": {
            "baseline_proved_root_statement_sha256":
                baseline["arm_binding"]["proved_root_statement_sha256"],
            "candidate_proved_root_statement_sha256":
                candidate["arm_binding"]["proved_root_statement_sha256"],
            "baseline_vm_final_state_sha256":
                baseline["arm_binding"]["vm_final_state_sha256"],
            "candidate_vm_final_state_sha256":
                candidate["arm_binding"]["vm_final_state_sha256"],
            "baseline_proof_root_sha256": baseline["proof"]["root_sha256"],
            "candidate_proof_root_sha256": candidate["proof"]["root_sha256"],
        },
        "semantic_correctness": {
            "output": copy.deepcopy(baseline["correctness"]["semantic_output"]),
            "block_state_root": baseline["correctness"]["block_state_root"],
            "benchmark_statement_sha256":
                baseline["correctness"]["benchmark_statement_sha256"],
            "both_fresh_verified": True,
        },
        "metrics": metrics,
        "target": {
            "minimum_reduction_ppm": 950_000,
            "met": metrics["total_wall"]["target_95_percent_met"],
        },
    })


def validate_comparison(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "status", "baseline_trial", "candidate_trial", "benchmark", "host",
        "trial_regime", "resource_budget", "baseline_subject", "candidate_subject",
        "program_bound_authority", "semantic_correctness", "metrics", "target",
        "content_sha256",
    }, "Stwo A/B v2 comparison")
    _require(value["schema"] == COMPARISON_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "Stwo A/B v2 comparison seal differs")
    baseline_path = Path(_identity(
        value["baseline_trial"], "Stwo A/B v2 baseline trial", reopen=True,
    )["path"])
    candidate_path = Path(_identity(
        value["candidate_trial"], "Stwo A/B v2 candidate trial", reopen=True,
    )["path"])
    _require(value == build_comparison(baseline_path, candidate_path),
             "Stwo A/B v2 comparison replay differs")
    return value


def load_comparison(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "Stwo A/B v2 comparison",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(raw == protocol.canonical_bytes(value),
             "Stwo A/B v2 comparison is not canonical JSON")
    return validate_comparison(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--baseline", type=Path, required=True)
    create.add_argument("--candidate", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--comparison", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load_comparison(arguments.comparison)
            return 0
        result = build_comparison(arguments.baseline, arguments.candidate)
        output = arguments.output.absolute()
        staging = arguments.staging.absolute()
        store.require_directory(output.parent, "Stwo A/B v2 output parent")
        store.require_directory(staging, "Stwo A/B v2 staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(result), staging_directory=staging,
        )
        return 0
    except (StwoComparisonV2Error, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
