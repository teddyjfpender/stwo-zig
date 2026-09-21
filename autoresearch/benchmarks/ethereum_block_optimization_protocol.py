"""Typed, fail-closed optimization protocol for the Ethereum block corpus.

The optimization loop never scores an observation until its semantic output,
whole-block proof, fresh verification, security target, and host envelope are
all admitted.  Diagnostic subset runs remain useful for iteration, but cannot
silently become a five-block or apples-to-apples result.
"""

from __future__ import annotations

import argparse
import copy
from fractions import Fraction
from pathlib import Path
import re
import sys
from typing import Any


BENCHMARK_DIR = Path(__file__).resolve().parent
REPOSITORY = Path(__file__).resolve().parents[2]
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_benchmark_matrix_contract as matrix_contract  # noqa: E402
import ethereum_block_corpus as corpus_protocol  # noqa: E402
import ethereum_block_incremental_cost_evidence as incremental_evidence  # noqa: E402
import ethereum_block_microbenchmark_schedule as microbenchmark_schedule  # noqa: E402
import ethereum_block_optimization_evidence as input_evidence  # noqa: E402
import ethereum_block_provider_hpc_evidence as provider_evidence  # noqa: E402
import ethereum_block_zisk_final_evidence as zisk_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


PLAN_SCHEMA = "stwo.ethereum.optimization-experiment-plan.v1"
OBSERVATION_SCHEMA = "stwo.ethereum.optimization-observation.v1"
RESULT_SCHEMA = "stwo.ethereum.optimization-experiment-result.v1"
TRIAL_POLICIES = {
    "diagnostic": {"rounds": 1, "sequence": ["candidate"]},
    "milestone": {"rounds": 1, "sequence": ["baseline", "candidate"]},
    "promotion": {
        "rounds": 3,
        "sequence": ["baseline", "candidate", "candidate", "baseline"],
    },
}
STAGE_NAMES = (
    "execution", "witness_generation", "base_proofs", "aggregation",
    "fresh_verification",
)
CORPUS_CATEGORIES = {
    "empty-or-light-transfer",
    "keccak-heavy",
    "ecrecover-heavy",
    "contract-or-storage-heavy",
    "representative-medium-block",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")


class OptimizationProtocolError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OptimizationProtocolError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value), f"{where} differs")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"path", "bytes", "sha256"}, where)
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where}.path differs")
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where}.bytes differs")
    _sha(value["sha256"], f"{where}.sha256")
    store.validate_file_identity(Path(value["path"]), {
        "bytes": value["bytes"], "sha256": value["sha256"],
    }, where)
    return value


def _read_json(path: Path, where: str, *, canonical: bool = False) -> dict[str, Any]:
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    if canonical:
        _require(raw == protocol.canonical_bytes(value), f"{where} is not canonical JSON")
    return value


def _transport(value: Any, where: str) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact(value, {"bytes", "sha256", "framing"}, where)
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where}.bytes differs")
    _sha(value["sha256"], f"{where}.sha256")
    _require(type(value["framing"]) is str and value["framing"],
             f"{where}.framing differs")
    return value


def _fixture_projection(index: int, fixture: dict[str, Any]) -> dict[str, Any]:
    transports = fixture["semantic_io"]["guest_transports"]
    stwo_input = transports["stwo_input"]
    stwo_output = transports["stwo_output"]
    materialized = stwo_input is not None and stwo_output is not None
    block = fixture["block"]
    return {
        "fixture_index": index,
        "fixture_id": fixture["fixture_id"],
        "category": fixture["category"],
        "block": {
            "chain_id": block["chain_id"],
            "number": block["number"],
            "hash": block["hash"],
            "parent_state_root": block["parent_state_root"],
        },
        "semantic_input": copy.deepcopy(fixture["semantic_io"]["input"]),
        "semantic_output": copy.deepcopy(fixture["semantic_io"]["output"]),
        "stwo_input": copy.deepcopy(stwo_input),
        "stwo_output": copy.deepcopy(stwo_output),
        "authority_status": (
            "materialized" if materialized else "guest-transport-authority-unavailable"
        ),
    }


def _validate_fixture(value: Any, index: int) -> dict[str, Any]:
    value = _exact(value, {
        "fixture_index", "fixture_id", "category", "block", "semantic_input",
        "semantic_output", "stwo_input", "stwo_output", "authority_status",
    }, f"optimization fixture {index}")
    _require(value["fixture_index"] == index and type(value["fixture_id"]) is str
             and value["fixture_id"] and value["category"] in CORPUS_CATEGORIES,
             f"optimization fixture {index} identity differs")
    _exact(value["block"], {"chain_id", "number", "hash", "parent_state_root"},
           f"optimization fixture {index} block")
    _transport(value["semantic_input"], f"optimization fixture {index} semantic input")
    _transport(value["semantic_output"], f"optimization fixture {index} semantic output")
    stwo_input = _transport(value["stwo_input"], f"optimization fixture {index} input")
    stwo_output = _transport(value["stwo_output"], f"optimization fixture {index} output")
    status = ("materialized" if stwo_input is not None and stwo_output is not None
              else "guest-transport-authority-unavailable")
    _require(value["authority_status"] == status,
             f"optimization fixture {index} authority status differs")
    return value


def _candidate(value: Any, fixture_tokens: list[str]) -> dict[str, Any]:
    value = _exact(value, {"source", "binary", "configuration"},
                   "optimization candidate")
    source = _exact(value["source"], {"commit", "tree", "clean"},
                    "optimization candidate source")
    _require(type(source["commit"]) is str and GIT_ID.fullmatch(source["commit"])
             and type(source["tree"]) is str and GIT_ID.fullmatch(source["tree"])
             and source["clean"] is True,
             "optimization candidate source differs")
    _validate_identity(value["binary"], "optimization candidate binary")
    config = _exact(value["configuration"], {
        "scope", "optimization_family", "engine_profile", "backend",
        "worker_envelope", "memory_budget_bytes", "trial_timeout_seconds",
        "feature_flags",
    }, "optimization candidate configuration")
    _require(config["scope"] == "global-corpus-policy"
             and type(config["optimization_family"]) is str
             and config["optimization_family"]
             and type(config["engine_profile"]) is str and config["engine_profile"]
             and config["backend"] in ("cpu", "metal", "hybrid")
             and type(config["memory_budget_bytes"]) is int
             and config["memory_budget_bytes"] > 0
             and type(config["trial_timeout_seconds"]) is int
             and 0 < config["trial_timeout_seconds"] <= 120,
             "optimization candidate configuration differs")
    workers = _exact(config["worker_envelope"], {
        "processes", "threads", "accelerator_workers",
    }, "optimization candidate workers")
    _require(all(type(item) is int and item >= 0 for item in workers.values())
             and workers["processes"] > 0 and workers["threads"] > 0,
             "optimization candidate workers differ")
    flags = config["feature_flags"]
    _require(type(flags) is list and flags == sorted(set(flags))
             and all(type(item) is str and item for item in flags),
             "optimization candidate flags differ")

    def values(item: Any):
        if type(item) is dict:
            for child in item.values():
                yield from values(child)
        elif type(item) is list:
            for child in item:
                yield from values(child)
        elif type(item) is str:
            yield item

    encoded = "\n".join(values(config)).lower()
    _require(not any(token.lower() in encoded for token in fixture_tokens),
             "optimization candidate contains a fixture-specific override")
    return value


def _baseline(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "typed-combined-result-unavailable",
            "identity": None,
            "source_schema": None,
            "adapter_kind": None,
            "production_admitted": False,
        }
    value = _read_json(path, "optimization baseline result")
    _require(type(value.get("schema")) is str and value["schema"],
             "optimization baseline result schema differs")
    return {
        "status": "typed-result-awaiting-production-adapter",
        "identity": _identity(path, "optimization baseline result"),
        "source_schema": value["schema"],
        "adapter_kind": None,
        "production_admitted": False,
    }


def _diagnostic_inputs(path: Path, peer: dict[str, Any],
                       fixture: dict[str, Any]) -> dict[str, Any]:
    value = input_evidence.load(path.absolute())
    workload = value["corpus_workload"]
    _require(workload["fixture"]["fixture_id"] == fixture["fixture_id"]
             and workload["fixture"]["stwo_input"] == fixture["stwo_input"]
             and workload["fixture"]["stwo_output"] == fixture["stwo_output"],
             "optimization input evidence differs from reference fixture")
    _require(value["zisk_peer"] == peer,
             "optimization input evidence ZisK peer differs")
    _require(value["optimization_boundary"]["production_promotion_eligible"] is False,
             "optimization diagnostic inputs cannot promote")
    return {
        "identity": _identity(path, "optimization input evidence"),
        "content_sha256": value["content_sha256"],
        "status": value["status"],
        "fixture_id": workload["fixture"]["fixture_id"],
        "segment_count": workload["segment_count"],
        "total_cycles": workload["total_cycles"],
        "ranking_role": "diagnostic-context-only",
        "production_promotion_eligible": False,
    }


def _diagnostic_rankings(paths: list[Path]) -> list[dict[str, Any]]:
    result = []
    seen: set[str] = set()
    for path in paths:
        path = path.absolute()
        value = _read_json(path, "optimization diagnostic ranking", canonical=True)
        schema = value.get("schema")
        if schema in {
            incremental_evidence.RANKING_SCHEMA_V1,
            incremental_evidence.RANKING_SCHEMA,
        }:
            incremental_evidence.load_ranking(path)
        elif schema == provider_evidence.RANKING_SCHEMA:
            provider_evidence.load_ranking(path)
        elif schema == microbenchmark_schedule.SCHEMA:
            microbenchmark_schedule.load(path)
        else:
            raise OptimizationProtocolError("optimization ranking schema differs")
        identity = _identity(path, "optimization diagnostic ranking")
        _require(identity["sha256"] not in seen,
                 "optimization ranking identity is duplicated")
        seen.add(identity["sha256"])
        result.append({
            "identity": identity,
            "schema": schema,
            "content_sha256": value["content_sha256"],
            "status": value["status"],
            "ranking_role": "diagnostic-context-only",
            "production_promotion_eligible": False,
        })
    return result


def _task_list(
    fixtures: list[dict[str, Any]], trial_policy: dict[str, Any],
) -> list[dict[str, Any]]:
    tasks = []
    for fixture in fixtures:
        if fixture["authority_status"] != "materialized":
            continue
        for round_index in range(trial_policy["rounds"]):
            for sequence_index, arm in enumerate(trial_policy["sequence"]):
                tasks.append({
                    "task_id": (
                        f"fixture-{fixture['fixture_index']:03d}-round-{round_index:03d}-"
                        f"sequence-{sequence_index:02d}-{arm}"
                    ),
                    "fixture_index": fixture["fixture_index"],
                    "fixture_id": fixture["fixture_id"],
                    "round_index": round_index,
                    "sequence_index": sequence_index,
                    "arm": arm,
                })
    return tasks


def build_plan(
    *, corpus_path: Path, zisk_receipt: Path, trial_class: str,
    candidate: dict[str, Any], baseline_result: Path | None,
    security_target_bits: int, input_evidence_path: Path,
    diagnostic_ranking_paths: list[Path] | None = None,
) -> dict[str, Any]:
    _require(trial_class in TRIAL_POLICIES, "optimization trial class differs")
    corpus = _read_json(corpus_path, "optimization corpus")
    try:
        corpus_protocol.validate(corpus)
    except corpus_protocol.CorpusError as error:
        raise OptimizationProtocolError(str(error)) from error
    fixtures = [_fixture_projection(index, fixture)
                for index, fixture in enumerate(corpus["fixtures"])]
    _require(len(fixtures) == 5 and {item["category"] for item in fixtures}
             == CORPUS_CATEGORIES, "optimization corpus diversity differs")
    tokens = [item["fixture_id"] for item in fixtures]
    tokens += [str(item["block"]["number"]) for item in fixtures]
    tokens += [item["block"]["hash"] for item in fixtures]
    candidate = _candidate(copy.deepcopy(candidate), tokens)
    peer = zisk_evidence.evidence(zisk_receipt.absolute())
    _require(peer["projection"]["fixture_id"] == fixtures[0]["fixture_id"],
             "ZisK peer evidence differs from the reference corpus fixture")
    _require(type(security_target_bits) is int and security_target_bits > 0,
             "optimization security target differs")
    trial_policy = copy.deepcopy(TRIAL_POLICIES[trial_class])
    baseline = _baseline(baseline_result)
    diagnostic_inputs = _diagnostic_inputs(
        input_evidence_path.absolute(), peer, fixtures[0],
    )
    diagnostic_rankings = _diagnostic_rankings(diagnostic_ranking_paths or [])
    materialized_count = sum(item["authority_status"] == "materialized"
                             for item in fixtures)
    _require(trial_class != "promotion" or (
        materialized_count == 5 and baseline["production_admitted"] is True
    ), "promotion trial lacks five materialized fixtures or an admitted baseline")
    return protocol.seal({
        "schema": PLAN_SCHEMA,
        "trial_class": trial_class,
        "corpus": {
            "identity": _identity(corpus_path, "optimization corpus"),
            "corpus_sha256": corpus["corpus_sha256"],
            "fixture_count": len(fixtures),
            "materialized_fixture_count": materialized_count,
            "fixtures": fixtures,
        },
        "peer_context": {
            "role": "correctness-and-capability-context-not-optimization-baseline",
            "zisk_final_evidence": peer,
            "timing_role": "none",
        },
        "diagnostic_inputs": diagnostic_inputs,
        "diagnostic_rankings": diagnostic_rankings,
        "baseline": baseline,
        "candidate": candidate,
        "trial_policy": trial_policy,
        "tasks": _task_list(fixtures, trial_policy),
        "correctness_policy": {
            "ordered_gates": [
                "source-and-semantic-io", "execution-output", "complete-final-root",
                "fresh-verification", "security-target", "host-envelope",
            ],
            "metrics_before_all_gates": "forbidden",
            "required_proof_scope": "final_root",
            "required_fresh_verification": True,
        },
        "measurement_policy": {
            "stage_names": list(STAGE_NAMES),
            "exclusive_stage_reconciliation": "sum-stage-wall-equals-e2e-wall",
            "interleaving": trial_policy["sequence"],
            "rounds": trial_policy["rounds"],
            "failed_or_indeterminate_attempt_timing": "nonpromotable",
            "per_trial_timeout_seconds": candidate["configuration"][
                "trial_timeout_seconds"
            ],
        },
        "objective": {
            "primary": "arithmetic-mean-of-five-fixture-median-e2e-wall-ns",
            "target_average_wall_ns": matrix_contract.TARGET_AVERAGE_WALL_NS,
            "secondary": "candidate-peak-rss-bytes",
            "memory_cap_bytes": candidate["configuration"]["memory_budget_bytes"],
            "per_fixture_max_regression": {"numerator": 105, "denominator": 100},
            "stage_timings": "diagnostic-decomposition-only",
            "fixture_specific_tuning": "forbidden",
        },
        "security_policy": {
            "conservative_end_to_end_target_bits": security_target_bits,
            "baseline_and_candidate_must_match": True,
        },
        "host_policy": copy.deepcopy(matrix_contract.CONTRACT["hardware_policy"]),
        "promotion_policy": {
            "requires_all_five_fixtures": True,
            "requires_three_paired_rounds": True,
            "requires_clean_ac_no_interference": True,
            "requires_no_failed_or_indeterminate_attempts": True,
            "requires_candidate_mean_below_baseline": True,
            "requires_target_average": True,
        },
    })


def validate_plan(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "trial_class", "corpus", "peer_context", "baseline", "candidate",
        "diagnostic_inputs", "diagnostic_rankings", "trial_policy", "tasks",
        "correctness_policy", "measurement_policy", "objective", "security_policy",
        "host_policy", "promotion_policy", "content_sha256",
    }, "optimization plan")
    _require(value["schema"] == PLAN_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "optimization plan identity differs")
    trial_class = value["trial_class"]
    _require(trial_class in TRIAL_POLICIES
             and value["trial_policy"] == TRIAL_POLICIES[trial_class],
             "optimization trial policy differs")
    corpus = _exact(value["corpus"], {
        "identity", "corpus_sha256", "fixture_count", "materialized_fixture_count",
        "fixtures",
    }, "optimization plan corpus")
    identity = _validate_identity(corpus["identity"], "optimization corpus")
    source = _read_json(Path(identity["path"]), "optimization corpus")
    try:
        corpus_protocol.validate(source)
    except corpus_protocol.CorpusError as error:
        raise OptimizationProtocolError(str(error)) from error
    fixtures = corpus["fixtures"]
    _require(type(fixtures) is list and len(fixtures) == corpus["fixture_count"] == 5,
             "optimization plan fixture count differs")
    for index, fixture in enumerate(fixtures):
        _validate_fixture(fixture, index)
        _require(fixture == _fixture_projection(index, source["fixtures"][index]),
                 f"optimization fixture {index} replay differs")
    materialized = sum(item["authority_status"] == "materialized" for item in fixtures)
    _require(corpus["materialized_fixture_count"] == materialized
             and corpus["corpus_sha256"] == source["corpus_sha256"],
             "optimization corpus authority differs")
    peer = _exact(value["peer_context"], {
        "role", "zisk_final_evidence", "timing_role",
    }, "optimization peer context")
    _require(peer["role"]
             == "correctness-and-capability-context-not-optimization-baseline"
             and peer["timing_role"] == "none",
             "optimization peer role differs")
    receipt_path = Path(peer["zisk_final_evidence"]["receipt"]["path"])
    _require(peer["zisk_final_evidence"] == zisk_evidence.evidence(receipt_path),
             "optimization ZisK peer evidence replay differs")
    inputs = _exact(value["diagnostic_inputs"], {
        "identity", "content_sha256", "status", "fixture_id", "segment_count",
        "total_cycles", "ranking_role", "production_promotion_eligible",
    }, "optimization diagnostic inputs")
    input_identity = _validate_identity(
        inputs["identity"], "optimization input evidence",
    )
    _require(inputs == _diagnostic_inputs(
        Path(input_identity["path"]), peer["zisk_final_evidence"], fixtures[0],
    ), "optimization diagnostic input replay differs")
    rankings = value["diagnostic_rankings"]
    _require(type(rankings) is list, "optimization diagnostic rankings differ")
    ranking_paths = []
    for index, item in enumerate(rankings):
        item = _exact(item, {
            "identity", "schema", "content_sha256", "status", "ranking_role",
            "production_promotion_eligible",
        }, f"optimization diagnostic ranking {index}")
        identity = _validate_identity(
            item["identity"], f"optimization diagnostic ranking {index}",
        )
        ranking_paths.append(Path(identity["path"]))
    _require(rankings == _diagnostic_rankings(ranking_paths),
             "optimization diagnostic ranking replay differs")
    baseline = _exact(value["baseline"], {
        "status", "identity", "source_schema", "adapter_kind", "production_admitted",
    }, "optimization baseline")
    if baseline["identity"] is None:
        _require(baseline == _baseline(None), "optimization absent baseline differs")
    else:
        _require(baseline == _baseline(Path(baseline["identity"]["path"])),
                 "optimization baseline replay differs")
    tokens = [item["fixture_id"] for item in fixtures]
    tokens += [str(item["block"]["number"]) for item in fixtures]
    tokens += [item["block"]["hash"] for item in fixtures]
    _candidate(value["candidate"], tokens)
    _require(value["tasks"] == _task_list(fixtures, value["trial_policy"]),
             "optimization task schedule differs")
    _require(value["correctness_policy"]["metrics_before_all_gates"] == "forbidden"
             and value["measurement_policy"]["stage_names"] == list(STAGE_NAMES)
             and 0 < value["measurement_policy"]["per_trial_timeout_seconds"] <= 120
             and value["objective"]["target_average_wall_ns"]
             == matrix_contract.TARGET_AVERAGE_WALL_NS
             and value["objective"]["fixture_specific_tuning"] == "forbidden",
             "optimization policy differs")
    target = value["security_policy"]["conservative_end_to_end_target_bits"]
    _require(type(target) is int and target > 0,
             "optimization security policy differs")
    _require(trial_class != "promotion" or (
        materialized == 5 and baseline["production_admitted"] is True
    ), "optimization promotion plan is not production-admitted")
    return value


def _timing(value: Any, where: str) -> dict[str, int] | None:
    if value is None:
        return None
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values()),
             f"{where} differs")
    return value


def validate_observation(
    value: Any, plan: dict[str, Any], task: dict[str, Any],
) -> dict[str, Any]:
    validate_plan(plan)
    value = _exact(value, {
        "schema", "plan_sha256", "task", "adapter", "subject_identity",
        "source_result", "correctness", "measurements", "host", "attempt_custody",
        "content_sha256",
    }, "optimization observation")
    _require(value["schema"] == OBSERVATION_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value)
             and value["plan_sha256"] == plan["content_sha256"]
             and value["task"] == task,
             "optimization observation identity differs")
    adapter = _exact(value["adapter"], {
        "kind", "production_admitted", "validator_identity",
    }, "optimization observation adapter")
    _require(type(adapter["kind"]) is str and adapter["kind"]
             and type(adapter["production_admitted"]) is bool,
             "optimization observation adapter differs")
    _sha(adapter["validator_identity"], "optimization adapter validator identity")
    _sha(value["subject_identity"], "optimization observation subject")
    if task["arm"] == "candidate":
        _require(value["subject_identity"] == plan["candidate"]["binary"]["sha256"],
                 "optimization candidate observation subject differs")
    else:
        _require(plan["baseline"]["production_admitted"] is True
                 and value["subject_identity"] == plan["baseline"]["identity"]["sha256"],
                 "optimization baseline observation subject differs")
    _validate_identity(value["source_result"], "optimization source result")
    fixture = plan["corpus"]["fixtures"][task["fixture_index"]]
    correctness = _exact(value["correctness"], {
        "semantic_input_sha256", "semantic_output_sha256", "execution_complete",
        "output_matched", "proof_scope", "proof_complete", "fresh_verification",
        "security_target_bits", "passed",
    }, "optimization observation correctness")
    expected_passed = (
        correctness["semantic_input_sha256"] == fixture["semantic_input"]["sha256"]
        and correctness["semantic_output_sha256"] == fixture["semantic_output"]["sha256"]
        and correctness["execution_complete"] is True
        and correctness["output_matched"] is True
        and correctness["proof_scope"] == "final_root"
        and correctness["proof_complete"] is True
        and correctness["fresh_verification"] is True
        and type(correctness["security_target_bits"]) is int
        and correctness["security_target_bits"]
        >= plan["security_policy"]["conservative_end_to_end_target_bits"]
    )
    _require(correctness["passed"] is expected_passed,
             "optimization observation correctness verdict differs")
    host = _exact(value["host"], {
        "machine_model", "cpu_model", "memory_bytes", "operating_system",
        "power_source", "thermal_warning", "interference_observed", "matched",
    }, "optimization observation host")
    policy = plan["host_policy"]
    expected_host = (
        host["machine_model"] == policy["machine_model"]
        and host["memory_bytes"] == policy["memory_bytes"]
        and host["operating_system"] == policy["operating_system"]
        and type(host["power_source"]) is str
        and bool(host["power_source"])
        and host["thermal_warning"] is False
        and host["interference_observed"] is False
    )
    _require(host["matched"] is expected_host, "optimization host verdict differs")
    attempts = _exact(value["attempt_custody"], {
        "attempt_count", "failed_count", "indeterminate_count",
    }, "optimization attempt custody")
    _require(all(type(item) is int and item >= 0 for item in attempts.values())
             and attempts["attempt_count"] > 0
             and attempts["failed_count"] + attempts["indeterminate_count"]
             < attempts["attempt_count"],
             "optimization attempt custody differs")
    measurements = _exact(value["measurements"], {
        "eligible", "stage_timings", "end_to_end", "peak_rss_bytes",
    }, "optimization observation measurements")
    stages = _exact(measurements["stage_timings"], set(STAGE_NAMES),
                    "optimization stage timings")
    for name in STAGE_NAMES:
        _timing(stages[name], f"optimization {name} timing")
    e2e = _timing(measurements["end_to_end"], "optimization E2E timing")
    expected_eligible = (
        adapter["production_admitted"] is True and correctness["passed"] is True
        and host["matched"] is True and attempts == {
            "attempt_count": 1, "failed_count": 0, "indeterminate_count": 0,
        }
        and e2e is not None and all(stages[name] is not None for name in STAGE_NAMES)
        and type(measurements["peak_rss_bytes"]) is int
        and measurements["peak_rss_bytes"] > 0
        and sum(stages[name]["wall_ns"] for name in STAGE_NAMES) == e2e["wall_ns"]
    )
    _require(measurements["eligible"] is expected_eligible,
             "optimization measurement eligibility differs")
    if not expected_eligible:
        _require(e2e is None and all(stages[name] is None for name in STAGE_NAMES)
                 and measurements["peak_rss_bytes"] is None,
                 "ineligible optimization observation carries measurements")
    return value


def _median(values: list[int]) -> Fraction:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return (Fraction(ordered[middle], 1) if len(ordered) % 2
            else Fraction(ordered[middle - 1] + ordered[middle], 2))


def _rational(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def summarize(plan: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    validate_plan(plan)
    _require(len(observations) == len(plan["tasks"]),
             "optimization result lacks committed tasks")
    for task, observation in zip(plan["tasks"], observations):
        validate_observation(observation, plan, task)
    correctness_passed = all(item["correctness"]["passed"] for item in observations)
    measurement_complete = all(item["measurements"]["eligible"] for item in observations)
    reasons = []
    if plan["trial_class"] != "promotion":
        reasons.append("trial-class-is-nonpromotable")
    if plan["corpus"]["materialized_fixture_count"] != 5:
        reasons.append("five-fixture-authority-incomplete")
    if plan["baseline"]["production_admitted"] is not True:
        reasons.append("production-baseline-adapter-unavailable")
    if not correctness_passed:
        reasons.append("correctness-gate-failed")
    if not measurement_complete:
        reasons.append("eligible-measurements-incomplete")
    metrics: dict[str, Any] | None = None
    if not reasons:
        by_fixture: dict[int, dict[str, list[dict[str, Any]]]] = {}
        for observation in observations:
            task = observation["task"]
            by_fixture.setdefault(task["fixture_index"], {
                "baseline": [], "candidate": [],
            })[task["arm"]].append(observation)
        per_fixture = []
        candidate_medians = []
        baseline_medians = []
        no_regression = True
        for index in range(5):
            arms = by_fixture[index]
            baseline_median = _median([
                item["measurements"]["end_to_end"]["wall_ns"]
                for item in arms["baseline"]
            ])
            candidate_median = _median([
                item["measurements"]["end_to_end"]["wall_ns"]
                for item in arms["candidate"]
            ])
            limit = plan["objective"]["per_fixture_max_regression"]
            no_regression &= (candidate_median * limit["denominator"]
                              <= baseline_median * limit["numerator"])
            baseline_medians.append(baseline_median)
            candidate_medians.append(candidate_median)
            per_fixture.append({
                "fixture_index": index,
                "baseline_median_wall_ns": _rational(baseline_median),
                "candidate_median_wall_ns": _rational(candidate_median),
            })
        baseline_mean = sum(baseline_medians, Fraction()) / 5
        candidate_mean = sum(candidate_medians, Fraction()) / 5
        peak_rss = max(item["measurements"]["peak_rss_bytes"]
                       for item in observations if item["task"]["arm"] == "candidate")
        metrics = {
            "per_fixture": per_fixture,
            "baseline_mean_wall_ns": _rational(baseline_mean),
            "candidate_mean_wall_ns": _rational(candidate_mean),
            "candidate_peak_rss_bytes": peak_rss,
            "candidate_below_baseline": candidate_mean < baseline_mean,
            "target_met": (
                candidate_mean <= plan["objective"]["target_average_wall_ns"]
            ),
            "memory_cap_met": peak_rss <= plan["objective"]["memory_cap_bytes"],
            "per_fixture_regression_budget_met": no_regression,
        }
        if not metrics["candidate_below_baseline"]:
            reasons.append("candidate-mean-does-not-improve-baseline")
        if not metrics["target_met"]:
            reasons.append("five-fixture-target-not-met")
        if not metrics["memory_cap_met"]:
            reasons.append("memory-cap-exceeded")
        if not metrics["per_fixture_regression_budget_met"]:
            reasons.append("per-fixture-regression-budget-exceeded")
    return protocol.seal({
        "schema": RESULT_SCHEMA,
        "plan_sha256": plan["content_sha256"],
        "task_count": len(observations),
        "correctness_passed": correctness_passed,
        "measurement_complete": measurement_complete,
        "metrics": metrics,
        "promotion": {
            "eligible": not reasons,
            "blockers": sorted(reasons),
        },
        "observations": observations,
    })


def validate_result(value: Any, plan: dict[str, Any]) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "plan_sha256", "task_count", "correctness_passed",
        "measurement_complete", "metrics", "promotion", "observations",
        "content_sha256",
    }, "optimization result")
    _require(value["schema"] == RESULT_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "optimization result identity differs")
    _require(value == summarize(plan, value["observations"]),
             "optimization result replay differs")
    return value


def load_plan(path: Path) -> dict[str, Any]:
    return validate_plan(_read_json(path.absolute(), "optimization plan", canonical=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-plan")
    create.add_argument("--corpus", type=Path, default=corpus_protocol.DEFAULT_CORPUS)
    create.add_argument("--zisk-receipt", type=Path, required=True)
    create.add_argument("--input-evidence", type=Path, required=True)
    create.add_argument("--diagnostic-ranking", type=Path, action="append", default=[])
    create.add_argument("--trial-class", choices=tuple(TRIAL_POLICIES), required=True)
    create.add_argument("--candidate", type=Path, required=True)
    create.add_argument("--baseline-result", type=Path)
    create.add_argument("--security-target-bits", type=int, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    validate_command = commands.add_parser("validate-plan")
    validate_command.add_argument("--plan", type=Path, required=True)
    result = commands.add_parser("validate-result")
    result.add_argument("--plan", type=Path, required=True)
    result.add_argument("--result", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create-plan":
            candidate = _read_json(arguments.candidate, "optimization candidate",
                                   canonical=True)
            value = build_plan(
                corpus_path=arguments.corpus,
                zisk_receipt=arguments.zisk_receipt,
                trial_class=arguments.trial_class,
                candidate=candidate,
                baseline_result=arguments.baseline_result,
                security_target_bits=arguments.security_target_bits,
                input_evidence_path=arguments.input_evidence,
                diagnostic_ranking_paths=arguments.diagnostic_ranking,
            )
            output = arguments.output.absolute()
            staging = arguments.staging_directory.absolute()
            store.require_directory(output.parent, "optimization plan parent")
            store.require_directory(staging, "optimization plan staging", create=True)
            store.publish_new_or_identical(
                output, protocol.canonical_bytes(value), staging_directory=staging,
            )
            return 0
        plan = load_plan(arguments.plan)
        if arguments.command == "validate-result":
            validate_result(
                _read_json(arguments.result, "optimization result", canonical=True), plan,
            )
        return 0
    except (OptimizationProtocolError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
