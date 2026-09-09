#!/usr/bin/env python3
"""Strict one-block Stwo baseline/candidate apples-to-apples comparison.

This adapter intentionally refuses diagnostic, failed, or partially timed runs.
In particular, an InvalidStatement attempt can never become a baseline.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


TRIAL_SCHEMA = "stwo.ethereum.block-stwo-ab-trial.v1"
COMPARISON_SCHEMA = "stwo.ethereum.block-stwo-ab-comparison.v1"
ARMS = ("baseline", "candidate")
STAGES = ("execution", "witness_generation", "proving", "fresh_verification")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")


class StwoComparisonError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StwoComparisonError(message)


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


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values()),
             f"{where} differs")
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


def validate_trial(value: Any, *, reopen: bool = True) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "arm", "status", "workload", "subject", "host", "stages",
        "total", "peak_rss_bytes", "proof", "correctness", "attempt_custody",
        "eligible", "content_sha256",
    }, "Stwo A/B trial")
    _require(value["schema"] == TRIAL_SCHEMA and value["arm"] in ARMS
             and value["status"] == "fresh-verified-complete",
             "Stwo A/B trial header differs")
    _require(value["content_sha256"] == protocol.content_sha256(value),
             "Stwo A/B trial seal differs")

    workload = _exact(value["workload"], {
        "chain_id", "block_number", "block_hash", "input", "expected_output",
        "expected_final_state_sha256", "execution_profile", "statement_sha256",
    }, "Stwo A/B workload")
    _positive(workload["chain_id"], "Stwo A/B chain id")
    _positive(workload["block_number"], "Stwo A/B block number")
    _sha(workload["block_hash"], "Stwo A/B block hash")
    _identity(workload["input"], "Stwo A/B input", reopen=reopen)
    _transport(workload["expected_output"], "Stwo A/B expected output")
    _sha(workload["expected_final_state_sha256"], "Stwo A/B expected final state")
    _sha(workload["statement_sha256"], "Stwo A/B statement")
    _require(type(workload["execution_profile"]) is str
             and workload["execution_profile"],
             "Stwo A/B execution profile differs")

    subject = _exact(value["subject"], {
        "source", "executable", "build_mode", "feature_flags", "production_admitted",
        "process_count", "thread_count", "engine_workers", "provider_topology",
        "coefficient_retention",
    }, "Stwo A/B subject")
    _source(subject["source"], "Stwo A/B source")
    _identity(subject["executable"], "Stwo A/B executable", reopen=reopen)
    _require(subject["build_mode"] == "ReleaseFast"
             and type(subject["production_admitted"]) is bool,
             "Stwo A/B subject mode differs")
    flags = subject["feature_flags"]
    _require(type(flags) is list and flags == sorted(set(flags))
             and all(type(item) is str and item for item in flags),
             "Stwo A/B feature flags differ")
    for field in ("process_count", "thread_count", "engine_workers"):
        _positive(subject[field], f"Stwo A/B subject {field}")
    _require(type(subject["provider_topology"]) is str
             and subject["provider_topology"]
             and subject["coefficient_retention"] in ("always", "never"),
             "Stwo A/B provider configuration differs")

    host = _exact(value["host"], {
        "machine_model", "cpu_model", "memory_bytes", "operating_system",
        "power_source", "thermal_state", "interference_observed",
    }, "Stwo A/B host")
    for field in ("machine_model", "cpu_model", "operating_system", "power_source",
                  "thermal_state"):
        _require(type(host[field]) is str and host[field], f"Stwo A/B host {field} differs")
    _positive(host["memory_bytes"], "Stwo A/B host memory")
    _require(type(host["interference_observed"]) is bool,
             "Stwo A/B host interference differs")

    stages = _exact(value["stages"], set(STAGES), "Stwo A/B stages")
    for stage in STAGES:
        _timing(stages[stage], f"Stwo A/B {stage}")
    total = _timing(value["total"], "Stwo A/B total")
    for field in ("wall_ns", "user_ns", "system_ns"):
        _require(total[field] == sum(stages[stage][field] for stage in STAGES),
                 f"Stwo A/B total {field} does not reconcile")
    _positive(value["peak_rss_bytes"], "Stwo A/B peak RSS")

    proof = _exact(value["proof"], {
        "identity", "statement_sha256", "root_sha256", "security_identity_sha256",
        "conservative_security_bits", "canonical_decode", "roundtrip_exact",
    }, "Stwo A/B proof")
    _identity(proof["identity"], "Stwo A/B proof artifact", reopen=reopen)
    for field in ("statement_sha256", "root_sha256", "security_identity_sha256"):
        _sha(proof[field], f"Stwo A/B proof {field}")
    _positive(proof["conservative_security_bits"], "Stwo A/B security bits")
    _require(type(proof["canonical_decode"]) is bool
             and type(proof["roundtrip_exact"]) is bool,
             "Stwo A/B proof codec verdict differs")

    correctness = _exact(value["correctness"], {
        "semantic_output", "final_state_sha256", "public_statement_sha256",
        "expected_output_matched", "expected_final_state_matched",
        "fresh_verified", "verifier_executable",
    }, "Stwo A/B correctness")
    _transport(correctness["semantic_output"], "Stwo A/B semantic output")
    _sha(correctness["final_state_sha256"], "Stwo A/B final state")
    _sha(correctness["public_statement_sha256"], "Stwo A/B public statement")
    _identity(correctness["verifier_executable"], "Stwo A/B verifier", reopen=reopen)
    for field in ("expected_output_matched", "expected_final_state_matched",
                  "fresh_verified"):
        _require(type(correctness[field]) is bool, f"Stwo A/B {field} differs")

    attempts = _exact(value["attempt_custody"], {
        "attempt_count", "successful_attempt_index", "failed_count",
        "indeterminate_count", "terminal_error",
    }, "Stwo A/B attempts")
    _require(all(type(attempts[field]) is int and attempts[field] >= 0 for field in (
        "attempt_count", "successful_attempt_index", "failed_count", "indeterminate_count",
    )) and attempts["attempt_count"] > 0
             and (attempts["terminal_error"] is None
                  or type(attempts["terminal_error"]) is str),
             "Stwo A/B attempt custody differs")

    expected_eligible = (
        subject["production_admitted"] is True
        and host["thermal_state"] == "nominal"
        and host["interference_observed"] is False
        and proof["statement_sha256"] == workload["statement_sha256"]
        and proof["canonical_decode"] is True
        and proof["roundtrip_exact"] is True
        and correctness["semantic_output"] == workload["expected_output"]
        and correctness["final_state_sha256"] == workload["expected_final_state_sha256"]
        and correctness["public_statement_sha256"] == workload["statement_sha256"]
        and correctness["expected_output_matched"] is True
        and correctness["expected_final_state_matched"] is True
        and correctness["fresh_verified"] is True
        and attempts == {
            "attempt_count": 1,
            "successful_attempt_index": 0,
            "failed_count": 0,
            "indeterminate_count": 0,
            "terminal_error": None,
        }
    )
    _require(type(value["eligible"]) is bool and value["eligible"] is expected_eligible,
             "Stwo A/B trial eligibility differs")
    return value


def _trial_identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def load_trial(path: Path) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, "Stwo A/B trial", maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(raw == protocol.canonical_bytes(value), "Stwo A/B trial is not canonical JSON")
    return validate_trial(value, reopen=True)


def _metric(baseline: int, candidate: int) -> dict[str, Any]:
    _positive(baseline, "Stwo A/B baseline metric")
    _positive(candidate, "Stwo A/B candidate metric")
    return {
        "baseline": baseline,
        "candidate": candidate,
        "speedup": {"numerator": baseline, "denominator": candidate},
        "reduction_ppm": ((baseline - candidate) * 1_000_000) // baseline,
        "target_95_percent_met": candidate * 20 <= baseline,
    }


def build_comparison(
    baseline_path: Path, candidate_path: Path,
) -> dict[str, Any]:
    baseline = load_trial(baseline_path)
    candidate = load_trial(candidate_path)
    _require(baseline["arm"] == "baseline" and candidate["arm"] == "candidate",
             "Stwo A/B arm order differs")
    _require(baseline["eligible"] is True and candidate["eligible"] is True,
             "Stwo A/B comparison requires two eligible trials")
    _require(baseline["workload"] == candidate["workload"],
             "Stwo A/B workloads differ")
    _require(baseline["host"] == candidate["host"], "Stwo A/B hosts differ")
    for field in ("build_mode", "process_count", "thread_count", "engine_workers"):
        _require(baseline["subject"][field] == candidate["subject"][field],
                 f"Stwo A/B subject {field} differs")
    for field in ("statement_sha256", "security_identity_sha256",
                  "conservative_security_bits"):
        _require(baseline["proof"][field] == candidate["proof"][field],
                 f"Stwo A/B proof {field} differs")
    _require(baseline["correctness"]["semantic_output"]
             == candidate["correctness"]["semantic_output"]
             and baseline["correctness"]["final_state_sha256"]
             == candidate["correctness"]["final_state_sha256"],
             "Stwo A/B correctness identities differ")

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
        baseline["proof"]["identity"]["bytes"],
        candidate["proof"]["identity"]["bytes"],
    )
    return protocol.seal({
        "schema": COMPARISON_SCHEMA,
        "status": "apples-to-apples-complete",
        "baseline_trial": _trial_identity(baseline_path, "Stwo A/B baseline trial"),
        "candidate_trial": _trial_identity(candidate_path, "Stwo A/B candidate trial"),
        "workload": copy.deepcopy(baseline["workload"]),
        "host": copy.deepcopy(baseline["host"]),
        "baseline_subject": copy.deepcopy(baseline["subject"]),
        "candidate_subject": copy.deepcopy(candidate["subject"]),
        "correctness": {
            "semantic_output_sha256": baseline["correctness"]["semantic_output"]["sha256"],
            "final_state_sha256": baseline["correctness"]["final_state_sha256"],
            "public_statement_sha256": baseline["correctness"]["public_statement_sha256"],
            "baseline_proof_root_sha256": baseline["proof"]["root_sha256"],
            "candidate_proof_root_sha256": candidate["proof"]["root_sha256"],
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
        "schema", "status", "baseline_trial", "candidate_trial", "workload", "host",
        "baseline_subject", "candidate_subject", "correctness", "metrics", "target",
        "content_sha256",
    }, "Stwo A/B comparison")
    _require(value["schema"] == COMPARISON_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "Stwo A/B comparison seal differs")
    baseline_path = Path(_identity(
        value["baseline_trial"], "Stwo A/B baseline trial", reopen=True,
    )["path"])
    candidate_path = Path(_identity(
        value["candidate_trial"], "Stwo A/B candidate trial", reopen=True,
    )["path"])
    _require(value == build_comparison(baseline_path, candidate_path),
             "Stwo A/B comparison replay differs")
    return value


def load_comparison(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "Stwo A/B comparison",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(raw == protocol.canonical_bytes(value),
             "Stwo A/B comparison is not canonical JSON")
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
        store.require_directory(output.parent, "Stwo A/B output parent")
        store.require_directory(staging, "Stwo A/B staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(result), staging_directory=staging,
        )
        return 0
    except (StwoComparisonError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
