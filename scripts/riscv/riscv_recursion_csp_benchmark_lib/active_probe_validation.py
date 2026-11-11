"""Fail-closed replay validation for active recursive outer probes."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from .active_probe import (
    ACTIVE_PROBE_CLASSIFICATION,
    ACTIVE_PROBE_SCHEMA,
    PROBE_ATTEMPT_KEYS,
    PROBE_INVOCATION_KEYS,
    PROBE_KEYS,
    PROBE_REPOSITORY_KEYS,
    PROBE_SAMPLING_KEYS,
    PROBE_SOURCE_KEYS,
    PROBE_SOURCE_PATHS,
    PROBE_SUMMARY_KEYS,
    _mean,
    parse_active_outer_output,
)
from .codec import EvidenceError, sha256_bytes, verify_document_seal
from .contract import (
    MAX_SAMPLES,
    SCHEMA_VERSION,
    exact_object,
    expect_commit,
    expect_digest,
    expect_positive_int,
)


def _validate_observation(value: Any, label: str, workers: int) -> dict[str, Any]:
    observation = exact_object(
        value,
        {
            "base",
            "outer",
            "roster",
            "canonical_recursive_artifact_available",
            "canonical_recursive_artifact_unavailable_reason",
            "ethproof_csp_workload",
        },
        label,
    )
    base = exact_object(
        observation["base"],
        {
            "proof_estimate",
            "postcard_bytes",
            "prove_ns",
            "serialize_ns",
            "ingress_ns",
            "decode_ns",
            "verify_ns",
            "total_ns",
            "peak_bytes",
            "cpu_ns",
            "energy_nj",
            "instructions",
            "cycles",
        },
        f"{label}.base",
    )
    for key, item in base.items():
        expect_positive_int(
            item,
            f"{label}.base.{key}",
            allow_zero=key
            in {"peak_bytes", "cpu_ns", "energy_nj", "instructions", "cycles"},
        )
    outer = exact_object(
        observation["outer"],
        {
            "preprocessed",
            "main",
            "interaction",
            "constraints",
            "proof_estimate",
            "prove_ns",
            "assembly_ns",
            "stark_prove_ns",
            "verify_ns",
            "poseidon_calls",
            "workers",
            "draws",
            "mutations",
            "mutation_total",
            "log_sizes",
        },
        f"{label}.outer",
    )
    for key, item in outer.items():
        if key == "log_sizes":
            if (
                type(item) is not list
                or len(item) != 17
                or any(type(log_size) is not int or log_size <= 0 for log_size in item)
            ):
                raise EvidenceError(f"{label}.outer.log_sizes is invalid")
        else:
            expect_positive_int(item, f"{label}.outer.{key}")
    if outer["workers"] != workers:
        raise EvidenceError(f"{label}.outer.workers differs from the invocation")
    if outer["mutations"] != 5 or outer["mutation_total"] != 5:
        raise EvidenceError(f"{label}.outer mutation fleet is incomplete")
    if outer["prove_ns"] < outer["assembly_ns"] + outer["stark_prove_ns"]:
        raise EvidenceError(f"{label}.outer prove timing partition is impossible")
    roster = exact_object(
        observation["roster"],
        {"roster", "verifier", "provider"},
        f"{label}.roster",
    )
    if roster != {"roster": 36, "verifier": 34, "provider": 2}:
        raise EvidenceError(f"{label}.roster is incomplete")
    if (
        observation["canonical_recursive_artifact_available"] is not False
        or type(observation["canonical_recursive_artifact_unavailable_reason"]) is not str
        or not observation["canonical_recursive_artifact_unavailable_reason"]
        or observation["ethproof_csp_workload"] is not False
    ):
        raise EvidenceError(f"{label} overstates the active gate evidence")
    return observation


def validate_active_outer_probe(
    probe: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a sealed active-gate observation without promoting it to CSP evidence."""

    exact_object(probe, PROBE_KEYS, "active outer probe")
    if (
        probe["schema"] != ACTIVE_PROBE_SCHEMA
        or probe["schema_version"] != SCHEMA_VERSION
        or probe["classification"] != ACTIVE_PROBE_CLASSIFICATION
        or probe["comparison_eligible"] is not False
    ):
        raise EvidenceError("active outer probe schema/classification drifted")
    verify_document_seal(probe, label="active outer probe")
    expect_digest(probe["plan_digest"], "active outer probe.plan_digest")
    expect_digest(probe["cohort_id"], "active outer probe.cohort_id")
    if plan is not None and (
        probe["plan_digest"] != plan["canonical_digest"]
        or probe["cohort_id"] != plan["cohort_id"]
    ):
        raise EvidenceError("active outer probe is bound to a different plan")
    captured_at = probe["captured_at"]
    if type(captured_at) is not str:
        raise EvidenceError("active outer probe captured_at is missing")
    try:
        captured = dt.datetime.fromisoformat(captured_at)
    except ValueError as error:
        raise EvidenceError("active outer probe captured_at is not ISO-8601") from error
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise EvidenceError("active outer probe captured_at must include a UTC offset")
    repository = exact_object(
        probe["repository"],
        PROBE_REPOSITORY_KEYS,
        "active outer probe.repository",
    )
    expect_commit(repository["head"], "active outer probe.repository.head")
    if type(repository["implementation_dirty"]) is not bool:
        raise EvidenceError("active outer probe repository dirty state is invalid")
    for key in (
        "status_sha256",
        "tracked_diff_sha256",
        "source_manifest_sha256",
    ):
        expect_digest(repository[key], f"active outer probe.repository.{key}")
    expect_positive_int(
        repository["source_file_count"],
        "active outer probe.repository.source_file_count",
    )
    sources = repository["source_evidence"]
    if type(sources) is not list or len(sources) != len(PROBE_SOURCE_PATHS):
        raise EvidenceError("active outer probe source evidence inventory is incomplete")
    for index, (raw_source, expected_path) in enumerate(zip(sources, PROBE_SOURCE_PATHS)):
        source = exact_object(
            raw_source,
            PROBE_SOURCE_KEYS,
            f"active outer probe.repository.source_evidence[{index}]",
        )
        if source["path"] != expected_path.as_posix():
            raise EvidenceError("active outer probe source evidence order drifted")
        expect_digest(source["sha256"], f"active outer probe source {expected_path}")

    invocation = exact_object(
        probe["invocation"],
        PROBE_INVOCATION_KEYS,
        "active outer probe.invocation",
    )
    argv = invocation["argv"]
    if (
        type(argv) is not list
        or len(argv) != 4
        or argv[1:]
        != [
            "build",
            "test-riscv-recursion-poseidon-leaf",
            "-Doptimize=ReleaseFast",
        ]
        or type(argv[0]) is not str
        or not Path(argv[0]).is_absolute()
    ):
        raise EvidenceError("active outer probe invocation drifted")
    if invocation["working_directory"] != ".":
        raise EvidenceError("active outer probe working directory drifted")
    expect_digest(
        invocation["zig_executable_sha256"],
        "active outer probe.invocation.zig_executable_sha256",
    )
    expect_positive_int(
        invocation["timeout_seconds"],
        "active outer probe.invocation.timeout_seconds",
    )
    environment = invocation["environment_overrides"]
    if (
        type(environment) is not dict
        or environment.get("STWO_RECURSION_ACTIVE_FRI_OUTER") != "1"
        or environment.get("NO_COLOR") != "1"
        or frozenset(environment)
        != {
            "STWO_RECURSION_ACTIVE_FRI_OUTER",
            "STWO_RECURSION_OUTER_WORKERS",
            "NO_COLOR",
        }
    ):
        raise EvidenceError("active outer probe environment overrides drifted")
    try:
        workers = int(environment["STWO_RECURSION_OUTER_WORKERS"])
    except (TypeError, ValueError) as error:
        raise EvidenceError("active outer probe worker override is invalid") from error
    if not 1 <= workers <= 32:
        raise EvidenceError("active outer probe worker override is outside bounds")
    sanitized = invocation["sanitized_environment_keys"]
    if type(sanitized) is not list or any(
        type(item) is not str or not item for item in sanitized
    ):
        raise EvidenceError("active outer probe sanitized environment inventory is invalid")

    sampling = exact_object(
        probe["sampling"],
        PROBE_SAMPLING_KEYS,
        "active outer probe.sampling",
    )
    warmups = expect_positive_int(
        sampling["warmups_excluded"],
        "active outer probe.sampling.warmups_excluded",
    )
    samples = expect_positive_int(
        sampling["measured_samples"],
        "active outer probe.sampling.measured_samples",
    )
    if (
        warmups > MAX_SAMPLES
        or not 3 <= samples <= MAX_SAMPLES
        or sampling["fresh_process_per_attempt"] is not True
        or sampling["automatic_retries"] != 0
        or sampling["outlier_drops"] != 0
    ):
        raise EvidenceError("active outer probe sampling contract drifted")
    if plan is not None and (
        warmups != plan["native_run"].get("warmups")
        or samples != plan["native_run"].get("samples")
    ):
        raise EvidenceError("active outer probe sampling differs from the plan")

    attempts = probe["attempts"]
    if type(attempts) is not list or not attempts or len(attempts) > warmups + samples:
        raise EvidenceError("active outer probe attempt inventory is invalid")
    measured: list[dict[str, Any]] = []
    unavailable_seen = False
    for ordinal, raw_attempt in enumerate(attempts):
        label = f"active outer probe.attempts[{ordinal}]"
        attempt = exact_object(raw_attempt, PROBE_ATTEMPT_KEYS, label)
        expected_classification = "excluded_warmup" if ordinal < warmups else "measured"
        if attempt["ordinal"] != ordinal or attempt["classification"] != expected_classification:
            raise EvidenceError(f"{label} schedule drifted")
        if type(attempt["return_code"]) is not int or type(attempt["timed_out"]) is not bool:
            raise EvidenceError(f"{label} process result is invalid")
        expect_positive_int(attempt["command_wall_ns"], f"{label}.command_wall_ns")
        expect_digest(attempt["combined_log_sha256"], f"{label}.combined_log_sha256")
        expect_positive_int(
            attempt["combined_log_bytes"],
            f"{label}.combined_log_bytes",
            allow_zero=True,
        )
        if attempt["status"] == "verified":
            if (
                unavailable_seen
                or attempt["return_code"] != 0
                or attempt["timed_out"] is not False
                or attempt["reason"] is not None
                or attempt["diagnostic_tail"] is not None
                or type(attempt["combined_log_utf8"]) is not str
                or not attempt["combined_log_utf8"]
            ):
                raise EvidenceError(f"{label} verified process result is contradictory")
            encoded_log = attempt["combined_log_utf8"].encode("utf-8")
            if (
                len(encoded_log) != attempt["combined_log_bytes"]
                or sha256_bytes(encoded_log) != attempt["combined_log_sha256"]
            ):
                raise EvidenceError(f"{label} retained log identity drifted")
            reparsed = parse_active_outer_output(
                encoded_log,
                requested_workers=workers,
            )
            observation = _validate_observation(
                attempt["observation"],
                f"{label}.observation",
                workers,
            )
            if observation != reparsed:
                raise EvidenceError(f"{label} observation differs from its retained log")
            if expected_classification == "measured":
                measured.append(attempt)
        elif attempt["status"] == "unavailable":
            if unavailable_seen or ordinal != len(attempts) - 1:
                raise EvidenceError(f"{label} must be the terminal first failure")
            unavailable_seen = True
            if (
                attempt["observation"] is not None
                or attempt["combined_log_utf8"] is not None
                or type(attempt["reason"]) is not str
                or not attempt["reason"]
                or type(attempt["diagnostic_tail"]) is not str
            ):
                raise EvidenceError(f"{label} unavailable result is contradictory")
        else:
            raise EvidenceError(f"{label}.status is unsupported")

    status = probe["status"]
    if status == "verified_non_csp_probe":
        if (
            unavailable_seen
            or len(attempts) != warmups + samples
            or len(measured) != samples
            or probe["unavailable_reason"] is not None
        ):
            raise EvidenceError("active outer verified status contradicts its attempts")
        summary = exact_object(
            probe["summary"],
            PROBE_SUMMARY_KEYS,
            "active outer probe.summary",
        )
        for key, item in summary.items():
            if key in {"canonical_recursive_proof_bytes", "peak_rss_bytes"}:
                if item is not None:
                    raise EvidenceError(f"active outer probe.summary.{key} must be unavailable")
            else:
                expect_positive_int(item, f"active outer probe.summary.{key}")
        observations = [attempt["observation"] for attempt in measured]
        expected_means = {
            "base_prove_ns": [item["base"]["prove_ns"] for item in observations],
            "base_verify_ns": [item["base"]["verify_ns"] for item in observations],
            "outer_prove_ns": [item["outer"]["prove_ns"] for item in observations],
            "outer_assembly_ns": [item["outer"]["assembly_ns"] for item in observations],
            "outer_stark_prove_ns": [
                item["outer"]["stark_prove_ns"] for item in observations
            ],
            "outer_verify_ns": [item["outer"]["verify_ns"] for item in observations],
            "command_wall_ns": [attempt["command_wall_ns"] for attempt in measured],
        }
        for key, values in expected_means.items():
            if summary[key] != _mean(values):
                raise EvidenceError(f"active outer probe.summary.{key} mean drifted")
        for summary_key, observation_key in (
            ("outer_poseidon2_permutations", "poseidon_calls"),
            ("outer_proof_size_estimate_bytes", "proof_estimate"),
        ):
            values = {item["outer"][observation_key] for item in observations}
            if len(values) != 1 or summary[summary_key] != next(iter(values)):
                raise EvidenceError(f"active outer probe.summary.{summary_key} drifted")
    elif status == "unavailable":
        if (
            not unavailable_seen
            or probe["summary"] is not None
            or type(probe["unavailable_reason"]) is not str
            or not probe["unavailable_reason"]
            or probe["unavailable_reason"] != attempts[-1]["reason"]
        ):
            raise EvidenceError("active outer unavailable status contradicts its attempts")
    else:
        raise EvidenceError("active outer probe status is unsupported")
    if type(probe["limitations"]) is not list or not probe["limitations"] or any(
        type(item) is not str or not item for item in probe["limitations"]
    ):
        raise EvidenceError("active outer probe limitations are invalid")
    return probe
