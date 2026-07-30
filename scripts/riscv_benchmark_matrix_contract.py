"""Fail-closed evidence contract for ``riscv_benchmark_matrix_v2``."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from scripts.riscv_benchmark_matrix_model import FULL_COUNTS


SCHEMA = "riscv_benchmark_matrix_v2"
EVIDENCE_CLASS = "staged_diagnostic"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ROW_CLASSES = frozenset(FULL_COUNTS)
ROOT_FIELDS = {
    "schema", "generated_at", "status", "evidence_class", "promotion_eligible",
    "duration_ns", "candidate", "oracle", "fixtures", "protocol", "metal",
    "host_environment", "timing_policy", "selection", "artifact_root", "rows",
    "summary",
}
ROW_FIELDS = {
    "id", "suite", "class", "status", "fixture", "metal", "oracle_semantics",
    "candidate_semantics", "semantic_parity", "timing", "proof", "rejection",
    "error",
}
SEMANTIC_FIELDS = (
    "initial_pc", "final_pc", "clock", "initial_regs", "final_regs",
    "reg_last_clock", "program_root", "initial_rw_root", "final_rw_root",
    "io_entries",
)
METAL_GATE = {
    "status": "gated",
    "reason": "riscv_adapter_cpu_only_and_stark_v_has_no_riscv_metal_prover",
}
FUNCTIONAL_PROTOCOL = {
    "name": "functional",
    "candidate": {
        "pow_bits": 10,
        "fri": {
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 3,
            "fold_step": 1,
        },
    },
    "stark_v": {
        "constructor": "PcsConfig::default()",
        "pow_bits": 10,
        "fri": {
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 3,
            "fold_step": 1,
        },
    },
    "matched": True,
}
EXPECTED_REJECTION_STDERR = (
    "stark-v adapter: error=UnsupportedProofFamily "
    "stage=statement_validation_before_first_commitment "
    "limitation=stark-v-signed-mulh\n"
).encode()


class MatrixContractError(ValueError):
    pass


def strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise MatrixContractError(f"{label}: duplicate JSON field {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixContractError(f"{label}: invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise MatrixContractError(f"{label}: root must be an object")
    return value


def strict_json_file(path: Path, label: str, maximum: int = 512 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise MatrixContractError(f"{label}: missing, symlinked, empty, or oversized")
    return strict_json_bytes(path.read_bytes(), label)


def exact_fields(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MatrixContractError(f"{label}: must be an object")
    actual = set(value)
    if actual != fields:
        raise MatrixContractError(
            f"{label}: fields drifted; missing={sorted(fields - actual)} "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise MatrixContractError(f"{label}: must be a lowercase SHA-256")
    return value


def require_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise MatrixContractError(f"{label}: must be a positive integer")
    return value


def require_finite_positive(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MatrixContractError(f"{label}: must be numeric")
    rendered = float(value)
    if not math.isfinite(rendered) or rendered <= 0:
        raise MatrixContractError(f"{label}: must be finite and positive")
    return rendered


def _validate_identity_file(value: object, label: str) -> None:
    item = exact_fields(value, {"path", "sha256", "size_bytes"}, label)
    if not isinstance(item["path"], str) or not item["path"]:
        raise MatrixContractError(f"{label}.path: must be nonempty")
    require_sha256(item["sha256"], f"{label}.sha256")
    require_positive_int(item["size_bytes"], f"{label}.size_bytes")


def _validate_candidate(value: object) -> None:
    candidate = exact_fields(value, {
        "repository", "commit", "git_tree", "dirty", "worktree_identity_sha256",
        "git_status_sha256", "git_diff_sha256", "untracked_files", "executables",
    }, "report.candidate")
    if candidate["repository"] != "https://github.com/teddyjfpender/stwo-zig":
        raise MatrixContractError("report.candidate.repository drifted")
    for field in ("commit", "git_tree"):
        if not isinstance(candidate[field], str) or re.fullmatch(r"[0-9a-f]{40,64}", candidate[field]) is None:
            raise MatrixContractError(f"report.candidate.{field}: invalid Git object")
    if type(candidate["dirty"]) is not bool:
        raise MatrixContractError("report.candidate.dirty: invalid")
    for field in ("worktree_identity_sha256", "git_status_sha256", "git_diff_sha256"):
        require_sha256(candidate[field], f"report.candidate.{field}")
    untracked = candidate["untracked_files"]
    if not isinstance(untracked, list):
        raise MatrixContractError("report.candidate.untracked_files: invalid")
    for index, item in enumerate(untracked):
        item = exact_fields(item, {"path", "sha256"}, f"report.candidate.untracked_files[{index}]")
        if not isinstance(item["path"], str) or not item["path"]:
            raise MatrixContractError(f"report.candidate.untracked_files[{index}].path: invalid")
        require_sha256(item["sha256"], f"report.candidate.untracked_files[{index}].sha256")
    executables = exact_fields(
        candidate["executables"], {"riscv_cpu", "trace_dump"},
        "report.candidate.executables",
    )
    for name in executables:
        _validate_identity_file(executables[name], f"report.candidate.executables.{name}")


def _validate_oracle(value: object) -> None:
    oracle = exact_fields(value, {"correctness", "timing"}, "report.oracle")
    correctness = exact_fields(oracle["correctness"], {
        "repository", "commit", "clean", "tree_digest_sha256", "submodule_status",
        "lockfile_sha256", "toolchain", "build_command", "build_mode",
        "adapter_overlay", "executable_sha256", "host_arch", "host_os",
        "build_cache", "executable",
    }, "report.oracle.correctness")
    if (
        correctness["repository"] != "https://github.com/ClementWalter/stark-v"
        or correctness["commit"] != "d478f783055aa0d73a93768a433a3c6c31c91d1c"
        or correctness["clean"] is not True
        or correctness["build_mode"] != "release"
    ):
        raise MatrixContractError("report.oracle.correctness identity drifted")
    for field in ("tree_digest_sha256", "lockfile_sha256", "executable_sha256"):
        require_sha256(correctness[field], f"report.oracle.correctness.{field}")
    _validate_identity_file(correctness["executable"], "report.oracle.correctness.executable")
    if correctness["executable"]["sha256"] != correctness["executable_sha256"]:
        raise MatrixContractError("report.oracle.correctness executable digest drifted")
    if not isinstance(correctness["submodule_status"], list):
        raise MatrixContractError("report.oracle.correctness.submodule_status: invalid")
    cache = exact_fields(correctness["build_cache"], {
        "schema", "status", "key_sha256", "manifest_sha256", "verification",
    }, "report.oracle.correctness.build_cache")
    if cache["schema"] != "riscv-stark-v-oracle-build-cache-v1" or cache["status"] not in ("hit", "miss"):
        raise MatrixContractError("report.oracle.correctness.build_cache identity drifted")
    require_sha256(cache["key_sha256"], "report.oracle.correctness.build_cache.key_sha256")
    require_sha256(cache["manifest_sha256"], "report.oracle.correctness.build_cache.manifest_sha256")

    timing = exact_fields(oracle["timing"], {
        "repository", "commit", "source_build_identity_sha256", "source_build_identity",
        "build_command", "features", "build_duration_ns", "build_stdout",
        "build_stderr", "executable",
    }, "report.oracle.timing")
    if (
        timing["repository"] != correctness["repository"]
        or timing["commit"] != correctness["commit"]
        or timing["build_command"] != [
            "cargo", "build", "--locked", "--release", "-p", "bench-cli",
            "--features", "parallel",
        ]
        or timing["features"] != ["parallel"]
    ):
        raise MatrixContractError("report.oracle.timing build identity drifted")
    require_positive_int(timing["build_duration_ns"], "report.oracle.timing.build_duration_ns")
    for stream in ("build_stdout", "build_stderr"):
        sidecar = exact_fields(
            timing[stream], {"path", "sha256", "size_bytes"},
            f"report.oracle.timing.{stream}",
        )
        if not isinstance(sidecar["path"], str) or not sidecar["path"]:
            raise MatrixContractError(f"report.oracle.timing.{stream}.path: invalid")
        require_sha256(sidecar["sha256"], f"report.oracle.timing.{stream}.sha256")
        if type(sidecar["size_bytes"]) is not int or sidecar["size_bytes"] < 0:
            raise MatrixContractError(f"report.oracle.timing.{stream}.size_bytes: invalid")
    require_sha256(timing["source_build_identity_sha256"], "report.oracle.timing.source_build_identity_sha256")
    if not isinstance(timing["source_build_identity"], dict):
        raise MatrixContractError("report.oracle.timing.source_build_identity: invalid")
    encoded = (
        json.dumps(timing["source_build_identity"], sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if hashlib.sha256(encoded).hexdigest() != timing["source_build_identity_sha256"]:
        raise MatrixContractError("report.oracle.timing source identity digest drifted")
    _validate_identity_file(timing["executable"], "report.oracle.timing.executable")


def _validate_fixtures(value: object) -> None:
    fixtures = exact_fields(
        value, {"trace_manifest", "crypto_provenance", "row_set_sha256"},
        "report.fixtures",
    )
    for name in ("trace_manifest", "crypto_provenance"):
        item = exact_fields(fixtures[name], {"path", "sha256"}, f"report.fixtures.{name}")
        if not isinstance(item["path"], str) or not item["path"]:
            raise MatrixContractError(f"report.fixtures.{name}.path: invalid")
        require_sha256(item["sha256"], f"report.fixtures.{name}.sha256")
    require_sha256(fixtures["row_set_sha256"], "report.fixtures.row_set_sha256")


def _validate_command_sample(value: object, label: str, *, measured: bool) -> None:
    sample = exact_fields(value, {
        "iteration", "warmup", "order_position", "duration_ns", "cpu_time_ns",
        "cpu_wall_ratio", "cycles", "phases_seconds", "stdout", "stderr", "argv",
        "evidence",
    }, label)
    if type(sample["iteration"]) is not int or sample["iteration"] < 0:
        raise MatrixContractError(f"{label}.iteration: invalid")
    if sample["warmup"] is measured or type(sample["warmup"]) is not bool:
        raise MatrixContractError(f"{label}.warmup: sample accounting drifted")
    if sample["order_position"] not in (0, 1):
        raise MatrixContractError(f"{label}.order_position: invalid")
    if (
        not isinstance(sample["argv"], list)
        or not sample["argv"]
        or any(not isinstance(argument, str) or not argument for argument in sample["argv"])
    ):
        raise MatrixContractError(f"{label}.argv: invalid")
    require_positive_int(sample["duration_ns"], f"{label}.duration_ns")
    if type(sample["cpu_time_ns"]) is not int or sample["cpu_time_ns"] < 0:
        raise MatrixContractError(f"{label}.cpu_time_ns: invalid")
    require_finite_positive(sample["cpu_wall_ratio"], f"{label}.cpu_wall_ratio")
    if type(sample["cycles"]) is not int or sample["cycles"] <= 0:
        raise MatrixContractError(f"{label}.cycles: missing or invalid")
    phases = sample["phases_seconds"]
    if not isinstance(phases, dict) or not phases:
        raise MatrixContractError(f"{label}.phases_seconds: missing")
    for phase, seconds in phases.items():
        if not isinstance(phase, str) or not phase:
            raise MatrixContractError(f"{label}.phases_seconds: invalid key")
        require_finite_positive(seconds, f"{label}.phases_seconds.{phase}")
    for stream in ("stdout", "stderr"):
        sidecar = exact_fields(sample[stream], {"path", "sha256", "size_bytes"}, f"{label}.{stream}")
        if not isinstance(sidecar["path"], str) or not sidecar["path"]:
            raise MatrixContractError(f"{label}.{stream}.path: invalid")
        require_sha256(sidecar["sha256"], f"{label}.{stream}.sha256")
        if type(sidecar["size_bytes"]) is not int or sidecar["size_bytes"] < 0:
            raise MatrixContractError(f"{label}.{stream}.size_bytes: invalid")
    if sample["evidence"] is not None:
        _validate_identity_file(sample["evidence"], f"{label}.evidence")


def _validate_timing(value: object, row_class: str, label: str) -> None:
    timing = exact_fields(value, {
        "mode", "clock", "warmups", "samples", "pair_orders", "candidate",
        "stark_v", "summary",
    }, label)
    expected_mode = "prove_verify" if row_class == "proof" else "execution"
    if timing["mode"] != expected_mode or timing["clock"] != "time.monotonic_ns":
        raise MatrixContractError(f"{label}: timing mode/clock drifted")
    if type(timing["warmups"]) is not int or not 0 <= timing["warmups"] <= 10:
        raise MatrixContractError(f"{label}.warmups: invalid")
    if type(timing["samples"]) is not int or not 1 <= timing["samples"] <= 21:
        raise MatrixContractError(f"{label}.samples: invalid")
    total = timing["warmups"] + timing["samples"]
    orders = timing["pair_orders"]
    if not isinstance(orders, list) or len(orders) != total:
        raise MatrixContractError(f"{label}.pair_orders: sample accounting drifted")
    for order in orders:
        if order not in (["candidate", "stark_v"], ["stark_v", "candidate"]):
            raise MatrixContractError(f"{label}.pair_orders: invalid order")
    for lane in ("candidate", "stark_v"):
        samples = timing[lane]
        if not isinstance(samples, list) or len(samples) != total:
            raise MatrixContractError(f"{label}.{lane}: sample accounting drifted")
        for index, sample in enumerate(samples):
            _validate_command_sample(
                sample,
                f"{label}.{lane}[{index}]",
                measured=index >= timing["warmups"],
            )
            if sample["iteration"] != index:
                raise MatrixContractError(f"{label}.{lane}[{index}]: iteration drifted")
            if sample["order_position"] != orders[index].index(lane):
                raise MatrixContractError(f"{label}.{lane}[{index}]: order drifted")
    summary = exact_fields(timing["summary"], {
        "candidate_median_seconds", "stark_v_median_seconds",
        "candidate_over_stark_v", "stark_v_median_cpu_wall_ratio",
    }, f"{label}.summary")
    for field in summary:
        require_finite_positive(summary[field], f"{label}.summary.{field}")


def _validate_semantics(value: object, label: str) -> None:
    semantics = exact_fields(value, {
        "total_steps", "final_pc", "final_regs_sha256", "public_data_sha256",
        "source", "duration_ns",
    }, label)
    require_positive_int(semantics["total_steps"], f"{label}.total_steps")
    if type(semantics["final_pc"]) is not int or not 0 <= semantics["final_pc"] <= 0xFFFFFFFF:
        raise MatrixContractError(f"{label}.final_pc: invalid")
    require_sha256(semantics["final_regs_sha256"], f"{label}.final_regs_sha256")
    require_sha256(semantics["public_data_sha256"], f"{label}.public_data_sha256")
    _validate_identity_file(semantics["source"], f"{label}.source")
    require_positive_int(semantics["duration_ns"], f"{label}.duration_ns")


def validate_row(row: object, label: str = "row") -> None:
    item = exact_fields(row, ROW_FIELDS, label)
    if not isinstance(item["id"], str) or not item["id"]:
        raise MatrixContractError(f"{label}.id: invalid")
    if item["suite"] not in ("corpus", "crypto") or item["class"] not in ROW_CLASSES:
        raise MatrixContractError(f"{label}: suite/class invalid")
    if item["metal"] != {
        "status": "gated",
        "reason": "riscv_adapter_cpu_only_and_stark_v_has_no_riscv_metal_prover",
    }:
        raise MatrixContractError(f"{label}.metal: gate drifted")
    if not isinstance(item["fixture"], dict):
        raise MatrixContractError(f"{label}.fixture: invalid")
    require_sha256(item["fixture"].get("elf_sha256"), f"{label}.fixture.elf_sha256")
    require_sha256(item["fixture"].get("input_sha256"), f"{label}.fixture.input_sha256")
    if item["status"] == "failed":
        if not isinstance(item["error"], str) or not item["error"]:
            raise MatrixContractError(f"{label}: failed row lacks an error")
        return
    if item["status"] != "ok" or item["error"] is not None:
        raise MatrixContractError(f"{label}: status/error invalid")
    _validate_semantics(item["oracle_semantics"], f"{label}.oracle_semantics")
    _validate_semantics(item["candidate_semantics"], f"{label}.candidate_semantics")
    parity = exact_fields(
        item["semantic_parity"],
        {"status", "fields", "mismatches", "public_data_sha256"},
        f"{label}.semantic_parity",
    )
    if (
        parity["status"] != "pass"
        or parity["fields"] != list(SEMANTIC_FIELDS)
        or parity["mismatches"] != []
    ):
        raise MatrixContractError(
            f"{label}: legacy benchmark execution parity did not pass"
        )
    require_sha256(parity["public_data_sha256"], f"{label}.semantic_parity.public_data_sha256")
    if not (
        item["oracle_semantics"]["public_data_sha256"]
        == item["candidate_semantics"]["public_data_sha256"]
        == parity["public_data_sha256"]
    ):
        raise MatrixContractError(f"{label}: semantic digest parity drifted")
    _validate_timing(item["timing"], item["class"], f"{label}.timing")
    if item["class"] == "proof":
        proof = exact_fields(item["proof"], {
            "artifact", "benchmark_report", "verification_receipt", "statement_sha256",
            "transcript_state_blake2s", "witness_layout_sha256", "verified",
        }, f"{label}.proof")
        for field in ("artifact", "benchmark_report", "verification_receipt"):
            _validate_identity_file(proof[field], f"{label}.proof.{field}")
        for field in ("statement_sha256", "transcript_state_blake2s", "witness_layout_sha256"):
            require_sha256(proof[field], f"{label}.proof.{field}")
        if proof["verified"] is not True or item["rejection"] is not None:
            raise MatrixContractError(f"{label}: proof evidence drifted")
    elif item["class"] == "expected_rejection":
        rejection = exact_fields(item["rejection"], {
            "status", "error", "stage", "limitation", "returncode", "stdout_empty",
            "stderr_exact", "proof_artifact_published", "report_published",
            "temporary_residue", "duration_ns", "stdout", "stderr",
        }, f"{label}.rejection")
        if rejection != {
            **rejection,
            "status": "pass",
            "error": "UnsupportedProofFamily",
            "stage": "statement_validation_before_first_commitment",
            "limitation": "stark-v-signed-mulh",
            "returncode": 1,
            "stdout_empty": True,
            "stderr_exact": True,
            "proof_artifact_published": False,
            "report_published": False,
            "temporary_residue": [],
        }:
            raise MatrixContractError(f"{label}: typed precommit rejection drifted")
        require_positive_int(rejection["duration_ns"], f"{label}.rejection.duration_ns")
        for stream in ("stdout", "stderr"):
            sidecar = rejection[stream]
            exact_fields(sidecar, {"path", "sha256", "size_bytes"}, f"{label}.rejection.{stream}")
            require_sha256(sidecar["sha256"], f"{label}.rejection.{stream}.sha256")
        if rejection["stdout"]["sha256"] != hashlib.sha256(b"").hexdigest() or \
                rejection["stdout"]["size_bytes"] != 0:
            raise MatrixContractError(f"{label}: rejection stdout evidence differs")
        if rejection["stderr"]["sha256"] != hashlib.sha256(EXPECTED_REJECTION_STDERR).hexdigest() or \
                rejection["stderr"]["size_bytes"] != len(EXPECTED_REJECTION_STDERR):
            raise MatrixContractError(f"{label}: rejection stderr evidence differs")
        if item["proof"] is not None:
            raise MatrixContractError(f"{label}: rejection row published proof evidence")
    elif item["proof"] is not None or item["rejection"] is not None:
        raise MatrixContractError(f"{label}: execution row has proof/rejection evidence")


def validate_report(
    report: object,
    *,
    expected_row_ids: list[str] | None = None,
    require_complete: bool = False,
) -> None:
    root = exact_fields(report, ROOT_FIELDS, "report")
    if root["schema"] != SCHEMA:
        raise MatrixContractError("report schema drifted")
    if root["evidence_class"] != EVIDENCE_CLASS or root["promotion_eligible"] is not False:
        raise MatrixContractError("RISC-V matrix must remain staged and non-promotable")
    require_positive_int(root["duration_ns"], "report.duration_ns")
    if not isinstance(root["generated_at"], str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", root["generated_at"],
    ) is None:
        raise MatrixContractError("report.generated_at: invalid UTC timestamp")
    _validate_candidate(root["candidate"])
    _validate_oracle(root["oracle"])
    _validate_fixtures(root["fixtures"])
    if root["protocol"] != FUNCTIONAL_PROTOCOL:
        raise MatrixContractError("report.protocol: functional PCS contract drifted")
    if root["metal"] != METAL_GATE:
        raise MatrixContractError("report.metal: RISC-V Metal gate drifted")
    host = exact_fields(root["host_environment"], {
        "schema", "platform", "hardware", "toolchain", "stark_v_commit",
    }, "report.host_environment")
    if host["schema"] != "riscv_benchmark_host_environment_v1":
        raise MatrixContractError("report.host_environment schema drifted")
    if host["stark_v_commit"] != "d478f783055aa0d73a93768a433a3c6c31c91d1c":
        raise MatrixContractError("report.host_environment Stark-V identity drifted")
    policy = exact_fields(root["timing_policy"], {
        "clock", "pairing", "candidate_proof_sampling", "stark_v_phase_source",
        "warmups_excluded_from_summary", "rust_feature_required",
        "min_stark_v_cpu_wall_ratio_on_multicore_proof_rows", "environment",
    }, "report.timing_policy")
    if (
        policy["clock"] != "time.monotonic_ns"
        or policy["pairing"] != "alternating_candidate_and_stark_v_order_per_external_sample"
        or policy["candidate_proof_sampling"] != "one_verified_proof_per_external_sample"
        or policy["stark_v_phase_source"] != "bench_cli_tracing_timestamps"
        or policy["warmups_excluded_from_summary"] is not True
        or policy["rust_feature_required"] != "parallel"
        or policy["environment"] != {"stark_v": {"RUST_LOG": "info"}, "candidate": "inherited"}
    ):
        raise MatrixContractError("report.timing_policy drifted")
    require_finite_positive(
        policy["min_stark_v_cpu_wall_ratio_on_multicore_proof_rows"],
        "report.timing_policy.min_stark_v_cpu_wall_ratio_on_multicore_proof_rows",
    )
    if not isinstance(root["artifact_root"], str) or not root["artifact_root"]:
        raise MatrixContractError("report.artifact_root: invalid")
    selection = exact_fields(root["selection"], {
        "mode", "complete", "expected_full_counts", "selected_counts",
        "expected_full_row_count", "selected_row_count", "row_ids",
    }, "report.selection")
    if selection["expected_full_counts"] != FULL_COUNTS:
        raise MatrixContractError("report.selection expected counts drifted")
    if selection["expected_full_row_count"] != sum(FULL_COUNTS.values()):
        raise MatrixContractError("report.selection expected row count drifted")
    rows = root["rows"]
    if not isinstance(rows, list) or not rows:
        raise MatrixContractError("report.rows must be nonempty")
    row_ids = [row.get("id") if isinstance(row, dict) else None for row in rows]
    if len(row_ids) != len(set(row_ids)) or row_ids != selection["row_ids"]:
        raise MatrixContractError("report row IDs are duplicate or differ from selection")
    if expected_row_ids is not None and row_ids != expected_row_ids:
        raise MatrixContractError("report row set differs from expected fixtures")
    counts = dict(Counter(row.get("class") for row in rows if isinstance(row, dict)))
    selected_counts = {name: counts.get(name, 0) for name in FULL_COUNTS}
    if selected_counts != selection["selected_counts"] or len(rows) != selection["selected_row_count"]:
        raise MatrixContractError("report selection counts drifted")
    complete = selected_counts == FULL_COUNTS and len(rows) == sum(FULL_COUNTS.values())
    if selection["complete"] is not complete or selection["mode"] != ("full" if complete else "filtered"):
        raise MatrixContractError("report selection completeness drifted")
    if require_complete and not complete:
        raise MatrixContractError("report is filtered; full 32-row evidence is required")
    for index, row in enumerate(rows):
        validate_row(row, f"report.rows[{index}]")
    failures = sum(row["status"] == "failed" for row in rows)
    summary = exact_fields(root["summary"], {
        "row_count", "ok_count", "failure_count", "class_counts",
    }, "report.summary")
    if summary != {
        "row_count": len(rows),
        "ok_count": len(rows) - failures,
        "failure_count": failures,
        "class_counts": selected_counts,
    }:
        raise MatrixContractError("report summary drifted")
    expected_status = "PASS" if failures == 0 else "FAIL"
    if root["status"] != expected_status:
        raise MatrixContractError("report status does not match row outcomes")


def validate_artifact_tree(report: Mapping[str, Any], artifact_root: Path | None = None) -> None:
    """Rehash every relative ``{path, sha256, size_bytes}`` evidence reference."""
    root_input = artifact_root or Path(str(report.get("artifact_root", "")))
    if root_input.is_symlink() or not root_input.is_dir():
        raise MatrixContractError(f"artifact root is missing or symlinked: {root_input}")
    root = root_input.resolve()

    identities: list[tuple[str, Mapping[str, Any]]] = []

    def visit(value: object, label: str) -> None:
        if isinstance(value, Mapping):
            if set(value) == {"path", "sha256", "size_bytes"}:
                identities.append((label, value))
            for key, item in value.items():
                visit(item, f"{label}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{label}[{index}]")

    visit(report, "report")
    checked = 0
    for label, identity in identities:
        raw_path = identity["path"]
        if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute():
            continue
        candidate = root / raw_path
        if candidate.is_symlink():
            raise MatrixContractError(f"{label}: referenced artifact is symlinked")
        path = candidate.resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise MatrixContractError(f"{label}.path escapes artifact root") from error
        if path.is_symlink() or not path.is_file():
            raise MatrixContractError(f"{label}: referenced artifact is missing or symlinked")
        raw = path.read_bytes()
        if len(raw) != identity["size_bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
            raise MatrixContractError(f"{label}: referenced artifact digest/size differs")
        checked += 1
    if checked == 0:
        raise MatrixContractError("report does not reference any artifact-tree evidence")
