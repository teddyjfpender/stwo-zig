"""Fail-closed BA-03 activation checks for an autoresearch board."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


SETTINGS_SCHEMA = "autoresearch_github_settings_receipt_v2"
REQUIRED_WORKFLOWS = {
    ".github/workflows/judge.yml": "autoresearch-judge",
    ".github/workflows/promote.yml": "autoresearch-promote",
}
REQUIRED_CHECKS = frozenset({"autoresearch-validate", "autoresearch-judge"})
RISCV_SAIL_COMMIT = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
RISCV_STARK_V_BENCHMARK_COMMIT = "d478f783055aa0d73a93768a433a3c6c31c91d1c"
RISCV_REPORT_SCHEMA = "riscv_proof_v2"
RISCV_CALIBRATION_SCHEMA = "stwo_perf_riscv_calibration_freeze_v1"
RISCV_RESOURCE_TELEMETRY = {
    "fail_closed": True,
    "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
    "scope": "self_process_lifetime",
    "sampling_points": ["before_warmups", "after_verified_samples"],
    "fields": [
        "lifetime_max_phys_footprint_bytes", "energy_nj", "instructions", "cycles",
    ],
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_ACTIONS_INTEGRATION_ID = 15368
AUTORESEARCH_PUBLISH_DEPLOY_KEY_ID = 157962927
AUTORESEARCH_PUBLISH_DEPLOY_KEY_TITLE = "autoresearch-publisher"
APPROVED_BYPASS_ACTORS = frozenset({
    (None, "DeployKey", "always"),
})


class ActivationError(ValueError):
    """Activation evidence is malformed or incomplete."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _positive(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationError(f"{label} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ActivationError(f"{label} must be a JSON object")
    return value


def validate_settings_receipt(
    receipt: dict[str, Any],
    *,
    repository: str,
    now: dt.datetime | None = None,
    max_age_seconds: int = 3600,
) -> list[str]:
    """Validate a trusted-CI capture of repository ruleset state."""
    errors: list[str] = []
    if receipt.get("schema") != SETTINGS_SCHEMA:
        errors.append("GitHub settings receipt schema is unsupported")
    if receipt.get("repository") != repository:
        errors.append("GitHub settings receipt names a different repository")
    if receipt.get("default_branch") != "main":
        errors.append("GitHub settings receipt does not bind main")
    if receipt.get("source") != "github-api":
        errors.append("GitHub settings receipt is not an API observation")

    observed = receipt.get("observed_at")
    try:
        parsed = dt.datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone missing")
        current = now or dt.datetime.now(dt.timezone.utc)
        age = (current.astimezone(dt.timezone.utc) - parsed.astimezone(dt.timezone.utc)).total_seconds()
        if age < -300 or age > max_age_seconds:
            errors.append("GitHub settings receipt is stale or from the future")
    except ValueError:
        errors.append("GitHub settings receipt observation time is invalid")

    payload = receipt.get("payload")
    digest = receipt.get("payload_sha256")
    if not isinstance(payload, dict) or not SHA256_RE.fullmatch(str(digest or "")):
        errors.append("GitHub settings receipt payload binding is missing")
    elif hashlib.sha256(_canonical(payload)).hexdigest() != digest:
        errors.append("GitHub settings receipt payload digest mismatches")
    else:
        checks = payload.get("required_status_checks")
        check_identities: set[tuple[str, int]] = set()
        if isinstance(checks, list):
            for item in checks:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("context"), str)
                    or type(item.get("integration_id")) is not int
                ):
                    errors.append("main required status-check identity is malformed")
                    continue
                check_identities.add((item["context"], item["integration_id"]))
        required_identities = {
            (context, GITHUB_ACTIONS_INTEGRATION_ID) for context in REQUIRED_CHECKS
        }
        if not required_identities.issubset(check_identities):
            errors.append("main does not require the autoresearch validate and judge checks")
        bypasses = payload.get("bypass_actors")
        bypass_identities: set[tuple[int | None, str, str]] = set()
        if not isinstance(bypasses, list):
            errors.append("main ruleset bypass actors are missing")
        else:
            for item in bypasses:
                if not isinstance(item, dict):
                    errors.append("main ruleset bypass actor is malformed")
                    continue
                identity = (
                    item.get("actor_id"),
                    item.get("actor_type"),
                    item.get("bypass_mode"),
                )
                valid_actor_id = type(identity[0]) is int or (
                    identity[0] is None and identity[1] == "DeployKey"
                )
                if not valid_actor_id or not all(
                    isinstance(value, str) and value for value in identity[1:]
                ):
                    errors.append("main ruleset bypass actor is malformed")
                    continue
                bypass_identities.add(identity)
            if bypass_identities != APPROVED_BYPASS_ACTORS:
                errors.append(
                    "main ruleset must grant only the approved publisher bypass"
                )
        write_keys = payload.get("write_deploy_keys")
        expected_key = {
            "id": AUTORESEARCH_PUBLISH_DEPLOY_KEY_ID,
            "title": AUTORESEARCH_PUBLISH_DEPLOY_KEY_TITLE,
            "verified": True,
            "read_only": False,
        }
        if write_keys != [expected_key]:
            errors.append(
                "repository must expose exactly the pinned autoresearch publisher key"
            )
        if payload.get("ruleset_enforcement") != "active":
            errors.append("main ruleset is not active")
        if payload.get("non_fast_forward") is not True:
            errors.append("main does not reject non-fast-forward updates")
    return errors


def _board_classes(
    manifest: dict[str, Any], group: dict[str, Any], errors: list[str],
) -> list[str]:
    registry = manifest.get("workload_registry", {}).get("classes")
    workloads = group.get("workloads")
    if not isinstance(registry, dict) or not registry:
        errors.append("manifest workload class registry is missing")
        return []
    if not isinstance(workloads, dict):
        return []
    exposed = {
        spec.get("class") for spec in workloads.values() if isinstance(spec, dict)
    }
    unknown = sorted(exposed - set(registry))
    if unknown:
        errors.append("RISC-V workloads reference unknown classes: " + ", ".join(unknown))
    unscored = sorted(
        name for name in exposed & set(registry)
        if not isinstance(registry[name], dict)
        or registry[name].get("scored") is not True
    )
    if unscored:
        errors.append("RISC-V workloads use unscored classes: " + ", ".join(unscored))
    return [
        name for name, spec in registry.items()
        if isinstance(spec, dict) and spec.get("scored") is True and name in exposed
    ]


def _workload_errors(group: dict[str, Any], classes: list[str]) -> list[str]:
    errors: list[str] = []
    workloads = group.get("workloads")
    if not isinstance(workloads, dict):
        return ["RISC-V workload registry is missing"]
    by_class = {
        name: [wid for wid, spec in workloads.items() if spec.get("class") == name]
        for name in classes
    }
    for name, members in by_class.items():
        if len(members) < 2:
            errors.append(f"RISC-V {name} class needs at least two workloads")
    for workload_id, spec in workloads.items():
        args = str(spec.get("args", ""))
        if "bench --elf " not in args or "--backend cpu" not in args:
            errors.append(f"{workload_id} is not a production RISC-V CPU proof command")
        if "--protocol functional" not in args:
            errors.append(f"{workload_id} does not pin the functional protocol")
        if "{admission}" not in args:
            errors.append(f"{workload_id} does not use phase-aware admission")
        if spec.get("native_unit") != "executed instructions":
            errors.append(f"{workload_id} has the wrong native unit")

    generator = group.get("holdout_generator")
    if not isinstance(generator, dict) or generator.get("strategy") != "seeded_workload_pool_v1":
        errors.append("RISC-V holdout generator is not a real-program pool")
    else:
        pools = generator.get("pools")
        if not isinstance(pools, dict):
            errors.append("RISC-V holdout pools are missing")
        else:
            for name in classes:
                pool = pools.get(name)
                if not isinstance(pool, list) or len(pool) < 2:
                    errors.append(f"RISC-V {name} holdout pool is too small")
                    continue
                for workload_id in pool:
                    spec = workloads.get(workload_id)
                    if not isinstance(spec, dict) or spec.get("class") != name:
                        errors.append(f"RISC-V {name} holdout references {workload_id!r} incorrectly")
    return errors


def _workflow_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for relative, expected_name in REQUIRED_WORKFLOWS.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"required workflow is not installed: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if f"name: {expected_name}" not in text:
            errors.append(f"{relative} has the wrong workflow identity")
    return errors


def _sail_evidence_errors(root: Path, oracle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    binding = oracle.get("evidence")
    if not isinstance(binding, dict):
        return ["RISC-V Sail corpus evidence is not pinned"]
    if set(binding) != {"path", "sha256"}:
        errors.append("RISC-V Sail evidence binding has unexpected fields")
    relative = binding.get("path")
    digest = binding.get("sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return errors + ["RISC-V Sail evidence path is invalid"]
    if not SHA256_RE.fullmatch(str(digest or "")):
        errors.append("RISC-V Sail evidence digest is invalid")

    repository = root.resolve()
    path = (repository / relative).resolve()
    try:
        path.relative_to(repository)
    except ValueError:
        return errors + ["RISC-V Sail evidence escapes the repository"]
    if not path.is_file():
        return errors + ["RISC-V Sail evidence is missing"]
    raw = path.read_bytes()
    if SHA256_RE.fullmatch(str(digest or "")) and hashlib.sha256(raw).hexdigest() != digest:
        errors.append("RISC-V Sail evidence digest mismatches")
    try:
        evidence = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, ValueError):
        return errors + ["RISC-V Sail evidence is not valid JSON"]
    if not isinstance(evidence, dict):
        return errors + ["RISC-V Sail evidence must be an object"]
    sail = evidence.get("sail")
    if (
        evidence.get("schema") != "stwo-riscv-formal-corpus-evidence-v1"
        or evidence.get("result") != "equivalent"
        or evidence.get("semantic_authority") != "Sail"
        or evidence.get("independent_cross_check") != "Spike"
        or not isinstance(sail, dict)
        or sail.get("repository_revision") != RISCV_SAIL_COMMIT
    ):
        errors.append("RISC-V Sail evidence identity or verdict is invalid")
    return errors


def _release_phase_errors(root: Path) -> list[str]:
    capability = root / "src/products/riscv_cpu/capabilities.zig"
    artifact = root / "src/interop/riscv_artifact.zig"
    if not capability.is_file() or not artifact.is_file():
        return ["RISC-V release phase sources are missing"]
    capability_source = capability.read_text(encoding="utf-8")
    artifact_source = artifact.read_text(encoding="utf-8")
    errors = []
    if re.search(r"pub\s+const\s+adapter_release_gated\s*=\s*true\s*;", capability_source) is None:
        errors.append("RISC-V adapter is not release gated")
    if re.search(r'pub\s+const\s+RELEASE_STATUS\s*=\s*"release_gated"\s*;', artifact_source) is None:
        errors.append("RISC-V artifact status is not release gated")
    return errors


def _calibration_errors(
    root: Path,
    manifest: dict[str, Any],
    oracle: dict[str, Any],
    board: str,
    classes: list[str],
    anchors: dict[str, Any],
    dispersion: dict[str, Any],
    epoch_number: object,
) -> list[str]:
    errors: list[str] = []
    config = manifest.get("harness", {}).get("riscv_calibration")
    if not isinstance(config, dict):
        return ["RISC-V calibration freeze is not pinned"]
    expected_fields = {
        "schema", "status", "board", "epoch", "artifact", "artifact_sha256",
        "measured_commit", "designated_host",
    }
    if set(config) != expected_fields:
        errors.append("RISC-V calibration binding has unexpected fields")
    if (
        config.get("schema") != RISCV_CALIBRATION_SCHEMA
        or config.get("status") != "frozen"
        or config.get("board") != board
        or config.get("epoch") != epoch_number
    ):
        errors.append("RISC-V calibration binding identity is invalid")
    relative = config.get("artifact")
    digest = config.get("artifact_sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return errors + ["RISC-V calibration artifact path is invalid"]
    if not SHA256_RE.fullmatch(str(digest or "")):
        errors.append("RISC-V calibration artifact digest is invalid")
    repository = root.resolve()
    path = (repository / relative).resolve()
    try:
        path.relative_to(repository)
    except ValueError:
        return errors + ["RISC-V calibration artifact escapes the repository"]
    if not path.is_file():
        return errors + ["RISC-V calibration artifact is missing"]
    raw = path.read_bytes()
    if SHA256_RE.fullmatch(str(digest or "")) and hashlib.sha256(raw).hexdigest() != digest:
        errors.append("RISC-V calibration artifact digest mismatches")
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, ValueError):
        return errors + ["RISC-V calibration artifact is not valid JSON"]
    if not isinstance(document, dict):
        return errors + ["RISC-V calibration artifact must be an object"]
    if (
        document.get("schema") != RISCV_CALIBRATION_SCHEMA
        or document.get("status") != "frozen"
        or document.get("board") != board
        or document.get("epoch") != epoch_number
    ):
        errors.append("RISC-V calibration artifact identity is invalid")
    repository_identity = document.get("repository")
    if not isinstance(repository_identity, dict) or (
        repository_identity.get("commit") != config.get("measured_commit")
        or repository_identity.get("dirty") is not False
        or not COMMIT_RE.fullmatch(str(repository_identity.get("tree") or ""))
    ):
        errors.append("RISC-V calibration repository identity is invalid")
    host = document.get("host")
    designated = config.get("designated_host")
    if not isinstance(host, dict) or not isinstance(designated, dict) or any(
        host.get(name) != designated.get(name)
        for name in ("chip", "logical_cpu_count")
    ):
        errors.append("RISC-V calibration was not measured on the designated host")
    authority = document.get("oracle")
    reference = oracle.get("benchmark_reference")
    if not isinstance(authority, dict) or not isinstance(reference, dict) or (
        authority.get("authority") != "stark-v"
        or authority.get("commit") != RISCV_STARK_V_BENCHMARK_COMMIT
        or reference.get("authority") != "stark-v"
        or reference.get("commit") != RISCV_STARK_V_BENCHMARK_COMMIT
        or "parallel" not in (authority.get("required_features") or [])
        or "parallel" not in (reference.get("required_features") or [])
    ):
        errors.append("RISC-V calibration benchmark-reference identity is invalid")

    class_evidence = document.get("classes")
    if not isinstance(class_evidence, dict) or set(class_evidence) != set(classes):
        return errors + ["RISC-V calibration class coverage differs from the board"]
    for name in classes:
        entry = class_evidence.get(name)
        if not isinstance(entry, dict):
            errors.append(f"RISC-V {name} calibration entry is invalid")
            continue
        if entry.get("anchor_prove_ms") != anchors.get(name):
            errors.append(f"RISC-V {name} anchor differs from calibration evidence")
        if entry.get("dispersion") != dispersion.get(name):
            errors.append(f"RISC-V {name} dispersion differs from calibration evidence")
        receipt_relative = entry.get("receipt")
        receipt_digest = entry.get("receipt_sha256")
        if (
            not isinstance(receipt_relative, str)
            or Path(receipt_relative).is_absolute()
            or not SHA256_RE.fullmatch(str(receipt_digest or ""))
        ):
            errors.append(f"RISC-V {name} calibration receipt binding is invalid")
            continue
        receipt_path = (repository / receipt_relative).resolve()
        try:
            receipt_path.relative_to(repository)
            receipt_raw = receipt_path.read_bytes()
        except (ValueError, OSError):
            errors.append(f"RISC-V {name} calibration receipt is missing or unsafe")
            continue
        if hashlib.sha256(receipt_raw).hexdigest() != receipt_digest:
            errors.append(f"RISC-V {name} calibration receipt digest mismatches")
            continue
        try:
            receipt = json.loads(receipt_raw, object_pairs_hook=_strict_object)
        except (UnicodeDecodeError, ValueError):
            errors.append(f"RISC-V {name} calibration receipt is invalid JSON")
            continue
        if not isinstance(receipt, dict) or (
            receipt.get("board") != board
            or receipt.get("workload_class") != name
            or receipt.get("anchor_prove_ms") != entry.get("anchor_prove_ms")
        ):
            errors.append(f"RISC-V {name} calibration receipt identity differs")
        observed = []
        ci = entry.get("ci")
        if isinstance(ci, list) and len(ci) == 2 and all(_positive(value) for value in ci):
            observed.extend(abs(float(value) - 1.0) for value in ci)
        for rejected in entry.get("rejected_attempts") or []:
            rejected_ci = rejected.get("ci") if isinstance(rejected, dict) else None
            if isinstance(rejected_ci, list) and len(rejected_ci) == 2 and all(
                _positive(value) for value in rejected_ci
            ):
                observed.extend(abs(float(value) - 1.0) for value in rejected_ci)
        if not observed or round(max(observed), 6) != entry.get("dispersion"):
            errors.append(f"RISC-V {name} dispersion does not cover retained A/A bias")
    return errors


def activation_errors(
    root: Path,
    *,
    board: str,
    settings_receipt: Path | None,
    repository: str,
    require_active: bool = True,
) -> list[str]:
    """Return all blockers to promotion-eligible board activation."""
    errors: list[str] = []
    manifest = _load(root / "autoresearch/MANIFEST.json", "autoresearch manifest")
    groups = manifest.get("workload_registry", {}).get("groups", {})
    matches = [value for value in groups.values() if value.get("board") == board]
    if len(matches) != 1:
        return [f"board {board} must have exactly one workload owner"]
    group = matches[0]
    board_classes = _board_classes(manifest, group, errors)
    if not board_classes:
        errors.append(f"board {board} exposes no scored workload classes")
    if require_active and group.get("enabled") is not True:
        errors.append(f"board {board} is disabled")
    if require_active and group.get("promotion_eligible") is not True:
        errors.append(f"board {board} is not promotion eligible")
    if group.get("report_schema") != RISCV_REPORT_SCHEMA:
        errors.append("RISC-V board does not consume riscv_proof_v2")

    oracle = group.get("correctness_oracle")
    if not isinstance(oracle, dict):
        errors.append("RISC-V final correctness oracle is missing")
    else:
        if (
            oracle.get("authority") != "sail-riscv"
            or oracle.get("repository") != "https://github.com/riscv/sail-riscv"
            or oracle.get("commit") != RISCV_SAIL_COMMIT
        ):
            errors.append("RISC-V final correctness authority is not pinned Sail")
        if oracle.get("final_validator") is not True:
            errors.append("Sail evidence is not marked as the final validator")
        benchmark = oracle.get("benchmark_reference")
        if (
            not isinstance(benchmark, dict)
            or benchmark.get("authority") != "stark-v"
            or benchmark.get("commit") != RISCV_STARK_V_BENCHMARK_COMMIT
            or "parallel" not in (benchmark.get("required_features") or [])
        ):
            errors.append("RISC-V Stark-V benchmark reference is not pinned")
        errors.extend(_sail_evidence_errors(root, oracle))
    errors.extend(_release_phase_errors(root))
    errors.extend(_workload_errors(group, board_classes))

    telemetry = group.get("mechanism_telemetry")
    if not isinstance(telemetry, dict) or telemetry.get("fail_closed") is not True:
        errors.append("RISC-V mechanism telemetry is not fail closed")
    elif not set(telemetry.get("required_fields") or []).issuperset({
        "total_steps", "n_components", "mean_proving_seconds", "statement_sha256",
    }):
        errors.append("RISC-V mechanism telemetry omits required proof fields")

    if group.get("resource_telemetry") != RISCV_RESOURCE_TELEMETRY:
        errors.append(
            "RISC-V resource telemetry does not fail closed on Darwin "
            "RUSAGE_INFO_V6 sampling"
        )

    policy = group.get("gates_policy")
    if not isinstance(policy, dict) or not all(
        isinstance(policy.get(key), int) and policy[key] > 0
        for key in ("samples_per_round", "min_rounds", "max_rounds")
    ):
        errors.append("RISC-V board sampling policy is missing or invalid")

    anchors = manifest.get("harness", {}).get("anchor_prove_ms", {}).get(board, {})
    epoch = _load(root / "autoresearch/ledger/epochs.json", "autoresearch epochs")
    epochs = epoch.get("epochs") or []
    dispersion = (epochs[-1].get("aa_dispersion", {}).get(board, {}) if epochs else {})
    for name in board_classes:
        if not _positive(anchors.get(name)):
            errors.append(f"RISC-V {name} anchor is not frozen")
        if not _positive(dispersion.get(name)):
            errors.append(f"RISC-V {name} A/A dispersion is not frozen")
    if isinstance(oracle, dict):
        errors.extend(_calibration_errors(
            root,
            manifest,
            oracle,
            board,
            board_classes,
            anchors,
            dispersion,
            epochs[-1].get("epoch") if epochs else None,
        ))

    errors.extend(_workflow_errors(root))
    if settings_receipt is None:
        errors.append("fresh GitHub settings receipt is required")
    else:
        try:
            receipt = _load(settings_receipt, "GitHub settings receipt")
            errors.extend(validate_settings_receipt(receipt, repository=repository))
        except ActivationError as error:
            errors.append(str(error))
    return errors
