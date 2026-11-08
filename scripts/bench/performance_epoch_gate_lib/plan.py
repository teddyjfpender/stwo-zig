"""Deterministic host capture-plan construction and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import content_digest, sha256_bytes, canonical_bytes, strict_json
from .model import (
    EvidenceError,
    PLAN_SCHEMA,
    exact_object,
    require_bool,
    require_hex,
    require_string,
)


PLAN_FIELDS = {
    "schema", "schema_version", "protocol_sha256", "host_role", "session_nonce",
    "sources", "paths", "commands", "content_sha256",
}
SOURCE_FIELDS = {"repository", "commit", "tree", "clean", "worktree_status"}
PATH_FIELDS = {
    "baseline_root", "candidate_root", "bundle_root", "baseline_local_cache",
    "baseline_global_cache", "candidate_local_cache", "candidate_global_cache",
}
COMMAND_FIELDS = {"id", "phase", "arm", "cwd", "argv", "environment"}


def _source(repository: str, commit: str, tree: str) -> dict[str, Any]:
    return {
        "repository": repository,
        "commit": commit,
        "tree": tree,
        "clean": True,
        "worktree_status": "",
    }


def _workload_args(workload: dict[str, Any]) -> list[str]:
    flags = {
        "log_n_rows": "--log-n-rows",
        "sequence_len": "--sequence-len",
        "log_size": "--log-size",
        "log_step": "--log-step",
        "offset": "--offset",
        "initial_x": "--initial-x",
        "initial_y": "--initial-y",
        "n_rounds": "--n-rounds",
        "log_n_instances": "--log-n-instances",
    }
    result = ["--air", workload["name"], "--protocol", "functional"]
    for key, value in workload["parameters"].items():
        result.extend((flags[key], str(value)))
    return result


def _build_commands(protocol: dict[str, Any], role: str, paths: dict[str, str]) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    specs = [item for item in protocol["build_comparisons"] if item["host_role"] == role]
    for spec in specs:
        for arm in ("baseline", "candidate"):
            step = spec[f"{arm}_step"]
            root = paths[f"{arm}_root"]
            local = paths[f"{arm}_local_cache"]
            global_cache = paths[f"{arm}_global_cache"]
            for state in ("cold", "warm"):
                commands.append({
                    "id": f"build:{spec['id']}:{arm}:{state}",
                    "phase": f"build-{state}",
                    "arm": arm,
                    "cwd": root,
                    "argv": [
                        "zig", "build", step, "-Doptimize=ReleaseFast",
                        "--cache-dir", local, "--global-cache-dir", global_cache,
                    ],
                    "environment": {"STWO_CAPTURE_MODE": "performance-epoch-2"},
                })
    return commands


def _benchmark_commands(protocol: dict[str, Any], role: str, paths: dict[str, str]) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    lanes = [item for item in protocol["performance_lanes"] if item["host_role"] == role]
    binaries = {
        ("baseline", "cpu"): "zig-out/bin/stwo-zig",
        ("baseline", "metal-hybrid"): "zig-out/bin/stwo-zig",
        ("candidate", "cpu"): "zig-out/bin/stwo-zig-native-cpu",
        ("candidate", "metal-hybrid"): "zig-out/bin/stwo-zig-native-metal",
    }
    for lane in lanes:
        for workload in protocol["workloads"]:
            for arm in ("baseline", "candidate"):
                root = paths[f"{arm}_root"]
                binary = str(Path(root) / binaries[(arm, lane["backend"])])
                args = _workload_args(workload)
                args[0:0] = ["prove", "--backend", lane["backend"]]
                commands.append({
                    "id": f"prove:{lane['backend']}:{workload['id']}:{arm}",
                    "phase": "proof-request",
                    "arm": arm,
                    "cwd": root,
                    "argv": [
                        binary, *args, "--output", "$ARTIFACT_PATH",
                        "--report-out", "$REPORT_PATH",
                    ],
                    "environment": {"STWO_CAPTURE_MODE": "performance-epoch-2"},
                })
    return commands


def _special_commands(role: str, paths: dict[str, str]) -> list[dict[str, Any]]:
    if role == "macos":
        return [{
            "id": "aot:candidate:metal-hybrid",
            "phase": "aot-check",
            "arm": "candidate",
            "cwd": paths["candidate_root"],
            "argv": ["zig", "build", "metal-core-aot-acceptance", "-Doptimize=ReleaseFast"],
            "environment": {"STWO_CAPTURE_MODE": "performance-epoch-2"},
        }]
    return [{
        "id": "challenge:candidate:riscv",
        "phase": "riscv-challenge",
        "arm": "candidate",
        "cwd": paths["candidate_root"],
        "argv": ["zig", "build", "riscv-release-gate", "-Doptimize=ReleaseFast"],
        "environment": {"STWO_CAPTURE_MODE": "performance-epoch-2"},
    }]


def build_plan(
    *,
    protocol: dict[str, Any],
    protocol_sha256: str,
    host_role: str,
    session_nonce: str,
    candidate_commit: str,
    candidate_tree: str,
    paths: dict[str, str],
) -> dict[str, Any]:
    if host_role not in protocol["host_roles"]:
        raise EvidenceError("unsupported host role")
    require_hex(protocol_sha256, 64, "protocol_sha256")
    require_hex(session_nonce, 64, "session_nonce")
    require_hex(candidate_commit, 40, "candidate commit")
    require_hex(candidate_tree, 40, "candidate tree")
    if set(paths) != PATH_FIELDS:
        raise EvidenceError("capture paths fields drifted")
    normalized_paths = {key: str(Path(value).resolve()) for key, value in paths.items()}
    source = protocol["baseline_source"]
    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "protocol_sha256": protocol_sha256,
        "host_role": host_role,
        "session_nonce": session_nonce,
        "sources": {
            "baseline": _source(protocol["repository"], source["commit"], source["tree"]),
            "candidate": _source(protocol["repository"], candidate_commit, candidate_tree),
        },
        "paths": normalized_paths,
        "commands": [
            *_build_commands(protocol, host_role, normalized_paths),
            *_benchmark_commands(protocol, host_role, normalized_paths),
            *_special_commands(host_role, normalized_paths),
        ],
    }
    plan["content_sha256"] = content_digest(plan)
    return plan


def _validate_source(value: object, expected: dict[str, Any], label: str) -> None:
    source = exact_object(value, SOURCE_FIELDS, label)
    if source != expected:
        raise EvidenceError(f"{label} identity mismatch")
    require_bool(source["clean"], f"{label}.clean")
    if source["clean"] is not True or source["worktree_status"] != "":
        raise EvidenceError(f"{label} must be clean")


def validate_plan(plan: object, protocol: dict[str, Any], protocol_sha256: str) -> dict[str, Any]:
    value = exact_object(plan, PLAN_FIELDS, "capture plan")
    if value["schema"] != PLAN_SCHEMA or value["schema_version"] != 1:
        raise EvidenceError("capture plan schema is unsupported")
    if value["protocol_sha256"] != protocol_sha256:
        raise EvidenceError("capture plan protocol mismatch")
    require_hex(value["session_nonce"], 64, "capture plan session nonce")
    role = value["host_role"]
    if role not in protocol["host_roles"]:
        raise EvidenceError("capture plan host role is unsupported")
    paths = exact_object(value["paths"], PATH_FIELDS, "capture paths")
    for key, item in paths.items():
        path = Path(require_string(item, f"capture paths.{key}"))
        if not path.is_absolute() or ".." in path.parts:
            raise EvidenceError(f"capture paths.{key} must be absolute and normalized")
    if len(set(paths.values())) != len(paths):
        raise EvidenceError("capture paths must not alias")
    baseline = protocol["baseline_source"]
    expected_baseline = _source(protocol["repository"], baseline["commit"], baseline["tree"])
    sources = exact_object(value["sources"], {"baseline", "candidate"}, "capture sources")
    _validate_source(sources["baseline"], expected_baseline, "baseline source")
    candidate = exact_object(sources["candidate"], SOURCE_FIELDS, "candidate source")
    require_hex(candidate["commit"], 40, "candidate commit")
    require_hex(candidate["tree"], 40, "candidate tree")
    if candidate["commit"] == baseline["commit"]:
        raise EvidenceError("candidate cannot equal the historical baseline")
    expected_candidate = _source(
        protocol["repository"], candidate["commit"], candidate["tree"],
    )
    _validate_source(candidate, expected_candidate, "candidate source")
    expected = build_plan(
        protocol=protocol,
        protocol_sha256=protocol_sha256,
        host_role=role,
        session_nonce=value["session_nonce"],
        candidate_commit=candidate["commit"],
        candidate_tree=candidate["tree"],
        paths=paths,
    )
    if value != expected:
        raise EvidenceError("capture plan differs from the repository-owned plan")
    require_hex(value["content_sha256"], 64, "capture plan digest")
    if value["content_sha256"] != content_digest(value):
        raise EvidenceError("capture plan content digest mismatch")
    command_ids: set[str] = set()
    for command in value["commands"]:
        exact_object(command, COMMAND_FIELDS, "capture command")
        if command["id"] in command_ids:
            raise EvidenceError("capture command IDs are not unique")
        command_ids.add(command["id"])
    return value


def load_and_validate_plan(
    path: Path,
    protocol: dict[str, Any],
    protocol_sha256: str,
) -> tuple[dict[str, Any], str]:
    value = strict_json(path, protocol["limits"]["max_json_bytes"])
    validate_plan(value, protocol, protocol_sha256)
    return value, sha256_bytes(canonical_bytes(value))
