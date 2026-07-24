"""MANIFEST.json loading, validation, and path policy queries."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

RUNGS = ("s1", "s2", "s3", "s4", "s5")
ACCEPTANCE_FLOOR = "s3"
REPORT_SCHEMA_VERSIONS = {
    "native_proof_v7": 7,
    "native_cuda_product_v3": 3,
    "pr6_supremacy_v1": 1,
    "riscv_proof_v2": 2,
}

GROUP_GATES_POLICY_LIMITS = {
    "warmups": (1, 100),
    "samples_per_round": (1, 32),
    "min_rounds": (1, 50),
    "max_rounds": (1, 50),
}
SEARCH_HEALTH_POLICY_KEYS = frozenset({
    "trailing_window",
    "gradient_snr_threshold",
    "auto_boost_rounds",
    "maximum_rounds",
})
MAX_GROUP_WALL_CLOCK_SECONDS = 7200
MAX_COMMAND_TIMEOUT_SECONDS = 7200
RESOURCE_PROFILES = frozenset(("standard", "large", "extreme"))
METAL_CALIBRATION_SCHEMA = "stwo_perf_metal_calibration_freeze_v2"
METAL_CALIBRATION_FIELDS = frozenset({
    "schema", "status", "board", "epoch", "artifact", "artifact_sha256",
    "measured_commit", "policy_sha256", "runtime_identity_sha256",
    "source_sha256", "runtime_manifest_sha256", "runtime_objc_sha256",
    "platform_identity_sha256", "runtime_mode", "designated_host",
})
RISCV_MECHANISM_FIELDS = frozenset({
    "total_steps",
    "n_components",
    "mean_execution_seconds",
    "mean_witness_seconds",
    "mean_proving_seconds",
    "mean_verification_seconds",
    "statement_sha256",
    "transcript_state_blake2s",
})
RISCV_STABLE_MECHANISM_FIELDS = frozenset({
    "total_steps",
    "n_components",
    "statement_sha256",
    "transcript_state_blake2s",
})
RISCV_RESOURCE_TELEMETRY = {
    "fail_closed": True,
    "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
    "scope": "self_process_lifetime",
    "sampling_points": ["before_warmups", "after_verified_samples"],
    "fields": [
        "lifetime_max_phys_footprint_bytes",
        "energy_nj",
        "instructions",
        "cycles",
    ],
}
PR6_MECHANISM_TELEMETRY = {
    "fail_closed": True,
    "required_fields": [
        "prove_ms",
        "verified_request_ms",
        "cold_process_ms",
        "trace_row_mhz",
        "committed_cell_mhz",
        "proof_bytes",
        "canonical_proof_sha256",
        "protocol_sha256",
        "statement_sha256",
        "transcript_state_blake2s",
        "metal_dispatches",
        "metal_synchronization_points",
        "metal_cpu_fallbacks",
    ],
}
PR6_RESOURCE_TELEMETRY = {
    "fail_closed": True,
    "scope": "each_verified_sample",
    "required_fields": [
        "peak_rss_bytes",
        "admission_profile",
        "admitted_committed_cells",
        "admitted_accounted_bytes",
        "allocation_failure",
    ],
    "best_effort_fields": ["energy_nj", "instructions", "cycles"],
}


class ManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Workload:
    workload_id: str
    workload_class: str
    args: str
    native_unit: str
    group_id: str = "native"


@dataclass(frozen=True)
class WorkloadClass:
    name: str
    scored: bool
    resource_profile: str
    command_timeout_seconds: int
    wall_clock_cap_seconds: int
    sampling: dict


@dataclass(frozen=True)
class WorkloadGroup:
    group_id: str
    enabled: bool
    promotion_eligible: bool
    disabled_reason: str | None
    board: str
    build_step: str
    binary: str
    report_schema: str
    workloads: list[Workload]
    gates_policy: dict = field(default_factory=dict)
    holdout_generator: dict = field(default_factory=dict)
    correctness_oracle: dict = field(default_factory=dict)
    mechanism_telemetry: dict = field(default_factory=dict)
    resource_telemetry: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Manifest:
    root: Path
    raw: dict

    @property
    def editable(self) -> list[dict]:
        return list(self.raw["editable_paths"])

    @property
    def locked(self) -> list[str]:
        return list(self.raw["locked_paths"])

    @property
    def gates(self) -> dict:
        return dict(self.raw["gates_policy"])

    def gates_for_group(self, group_id: str) -> dict:
        """Global gate policy with one group's bounded measurement overrides.

        Execution callers should use ``gates_for_workload`` so the class-owned
        resource and sampling contract is also applied.
        """
        policy = self.gates
        override = self.group(group_id).gates_policy
        for key, value in override.items():
            if key == "wall_clock_cap_seconds":
                caps = dict(policy.get(key, {}))
                caps.update(value)
                policy[key] = caps
            else:
                policy[key] = value
        return policy

    def gates_for_workload(self, group_id: str, workload_class: str) -> dict:
        """Resolve global, class, then group policy for one executable class."""
        cls = self.workload_class(workload_class)
        policy = self.gates
        policy.update(cls.sampling)
        policy["resource_profile"] = cls.resource_profile
        policy["command_timeout_seconds"] = cls.command_timeout_seconds
        policy["wall_clock_cap_seconds"] = {
            workload_class: cls.wall_clock_cap_seconds,
        }
        override = self.group(group_id).gates_policy
        for key, value in override.items():
            if key == "wall_clock_cap_seconds":
                caps = dict(policy[key])
                caps.update(value)
                policy[key] = caps
            else:
                policy[key] = value
        return policy

    @property
    def qualification_policy(self) -> dict:
        return dict(self.raw["qualification_policy"])

    @property
    def search_health_policy(self) -> dict:
        return dict(self.raw["gates_policy"]["search_health"])

    @property
    def anchor_commit(self) -> str | None:
        return self.raw["harness"].get("anchor_commit")

    def groups(self) -> list[WorkloadGroup]:
        """Workload groups in manifest order (registry v2)."""
        out = []
        for gid, spec in self.raw["workload_registry"]["groups"].items():
            out.append(WorkloadGroup(
                group_id=gid,
                enabled=bool(spec["enabled"]),
                promotion_eligible=spec["promotion_eligible"],
                disabled_reason=spec.get("disabled_reason"),
                board=spec["board"],
                build_step=spec["build_step"],
                binary=spec["binary"],
                report_schema=spec["report_schema"],
                workloads=[
                    Workload(wid, w["class"], w["args"], w["native_unit"], gid)
                    for wid, w in spec["workloads"].items()
                ],
                gates_policy=dict(spec.get("gates_policy", {})),
                holdout_generator=dict(spec.get("holdout_generator", {})),
                correctness_oracle=dict(spec.get("correctness_oracle", {})),
                mechanism_telemetry=dict(spec.get("mechanism_telemetry", {})),
                resource_telemetry=dict(spec.get("resource_telemetry", {})),
            ))
        return out

    def classes(self, *, scored_only: bool = False) -> list[WorkloadClass]:
        """Manifest-owned class registry in its declared scoring order."""
        out = []
        for name, spec in self.raw["workload_registry"]["classes"].items():
            resource = spec["resource"]
            cls = WorkloadClass(
                name=name,
                scored=spec["scored"],
                resource_profile=resource["profile"],
                command_timeout_seconds=resource["command_timeout_seconds"],
                wall_clock_cap_seconds=resource["wall_clock_cap_seconds"],
                sampling=dict(spec["sampling"]),
            )
            if not scored_only or cls.scored:
                out.append(cls)
        return out

    def workload_class(self, name: str) -> WorkloadClass:
        for cls in self.classes():
            if cls.name == name:
                return cls
        raise ManifestError(f"unknown workload class: {name}")

    def class_names(
        self,
        *,
        board: str | None = None,
        scored_only: bool = False,
        include_disabled: bool = False,
    ) -> list[str]:
        """Declared classes, optionally restricted to one board's workload rows."""
        declared = [cls.name for cls in self.classes(scored_only=scored_only)]
        if board is None:
            return declared
        group = self.group_for_board(board)
        if not include_disabled and not group.enabled:
            return []
        exposed = {workload.workload_class for workload in group.workloads}
        return [name for name in declared if name in exposed]

    def validate_workload_class(
        self,
        name: str,
        *,
        board: str | None = None,
        include_disabled: bool = False,
    ) -> None:
        self.workload_class(name)
        if board is not None:
            group = self.group_for_board(board)
            if not include_disabled and not group.enabled:
                raise ManifestError(f"board {board} workload group is disabled")
            if name not in self.class_names(board=board, include_disabled=True):
                raise ManifestError(
                    f"board {board} does not expose workload class: {name}"
                )

    def group(self, group_id: str) -> WorkloadGroup:
        for g in self.groups():
            if g.group_id == group_id:
                return g
        raise ManifestError(f"unknown workload group: {group_id}")

    def group_for_board(self, board: str) -> WorkloadGroup:
        matches = [group for group in self.groups() if group.board == board]
        if not matches:
            raise ManifestError(f"board has no workload group: {board}")
        if len(matches) != 1:
            raise ManifestError(f"board maps to multiple workload groups: {board}")
        return matches[0]

    def workloads(self, workload_class: str | None = None,
                  include_disabled: bool = False,
                  board: str | None = None) -> list[Workload]:
        """Workloads for exactly one board; disabled groups excluded unless asked.

        A board is mandatory so a new enabled group cannot silently enter an
        existing caller's score basket. Execution callers must still announce
        disabled groups loudly themselves (runner/workspace do).
        """
        if board is None:
            raise ManifestError("board is required for workload selection")
        if workload_class is not None:
            self.validate_workload_class(
                workload_class, board=board, include_disabled=True,
            )
        groups = [self.group_for_board(board)]
        out = [
            w
            for g in groups
            if include_disabled or g.enabled
            for w in g.workloads
        ]
        if workload_class:
            out = [w for w in out if w.workload_class == workload_class]
        return out

    def is_locked(self, path: str) -> bool:
        return any(_match(path, glob) for glob in self.locked)

    def is_editable(self, path: str) -> bool:
        return any(_match(path, e["glob"]) for e in self.editable)

    def path_rung(self, path: str) -> str | None:
        """Minimum acceptance rung for one path; None if not editable."""
        best: str | None = None
        for entry in self.editable:
            if _match(path, entry["glob"]):
                rung = entry["min_rung"]
                if best is None or RUNGS.index(rung) > RUNGS.index(best):
                    best = rung
        return best

    def judged_rung(self, declared: str, touched_paths: list[str]) -> str:
        """max(declared, highest rung mapped to any touched path); floor s3."""
        idx = max(RUNGS.index(declared), RUNGS.index(ACCEPTANCE_FLOOR))
        for path in touched_paths:
            rung = self.path_rung(path)
            if rung is not None:
                idx = max(idx, RUNGS.index(rung))
        return RUNGS[idx]

    def classify_touched(self, touched_paths: list[str]) -> tuple[list[str], list[str]]:
        """Split touched paths into (locked violations, non-editable strays)."""
        violations = [p for p in touched_paths if self.is_locked(p)]
        strays = [
            p for p in touched_paths if not self.is_locked(p) and not self.is_editable(p)
        ]
        return violations, strays


def _match(path: str, glob: str) -> bool:
    if glob.endswith("/**"):
        return path.startswith(glob[:-3] + "/") or path == glob[:-3]
    return fnmatch.fnmatch(path, glob)


def find_repo_root(start: Path | None = None) -> Path:
    cur = (start or Path.cwd()).resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / "autoresearch" / "MANIFEST.json").exists():
            return candidate
    raise ManifestError(
        "not inside a stwo-perf repository (autoresearch/MANIFEST.json not found)"
    )


def load(root: Path | None = None) -> Manifest:
    repo = find_repo_root(root)
    path = repo / "autoresearch" / "MANIFEST.json"
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid MANIFEST.json: {exc}") from exc
    _validate(raw)
    return Manifest(root=repo, raw=raw)


def _validate(raw: dict) -> None:
    for key in ("manifest_version", "harness", "editable_paths", "locked_paths",
                "workload_registry", "gates_policy", "qualification_policy"):
        if key not in raw:
            raise ManifestError(f"MANIFEST.json missing required key: {key}")
    for entry in raw["editable_paths"]:
        if entry.get("min_rung") not in RUNGS:
            raise ManifestError(f"editable path {entry.get('glob')} has invalid min_rung")
    qualification = raw["qualification_policy"]
    required_checks = qualification.get("required_checks")
    if not isinstance(required_checks, list) or not required_checks:
        raise ManifestError("qualification_policy.required_checks must be a non-empty list")
    if qualification.get("max_active_per_user", 0) < 1:
        raise ManifestError("qualification_policy.max_active_per_user must be positive")
    registry = raw["workload_registry"]
    if "groups" not in registry:
        raise ManifestError(
            "workload_registry has no 'groups': flat v1 registries "
            "(build_step/binary/workloads at top level) were replaced by named "
            "groups in manifest_version 2 — wrap the flat triple in a group"
        )
    _validate_classes(registry.get("classes"))
    if any(
        isinstance(spec, dict) and spec.get("board") == "core_metal"
        for spec in registry["groups"].values()
    ):
        _validate_metal_calibration(raw["harness"], registry["classes"])
    _validate_search_health_policy(raw["gates_policy"], registry["classes"])
    if not registry["groups"]:
        raise ManifestError("workload_registry.groups is empty")
    seen_boards: set[str] = set()
    for gid, spec in registry["groups"].items():
        for key in (
            "enabled", "promotion_eligible", "board", "build_step", "binary",
            "report_schema", "workloads",
        ):
            if key not in spec:
                raise ManifestError(f"workload group {gid} missing required key: {key}")
        if not isinstance(spec["enabled"], bool):
            raise ManifestError(f"workload group {gid}: 'enabled' must be a boolean")
        if not isinstance(spec["promotion_eligible"], bool):
            raise ManifestError(
                f"workload group {gid}: 'promotion_eligible' must be a boolean"
            )
        if not spec["enabled"] and spec["promotion_eligible"]:
            raise ManifestError(
                f"workload group {gid}: a disabled group cannot be promotion eligible"
            )
        if not spec["enabled"] and not str(spec.get("disabled_reason") or "").strip():
            raise ManifestError(
                f"workload group {gid} is disabled without a disabled_reason; "
                "silent dark groups are not allowed"
            )
        board = spec["board"]
        if not isinstance(board, str) or not board.strip():
            raise ManifestError(f"workload group {gid}: 'board' must be a non-empty string")
        if board in seen_boards:
            raise ManifestError(
                f"board {board} is owned by multiple workload groups; "
                "cross-group workload pooling is forbidden"
            )
        seen_boards.add(board)
        report_schema = spec["report_schema"]
        if report_schema not in REPORT_SCHEMA_VERSIONS:
            raise ManifestError(
                f"workload group {gid} has unsupported report_schema: {report_schema!r}"
            )
        _validate_group_gates_policy(
            gid, spec.get("gates_policy", {}), raw["gates_policy"],
            {
                workload.get("class")
                for workload in spec.get("workloads", {}).values()
                if isinstance(workload, dict)
            },
        )
        if not isinstance(spec.get("correctness_oracle", {}), dict):
            raise ManifestError(
                f"workload group {gid}: correctness_oracle must be an object"
            )
        _validate_group_mechanism_telemetry(
            gid, report_schema, spec.get("mechanism_telemetry", {})
        )
        _validate_group_resource_telemetry(
            gid, report_schema, spec.get("resource_telemetry", {})
        )
        if not isinstance(spec["workloads"], dict) or not spec["workloads"]:
            raise ManifestError(f"workload group {gid}: workloads must be a non-empty object")
        for wid, w in spec["workloads"].items():
            if not isinstance(w, dict):
                raise ManifestError(f"workload {gid}/{wid} must be an object")
            if w.get("class") not in registry["classes"]:
                raise ManifestError(
                    f"workload {gid}/{wid} references an unknown class: "
                    f"{w.get('class')!r}"
                )
            class_spec = registry["classes"][w["class"]]
            resource_profile = class_spec["resource"]["profile"]
            if (
                resource_profile != "standard"
                and f"--resource-profile {resource_profile}" not in str(w.get("args", ""))
            ):
                raise ManifestError(
                    f"workload {gid}/{wid} belongs to {resource_profile} resource class "
                    f"{w['class']} but does not request "
                    f"--resource-profile {resource_profile}"
                )
        _validate_group_holdout_generator(
            gid, spec.get("holdout_generator", {}), spec["workloads"]
        )


def _validate_search_health_policy(gates_policy: object, classes: dict) -> None:
    if not isinstance(gates_policy, dict):
        raise ManifestError("gates_policy must be an object")
    policy = gates_policy.get("search_health")
    if not isinstance(policy, dict) or set(policy) != SEARCH_HEALTH_POLICY_KEYS:
        raise ManifestError(
            "gates_policy.search_health requires exactly "
            + ", ".join(sorted(SEARCH_HEALTH_POLICY_KEYS))
        )
    for key in ("trailing_window", "auto_boost_rounds", "maximum_rounds"):
        value = policy[key]
        if type(value) is not int or not 1 <= value <= 50:
            raise ManifestError(
                f"gates_policy.search_health.{key} must be an integer in [1, 50]"
            )
    threshold = policy["gradient_snr_threshold"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not 0 < float(threshold) <= 100
    ):
        raise ManifestError(
            "gates_policy.search_health.gradient_snr_threshold must be in (0, 100]"
        )
    configured = max(
        spec["sampling"]["max_rounds"] for spec in classes.values()
    )
    if policy["maximum_rounds"] < configured:
        raise ManifestError(
            "gates_policy.search_health.maximum_rounds cannot be below a class max_rounds"
        )


def _validate_group_mechanism_telemetry(
    gid: str, report_schema: str, telemetry: object,
) -> None:
    if not isinstance(telemetry, dict):
        raise ManifestError(f"workload group {gid}: mechanism_telemetry must be an object")
    if report_schema == "pr6_supremacy_v1":
        if telemetry != PR6_MECHANISM_TELEMETRY:
            raise ManifestError(
                f"workload group {gid}: PR6 mechanism_telemetry must exactly "
                "require both timing boundaries, proof/protocol identities, and "
                "Metal dispatch/synchronization/fallback counters"
            )
        return
    if report_schema != "riscv_proof_v2":
        return
    if set(telemetry) != {"fail_closed", "required_fields"}:
        raise ManifestError(
            f"workload group {gid}: RISC-V mechanism_telemetry requires exactly "
            "fail_closed and required_fields"
        )
    if telemetry["fail_closed"] is not True:
        raise ManifestError(
            f"workload group {gid}: RISC-V mechanism telemetry must fail closed"
        )
    fields = telemetry["required_fields"]
    if (not isinstance(fields, list) or not fields or
            any(not isinstance(field, str) for field in fields) or
            len(fields) != len(set(fields))):
        raise ManifestError(
            f"workload group {gid}: mechanism required_fields must be a unique non-empty list"
        )
    unknown = sorted(set(fields) - RISCV_MECHANISM_FIELDS)
    if unknown:
        raise ManifestError(
            f"workload group {gid}: unsupported mechanism field(s): " + ", ".join(unknown)
        )
    missing = sorted(RISCV_STABLE_MECHANISM_FIELDS - set(fields))
    if missing:
        raise ManifestError(
            f"workload group {gid}: mechanism telemetry omits stable field(s): "
            + ", ".join(missing)
        )


def _validate_classes(classes: object) -> None:
    if not isinstance(classes, dict) or not classes:
        raise ManifestError("workload_registry.classes must be a non-empty object")
    for name, spec in classes.items():
        if not isinstance(name, str) or not name or not name.replace("_", "").isalnum():
            raise ManifestError(f"invalid workload class name: {name!r}")
        if not isinstance(spec, dict) or set(spec) != {"scored", "resource", "sampling"}:
            raise ManifestError(
                f"workload class {name} requires exactly scored, resource, and sampling"
            )
        if not isinstance(spec["scored"], bool):
            raise ManifestError(f"workload class {name}.scored must be a boolean")
        resource = spec["resource"]
        if not isinstance(resource, dict) or set(resource) != {
            "profile", "command_timeout_seconds", "wall_clock_cap_seconds",
        }:
            raise ManifestError(
                f"workload class {name}.resource requires profile, "
                "command_timeout_seconds, and wall_clock_cap_seconds"
            )
        if resource["profile"] not in RESOURCE_PROFILES:
            raise ManifestError(
                f"workload class {name} has unsupported resource profile: "
                f"{resource['profile']!r}"
            )
        for key, maximum in (
            ("command_timeout_seconds", MAX_COMMAND_TIMEOUT_SECONDS),
            ("wall_clock_cap_seconds", MAX_GROUP_WALL_CLOCK_SECONDS),
        ):
            value = resource[key]
            if type(value) is not int or not 1 <= value <= maximum:
                raise ManifestError(
                    f"workload class {name}.resource.{key} must be an integer "
                    f"in [1, {maximum}]"
                )
        sampling = spec["sampling"]
        if not isinstance(sampling, dict) or set(sampling) != set(GROUP_GATES_POLICY_LIMITS):
            raise ManifestError(
                f"workload class {name}.sampling requires exactly "
                + ", ".join(GROUP_GATES_POLICY_LIMITS)
            )
        for key, (minimum, maximum) in GROUP_GATES_POLICY_LIMITS.items():
            value = sampling[key]
            if type(value) is not int or not minimum <= value <= maximum:
                raise ManifestError(
                    f"workload class {name}.sampling.{key} must be an integer "
                    f"in [{minimum}, {maximum}]"
                )
        if sampling["min_rounds"] > sampling["max_rounds"]:
            raise ManifestError(
                f"workload class {name}.sampling min_rounds exceeds max_rounds"
            )


def _validate_group_resource_telemetry(
    gid: str, report_schema: str, telemetry: object,
) -> None:
    if not isinstance(telemetry, dict):
        raise ManifestError(f"workload group {gid}: resource_telemetry must be an object")
    if report_schema == "pr6_supremacy_v1":
        if telemetry != PR6_RESOURCE_TELEMETRY:
            raise ManifestError(
                f"workload group {gid}: PR6 resource_telemetry must exactly "
                "require per-sample admission, allocation, and peak-RSS evidence"
            )
        return
    if report_schema != "riscv_proof_v2":
        if telemetry:
            raise ManifestError(
                f"workload group {gid}: resource_telemetry is only valid for "
                "riscv_proof_v2"
            )
        return
    if telemetry != RISCV_RESOURCE_TELEMETRY:
        raise ManifestError(
            f"workload group {gid}: RISC-V resource_telemetry must exactly require "
            "Darwin RUSAGE_INFO_V6 lifetime counters before warmups and after "
            "verified samples"
        )


def _validate_metal_calibration(harness: object, classes: dict) -> None:
    if not isinstance(harness, dict):
        raise ManifestError("harness must be an object")
    config = harness.get("metal_calibration")
    if not isinstance(config, dict) or set(config) != METAL_CALIBRATION_FIELDS:
        raise ManifestError(
            "harness.metal_calibration has the wrong freeze schema"
        )
    if config["schema"] != METAL_CALIBRATION_SCHEMA:
        raise ManifestError("harness.metal_calibration.schema is unsupported")
    if config["status"] not in {"pending", "frozen"}:
        raise ManifestError("harness.metal_calibration.status must be pending or frozen")
    if config["board"] != "core_metal" or config["runtime_mode"] != "source-jit":
        raise ManifestError("Metal calibration board/runtime contract mismatch")
    if type(config["epoch"]) is not int or config["epoch"] <= 0:
        raise ManifestError("Metal calibration epoch must be a positive integer")
    artifact = config["artifact"]
    if (
        not isinstance(artifact, str) or not artifact.startswith("autoresearch/reference/")
        or Path(artifact).is_absolute() or ".." in Path(artifact).parts
    ):
        raise ManifestError("Metal calibration artifact must be a repository reference path")
    host = config["designated_host"]
    if (
        not isinstance(host, dict) or set(host) != {"chip", "logical_cpu_count"}
        or not isinstance(host["chip"], str) or not host["chip"].strip()
        or type(host["logical_cpu_count"]) is not int
        or host["logical_cpu_count"] <= 0
    ):
        raise ManifestError("Metal calibration designated_host is malformed")
    frozen_fields = (
        "artifact_sha256", "measured_commit", "policy_sha256",
        "runtime_identity_sha256", "source_sha256", "runtime_manifest_sha256",
        "runtime_objc_sha256", "platform_identity_sha256",
    )
    if config["status"] == "pending":
        if any(config[field] is not None for field in frozen_fields):
            raise ManifestError("pending Metal calibration contains frozen evidence")
    else:
        for field in frozen_fields:
            value = config[field]
            width = 40 if field == "measured_commit" else 64
            if (
                not isinstance(value, str) or len(value) != width
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ManifestError(f"frozen Metal calibration has invalid {field}")
    # Calibration anchors belong to the live scored Metal portfolio. Staged,
    # non-scored resource classes (for example the opt-in PR6 extreme profile)
    # must not silently widen or invalidate that frozen score universe.
    class_names = [name for name, spec in classes.items() if spec["scored"]]
    for field in ("anchor_prove_ms", "anchor_request_ms", "anchor_resources"):
        anchors = harness.get(field, {}).get("core_metal")
        if not isinstance(anchors, dict) or list(anchors) != class_names:
            raise ManifestError(f"harness.{field}.core_metal must cover every class")
        for name, value in anchors.items():
            if config["status"] == "pending" and value is not None:
                raise ManifestError(f"pending Metal calibration has non-null {field}.{name}")
            if config["status"] == "frozen" and value is None:
                raise ManifestError(f"frozen Metal calibration has null {field}.{name}")


def _validate_group_gates_policy(
    gid: str,
    override: object,
    global_policy: dict,
    workload_classes: set[str],
) -> None:
    if not isinstance(override, dict):
        raise ManifestError(f"workload group {gid}: gates_policy must be an object")
    allowed = set(GROUP_GATES_POLICY_LIMITS) | {"wall_clock_cap_seconds", "note"}
    unknown = sorted(set(override) - allowed)
    if unknown:
        raise ManifestError(
            f"workload group {gid}: unsupported gates_policy override(s): "
            + ", ".join(unknown)
        )
    if "note" in override and (
        not isinstance(override["note"], str) or not override["note"].strip()
    ):
        raise ManifestError(f"workload group {gid}: gates_policy.note must be non-empty")
    for key, (minimum, maximum) in GROUP_GATES_POLICY_LIMITS.items():
        if key not in override:
            continue
        value = override[key]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ManifestError(
                f"workload group {gid}: gates_policy.{key} must be an integer "
                f"in [{minimum}, {maximum}]"
            )
    caps = override.get("wall_clock_cap_seconds", {})
    if not isinstance(caps, dict):
        raise ManifestError(
            f"workload group {gid}: gates_policy.wall_clock_cap_seconds must be an object"
        )
    unknown_classes = sorted(set(caps) - workload_classes)
    if unknown_classes:
        raise ManifestError(
            f"workload group {gid}: unsupported wall-clock class(es): "
            + ", ".join(unknown_classes)
        )
    for workload_class, value in caps.items():
        if type(value) is not int or not 1 <= value <= MAX_GROUP_WALL_CLOCK_SECONDS:
            raise ManifestError(
                f"workload group {gid}: wall-clock cap for {workload_class} must be "
                f"an integer in [1, {MAX_GROUP_WALL_CLOCK_SECONDS}]"
            )
    merged = dict(global_policy)
    merged.update({key: value for key, value in override.items()
                   if key != "wall_clock_cap_seconds"})
    if "min_rounds" in merged and "max_rounds" in merged:
        if merged["min_rounds"] > merged["max_rounds"]:
            raise ManifestError(
                f"workload group {gid}: gates_policy min_rounds exceeds max_rounds"
            )
    search_maximum = global_policy["search_health"]["maximum_rounds"]
    if merged.get("max_rounds", 0) > search_maximum:
        raise ManifestError(
            f"workload group {gid}: max_rounds exceeds search-health maximum_rounds"
        )


def _validate_group_holdout_generator(
    gid: str, generator: object, workloads: dict,
) -> None:
    if not isinstance(generator, dict):
        raise ManifestError(f"workload group {gid}: holdout_generator must be an object")
    if not generator:
        return
    if set(generator) != {"strategy", "pools"}:
        raise ManifestError(
            f"workload group {gid}: holdout_generator requires exactly strategy and pools"
        )
    if generator["strategy"] != "seeded_workload_pool_v1":
        raise ManifestError(
            f"workload group {gid}: unsupported holdout strategy "
            f"{generator['strategy']!r}"
        )
    pools = generator["pools"]
    if not isinstance(pools, dict) or not pools:
        raise ManifestError(f"workload group {gid}: holdout pools must be a non-empty object")
    declared_classes = {
        workload.get("class") for workload in workloads.values()
        if isinstance(workload, dict)
    }
    unknown_classes = sorted(set(pools) - declared_classes)
    if unknown_classes:
        raise ManifestError(
            f"workload group {gid}: unsupported holdout class(es): "
            + ", ".join(unknown_classes)
        )
    for workload_class, ids in pools.items():
        if (not isinstance(ids, list) or not ids or
                any(not isinstance(item, str) or not item for item in ids)):
            raise ManifestError(
                f"workload group {gid}: holdout pool {workload_class} must be "
                "a non-empty list of workload IDs"
            )
        if len(ids) != len(set(ids)):
            raise ManifestError(
                f"workload group {gid}: holdout pool {workload_class} has duplicate IDs"
            )
        primary_id = next(
            (workload_id for workload_id, workload in workloads.items()
             if workload.get("class") == workload_class),
            None,
        )
        if primary_id is None or not any(workload_id != primary_id for workload_id in ids):
            raise ManifestError(
                f"workload group {gid}: holdout pool {workload_class} must contain "
                "a workload different from the primary workload"
            )
        for workload_id in ids:
            workload = workloads.get(workload_id)
            if not isinstance(workload, dict):
                raise ManifestError(
                    f"workload group {gid}: unknown holdout workload {workload_id!r}"
                )
            if workload.get("class") != workload_class:
                raise ManifestError(
                    f"workload group {gid}: holdout workload {workload_id!r} is not "
                    f"class {workload_class}"
                )
