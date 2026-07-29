"""MANIFEST.json loading, validation, and path policy queries."""

from __future__ import annotations

import fnmatch
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

RUNGS = ("s1", "s2", "s3", "s4", "s5")
ACCEPTANCE_FLOOR = "s3"
REPORT_SCHEMA_VERSIONS = {
    "native_proof_v7": 7,
    "native_cuda_product_v6": 6,
    "pr6_supremacy_v1": 1,
    "riscv_proof_v2": 2,
    # Harness envelope version for the Cairo frontend products. It is NOT the
    # product report's own schema_version (that is pinned separately in
    # runner.CAIRO_PRODUCT_REPORT_SCHEMA_VERSION); see
    # autoresearch/schema/cairo-proof-v1.md.
    "cairo_proof_v1": 1,
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

# TRACKS §6 retire-and-complete. A retired group flips to
# `promotion_eligible: false`, keeps every name in `ledger.BOARDS`, and carries
# exactly this block. `closing_audit` stays null until the M5 judge host runs
# the final closing audit that stamps the board's last audited score.
RETIREMENT_KEYS = frozenset({"retired_at_utc", "reason", "closing_audit"})
CLOSING_AUDIT_KEYS = frozenset({"completed_utc", "bundle_sha256", "row_ids"})

# TRACKS §3.1: the scored boundary a workload group's board reports. The whole
# harness scores `prove_ms` today; `request_ms` is the verified-request
# boundary the RISC-V board adopts at its NEXT era, and declaring it is gated
# on that era carrying its own recalibration (see ledger.SCORED_DIMENSIONS and
# schema/scoring.md). Nothing in this repository declares it yet — the runner
# refuses to score a board whose era declares a boundary it cannot measure.
SCORED_DIMENSIONS = ("prove_ms", "request_ms")
DEFAULT_SCORED_DIMENSION = "prove_ms"
RESOURCE_PROFILES = frozenset(("standard", "large", "extreme"))

# A group's `report_schema` names the envelope its rows MUST carry. It is not
# by itself a claim that the group's product can already produce one: a
# parity-gated product may install a benchmark binary that prints only
# human-readable output. `report_adapter` states which of the two is true, and
# a group whose adapter is absent can never be enabled or promotion eligible —
# there is nothing to parse, so any run would have to fabricate. Absent the
# block entirely, a group is assumed to have a working adapter (every group
# that predates this field does).
REPORT_ADAPTER_KEYS = frozenset({"status", "emits", "note"})
REPORT_ADAPTER_STATUSES = ("present", "absent")

# TRACKS §7: a basket/class-universe change on a scored board is a new era, so
# new rows must be stageable without touching the era's scoring universe. Rows
# live OUTSIDE `workloads`, which is what makes the staging fail closed: no
# execution, scoring, holdout, or guard path can reach them, because every one
# of those paths reads `workloads`. Opening the era moves the rows in as part
# of the recalibration event.
ERA_STAGED_BASKET_KEYS = frozenset({
    "note", "activates_in_era", "reason", "admission", "rows",
})
ERA_STAGED_ADMISSION_KEYS = frozenset({
    "path", "sha256", "authority", "driver", "build_step", "note",
})
ERA_STAGED_ROW_REQUIRED_KEYS = frozenset({
    "class", "args", "native_unit", "role", "admission",
})
ERA_STAGED_ROW_KEYS = ERA_STAGED_ROW_REQUIRED_KEYS | {"killer_family"}
ERA_STAGED_ROW_ADMISSION_KEYS = frozenset({
    "target", "input_size", "expected_cycles",
})
ERA_STAGED_ROLES = ("scored_candidate", "killer")
# TRACKS §3.3 requires at least two adversarial killer workloads per track, so
# a staged basket that declares none is a basket extension pretending to be a
# killer set.
ERA_STAGED_MIN_KILLERS = 2
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
CAIRO_MECHANISM_FIELDS = frozenset({
    "product_identity_sha256",
    "protocol_manifest_sha256",
    "profile",
    "input_sha256",
    "proof_format",
    "proof_bytes",
    "proof_sha256",
    "stwo_cairo_revision",
    "stwo_revision",
    "mean_execute_seconds",
    "mean_prove_seconds",
    "mean_verify_seconds",
    "mean_cold_process_seconds",
    "phase_seconds",
    "metal_dispatches",
    "cpu_fallbacks",
})
# Semantics, not implementation: these must be byte-identical across the A and
# B arms of a paired Cairo round and across rounds. Identity and protocol
# digests are deliberately excluded because they bind the arm's own source.
CAIRO_STABLE_MECHANISM_FIELDS = frozenset({
    "profile",
    "input_sha256",
    "proof_format",
    "proof_bytes",
    "proof_sha256",
    "stwo_cairo_revision",
    "stwo_revision",
})
# TRACKS §3.2: the named phase cutpoints every Cairo track must publish.
CAIRO_PHASE_NAMES = (
    "execute",
    "witness",
    "commit",
    "interaction",
    "composition",
    "fri",
    "serialize",
    "verify",
)
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
# --- Confirmation ladder (TRACKS §3.5/§3.6) -------------------------------
#
# Everything here is OPTIONAL in the manifest: a manifest without a
# gates_policy.confirmation_ladder block keeps exactly the pre-ladder runner
# behavior. Presence of the block is what pre-registers the tier cost targets
# and the sequential spending rule.
CONFIRMATION_LADDER_SCHEMA = "stwo_perf_confirmation_ladder_v1"
PROXY_VALIDITY_RECEIPT_SCHEMA = "stwo_perf_proxy_validity_receipt_v1"
PROXY_VALIDITY_METHOD = "paired_ln_ratio_pearson_v1"
# The one registered spending rule. A constant (Pocock-style) boundary with the
# family-wise error split evenly across the planned looks: at look k of K the
# decision uses a bootstrap CI at level 1 - alpha/K. Because alpha/K < alpha,
# the boundary is strictly stricter than the fixed-sample gate, so an early
# stop can never admit a run the full-power gate would have rejected.
SEQUENTIAL_STOP_RULE = "pocock_constant_boundary_bonferroni_v1"
LADDER_TIERS = ("T0", "T1", "T2", "T3")
LADDER_TIER_KEYS = frozenset({"cost_target_seconds", "note"})
LADDER_T0_EXTRA_KEYS = frozenset({"warmups", "samples", "min_phase_move"})
SEQUENTIAL_STOP_KEYS = frozenset({
    "enabled", "rule", "alpha", "stop_on_decisive_miss",
})
PROXY_VALIDITY_POLICY_KEYS = frozenset({
    "receipt_schema", "receipt_dir", "min_correlation", "min_observations",
})
COST_TELEMETRY_KEYS = frozenset({"statistic", "window"})
COST_TELEMETRY_STATISTICS = frozenset({"median", "max"})
PROXY_FIXTURE_KEYS = frozenset({
    "proxy_id", "args", "native_unit", "official_params",
    "target_workload_ids", "note",
})
# A proxy is a SCALED SHAPE at official parameters (TRACKS §3.3). Restating any
# security parameter in a proxy's args is how "fast confirmation" quietly
# becomes "weakened confirmation", so the tokens are refused outright.
PROXY_FORBIDDEN_ARG_TOKENS = (
    "--pow-bits", "--n-queries", "--protocol", "--security", "--functional",
)
PROXY_VALIDITY_RECEIPT_KEYS = frozenset({
    "schema", "board", "era", "workload_class", "proxy", "target",
    "measured_at_utc", "host", "harness_commit", "measurement",
    "artifact_sha256",
})
PROXY_RECEIPT_PROXY_KEYS = frozenset({
    "proxy_id", "args", "native_unit", "official_params",
})
PROXY_RECEIPT_HOST_KEYS = frozenset({
    "identity_sha256", "chip", "logical_cpu_count",
})
PROXY_RECEIPT_MEASUREMENT_KEYS = frozenset({
    "method", "observations", "observation_count", "correlation",
    "min_correlation", "min_observations", "valid",
})
PROXY_RECEIPT_OBSERVATION_KEYS = frozenset({
    "proxy_ln_ratio", "class_ln_ratio", "proxy_evidence_sha256",
    "class_evidence_sha256",
})

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
    promotion_blocked_reason: str | None = None
    acceptance_corpus: dict = field(default_factory=dict)
    workload_provisioning: dict = field(default_factory=dict)
    # Whether the group's product can emit its declared report_schema today.
    report_adapter: dict = field(default_factory=dict)
    # TRACKS §7: rows admitted for this board but held out of the scoring
    # universe until a named future era opens. Never runnable, never scored.
    era_staged_basket: dict = field(default_factory=dict)
    # TRACKS §6: a retired-and-completed track. Present only on retired groups.
    retirement: dict = field(default_factory=dict)
    # TRACKS §3.1: the boundary this group's board scores. Defaults to today's
    # behaviour everywhere; see SCORED_DIMENSIONS.
    scored_dimension: str = DEFAULT_SCORED_DIMENSION
    # TRACKS §8: the guard portfolio bound to this group, by name in
    # workload_registry.guards.registries. None means the track declares no
    # regression surface (and must say why in guard_registry_absent_reason).
    guard_registry: str | None = None
    guard_registry_absent_reason: str | None = None
    # TRACKS §8: per-track editable paths. Extends the global editable set for
    # THIS track only, so a frontend's sources are editable by its own track
    # and are strays everywhere else. A glob that repeats a global entry
    # overrides that entry's min_rung for this track.
    editable_paths: list[dict] = field(default_factory=list)


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

    @property
    def confirmation_ladder(self) -> dict:
        """Pre-registered ladder config, or {} when the manifest predates it."""
        ladder = self.raw["gates_policy"].get("confirmation_ladder")
        return dict(ladder) if isinstance(ladder, dict) else {}

    def tier_cost_target_seconds(self, tier: str) -> int | None:
        """Cost target for one ladder tier; None when judge-scheduled/absent."""
        tiers = self.confirmation_ladder.get("tiers") or {}
        spec = tiers.get(tier)
        if not isinstance(spec, dict):
            return None
        target = spec.get("cost_target_seconds")
        return target if isinstance(target, int) and not isinstance(target, bool) else None

    def proxy_fixture(self, workload_class: str) -> dict | None:
        """The class's declared proxy fixture (TRACKS §3.3), if any."""
        self.workload_class(workload_class)
        spec = self.raw["workload_registry"]["classes"][workload_class]
        fixture = spec.get("proxy_fixture")
        return dict(fixture) if isinstance(fixture, dict) else None

    def proxy_validity_state(
        self, board: str, workload_class: str, era: int,
    ) -> dict:
        """Resolve the era validity receipt for one (board, class) proxy.

        Absence is never fatal and never fabricated: it downgrades T0/T1
        results with a loud ``proxy unvalidated`` marker (TRACKS §3.5).
        """
        state = {
            "validated": False,
            "reason": "class declares no proxy fixture",
            "receipt": None,
            "correlation": None,
            "era": era,
        }
        fixture = self.proxy_fixture(workload_class)
        if fixture is None:
            return state
        policy = self.confirmation_ladder.get("proxy_validity") or {}
        receipt_dir = policy.get("receipt_dir")
        if not isinstance(receipt_dir, str) or not receipt_dir:
            state["reason"] = (
                "gates_policy.confirmation_ladder.proxy_validity.receipt_dir "
                "is not registered"
            )
            return state
        path = self.root / receipt_dir / proxy_receipt_filename(
            board, workload_class, era,
        )
        state["receipt"] = str(path)
        if not path.is_file():
            state["reason"] = "proxy unvalidated: no era validity receipt at " + str(path)
            return state
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            receipt = validate_proxy_validity_receipt(
                document,
                board=board,
                workload_class=workload_class,
                era=era,
                policy=policy,
                proxy_fixture=fixture,
            )
        except (OSError, json.JSONDecodeError, ManifestError) as exc:
            state["reason"] = f"proxy unvalidated: invalid era receipt ({exc})"
            return state
        measurement = receipt["measurement"]
        state["correlation"] = measurement["correlation"]
        state["validated"] = bool(measurement["valid"])
        state["reason"] = (
            "era receipt valid"
            if state["validated"]
            else (
                "proxy unvalidated: measured correlation "
                f"{measurement['correlation']} is below the registered floor "
                f"{measurement['min_correlation']} — rotate the proxy"
            )
        )
        return state

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
                promotion_blocked_reason=spec.get("promotion_blocked_reason"),
                acceptance_corpus=dict(spec.get("acceptance_corpus", {})),
                workload_provisioning=dict(spec.get("workload_provisioning", {})),
                report_adapter=dict(spec.get("report_adapter", {})),
                era_staged_basket=dict(spec.get("era_staged_basket", {})),
                retirement=dict(spec.get("retirement", {})),
                scored_dimension=str(
                    spec.get("scored_dimension", DEFAULT_SCORED_DIMENSION)
                ),
                guard_registry=spec.get("guard_registry"),
                guard_registry_absent_reason=spec.get(
                    "guard_registry_absent_reason"
                ),
                editable_paths=[dict(e) for e in spec.get("editable_paths", [])],
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

    def guard_registry(self, group_id: str | None = None) -> dict:
        """TRACKS §8: the guard portfolio bound to one objective group.

        Returns the resolved registry — ``workloads``, the impact map, and the
        global guard policy with that registry's overrides applied. A group
        that declares ``guard_registry: null`` resolves to an empty portfolio
        (its reason is in ``guard_registry_absent_reason``); a manifest that
        predates the per-group registries resolves to its flat block unchanged.
        """
        return resolve_guard_registry(self.raw, group_id)

    def editable_for_board(self, board: str | None = None) -> list[dict]:
        """Editable-path entries in force for one track.

        The global list plus the board's group-level additions. A group entry
        whose glob repeats a global glob overrides that entry's ``min_rung``
        for this track only. ``board=None`` is the global set — every
        pre-TRACKS-§8 caller's behaviour, unchanged.
        """
        entries = [dict(e) for e in self.editable]
        if board is None:
            return entries
        try:
            group = self.group_for_board(board)
        except ManifestError:
            return entries
        by_glob = {e["glob"]: i for i, e in enumerate(entries)}
        for extra in group.editable_paths:
            index = by_glob.get(extra["glob"])
            if index is None:
                by_glob[extra["glob"]] = len(entries)
                entries.append(dict(extra))
            else:
                entries[index] = dict(extra)
        return entries

    def is_locked(self, path: str) -> bool:
        return any(_match(path, glob) for glob in self.locked)

    def is_editable(self, path: str, board: str | None = None) -> bool:
        return any(
            _match(path, e["glob"]) for e in self.editable_for_board(board)
        )

    def path_rung(self, path: str, board: str | None = None) -> str | None:
        """Minimum acceptance rung for one path; None if not editable."""
        best: str | None = None
        for entry in self.editable_for_board(board):
            if _match(path, entry["glob"]):
                rung = entry["min_rung"]
                if best is None or RUNGS.index(rung) > RUNGS.index(best):
                    best = rung
        return best

    def judged_rung(
        self, declared: str, touched_paths: list[str], board: str | None = None,
    ) -> str:
        """max(declared, highest rung mapped to any touched path); floor s3."""
        idx = max(RUNGS.index(declared), RUNGS.index(ACCEPTANCE_FLOOR))
        editable = self.editable_for_board(board)
        for path in touched_paths:
            for entry in editable:
                if _match(path, entry["glob"]):
                    idx = max(idx, RUNGS.index(entry["min_rung"]))
        return RUNGS[idx]

    def classify_touched(
        self, touched_paths: list[str], board: str | None = None,
    ) -> tuple[list[str], list[str]]:
        """Split touched paths into (locked violations, non-editable strays).

        With a board, the editable set is that track's (TRACKS §8): a Cairo
        submission may edit ``src/frontends/cairo/**``, and the same path is a
        stray on a native or RISC-V submission.
        """
        editable = self.editable_for_board(board)
        violations = [p for p in touched_paths if self.is_locked(p)]
        strays = [
            p for p in touched_paths
            if not self.is_locked(p)
            and not any(_match(p, e["glob"]) for e in editable)
        ]
        return violations, strays


def resolve_guard_registry(raw: dict, group_id: str | None = None) -> dict:
    """TRACKS §8: resolve the guard registry bound to one workload group.

    Takes the raw manifest document (not a ``Manifest``) so callers that only
    hold ``manifest.raw`` — the runner's guard seam, its test doubles — resolve
    identically. Three shapes are handled:

    * a manifest with no ``registries`` key is a pre-TRACKS-§8 flat portfolio
      and is returned unchanged, whatever the group: exactly today's behaviour;
    * a group bound to a named registry gets that registry with the global
      guard policy merged underneath its own overrides;
    * a group that declares no registry gets an empty portfolio, so its runs
      select nothing rather than binding a foreign product's args to its
      binary.
    """
    guards = raw.get("workload_registry", {}).get("guards", {}) or {}
    registries = guards.get("registries")
    if not isinstance(registries, dict):
        return guards
    global_policy = dict(guards.get("policy", {}) or {})
    empty = {
        "note": guards.get("note"),
        "workloads": {},
        "policy": global_policy,
        "impact_map": {"rules": []},
    }
    if group_id is None:
        return empty
    spec = raw.get("workload_registry", {}).get("groups", {}).get(group_id)
    if not isinstance(spec, dict):
        return empty
    registry = registries.get(spec.get("guard_registry"))
    if not isinstance(registry, dict):
        return empty
    resolved = dict(registry)
    resolved["policy"] = {**global_policy, **(registry.get("policy") or {})}
    resolved.setdefault("impact_map", {"rules": []})
    return resolved


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
    _validate_acceptance_corpora(repo, raw)
    groups = raw["workload_registry"]["groups"]
    if "cuda" in groups:
        try:
            from scripts.native_cuda_benchmark_lib.activation import (
                ActivationError,
                validate_manifest_activation,
            )

            validate_manifest_activation(repo, raw)
        except ActivationError as exc:
            raise ManifestError(str(exc)) from exc
    return Manifest(root=repo, raw=raw)


def _validate(raw: dict) -> None:
    for key in ("manifest_version", "harness", "editable_paths", "locked_paths",
                "workload_registry", "gates_policy", "qualification_policy"):
        if key not in raw:
            raise ManifestError(f"MANIFEST.json missing required key: {key}")
    _validate_editable_entries(raw["editable_paths"], "editable_paths")
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
    _validate_confirmation_ladder(raw["gates_policy"])
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
        _validate_group_retirement(gid, spec)
        _validate_group_scored_dimension(gid, spec)
        _validate_group_report_adapter(gid, spec)
        _validate_group_acceptance_corpus(gid, spec.get("acceptance_corpus", {}))
        _validate_group_workload_provisioning(
            gid, spec.get("workload_provisioning", {}), spec.get("workloads", {})
        )
        _validate_group_era_staged_basket(
            gid,
            spec.get("era_staged_basket"),
            spec.get("workloads", {}),
            registry["classes"],
        )
        if report_schema == "cairo_proof_v1":
            _validate_cairo_group(gid, spec)
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
        _validate_editable_entries(
            spec.get("editable_paths", []),
            f"workload group {gid} editable_paths",
            locked=raw["locked_paths"],
        )
    _validate_guards(registry)


def _validate_editable_entries(
    entries: object, label: str, locked: list[str] | None = None,
) -> None:
    """Shape-check one editable-path list (global or TRACKS §8 per-track)."""
    if not isinstance(entries, list):
        raise ManifestError(f"{label} must be a list")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError(f"{label} entries must be objects")
        glob = entry.get("glob")
        if not isinstance(glob, str) or not glob.strip():
            raise ManifestError(f"{label} entry has no glob")
        if entry.get("min_rung") not in RUNGS:
            raise ManifestError(f"editable path {glob} has invalid min_rung")
        if glob in seen:
            raise ManifestError(f"{label} declares {glob} twice")
        seen.add(glob)
        # A per-track carve-out must never re-open a locked path: the locked
        # set is the contract's floor and outranks every editable declaration.
        for locked_glob in locked or []:
            if _match(glob.removesuffix("/**"), locked_glob) or glob == locked_glob:
                raise ManifestError(
                    f"{label} declares {glob}, which is locked by "
                    f"{locked_glob}; per-track editable paths cannot re-open "
                    "locked paths"
                )


def _validate_guards(registry: dict) -> None:
    """TRACKS §8 per-group guard registries + per-track impact maps.

    Enforces that every guard portfolio is a real, non-empty set of workloads,
    that every impact-map rule names guards that exist IN THAT registry and
    boards that exist, and — the point of the restructure — that every
    workload group either names a registry that exists or says out loud why it
    has no regression surface.
    """
    guards = registry.get("guards")
    if guards is None:
        # A registry that declares no guards has no regression contract at all
        # (fixture manifests, single-group test registries). Unchanged.
        return
    if not isinstance(guards, dict):
        raise ManifestError("workload_registry.guards must be an object")
    registries = guards.get("registries")
    if registries is None:
        # Pre-TRACKS-§8 flat portfolio: one registry for every group.
        _validate_guard_registry("guards", guards, registry["groups"])
        return
    if not isinstance(registries, dict) or not registries:
        raise ManifestError(
            "workload_registry.guards.registries must be a non-empty object"
        )
    if "workloads" in guards:
        raise ManifestError(
            "workload_registry.guards declares both 'registries' and a flat "
            "'workloads' portfolio; the flat block is the pre-TRACKS-§8 shape "
            "and must be moved into a named registry"
        )
    if not isinstance(guards.get("policy", {}), dict):
        raise ManifestError("workload_registry.guards.policy must be an object")
    for name, spec in registries.items():
        if not isinstance(spec, dict):
            raise ManifestError(f"guard registry {name} must be an object")
        _validate_guard_registry(
            f"guard registry {name}", spec, registry["groups"],
        )
    bound: set[str] = set()
    for gid, spec in registry["groups"].items():
        if "guard_registry" not in spec:
            raise ManifestError(
                f"workload group {gid} declares no guard_registry: every group "
                "must name the guard portfolio bound to its binary, or declare "
                "null with a guard_registry_absent_reason (TRACKS §8)"
            )
        name = spec["guard_registry"]
        if name is None:
            if not str(spec.get("guard_registry_absent_reason") or "").strip():
                raise ManifestError(
                    f"workload group {gid} declares no guard registry without a "
                    "guard_registry_absent_reason; silently unguarded tracks "
                    "are not allowed"
                )
            continue
        if name not in registries:
            raise ManifestError(
                f"workload group {gid} references unknown guard registry: {name!r}"
            )
        bound.add(name)
    orphans = sorted(set(registries) - bound)
    if orphans:
        raise ManifestError(
            f"guard registries bound to no workload group: {orphans}"
        )


def _validate_guard_registry(label: str, spec: dict, groups: dict) -> None:
    workloads = spec.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise ManifestError(f"{label}: workloads must be a non-empty object")
    for wid, workload in workloads.items():
        if not isinstance(workload, dict):
            raise ManifestError(f"{label}: guard {wid} must be an object")
        if not str(workload.get("args") or "").strip():
            raise ManifestError(f"{label}: guard {wid} has no args")
    policy = spec.get("policy", {})
    if not isinstance(policy, dict):
        raise ManifestError(f"{label}: policy must be an object")
    for key in (
        "warmups", "samples_per_round", "min_rounds", "max_rounds",
        "budget_upper", "inconclusive_extra_rounds", "wall_clock_cap_seconds",
        "command_timeout_seconds",
    ):
        if key in policy and not _positive_number(policy[key]):
            raise ManifestError(f"{label}: policy.{key} must be a positive number")
    impact_map = spec.get("impact_map", {})
    if not isinstance(impact_map, dict):
        raise ManifestError(f"{label}: impact_map must be an object")
    rules = impact_map.get("rules", [])
    if not isinstance(rules, list):
        raise ManifestError(f"{label}: impact_map.rules must be a list")
    boards = {g.get("board") for g in groups.values() if isinstance(g, dict)}
    for rule in rules:
        if not isinstance(rule, dict):
            raise ManifestError(f"{label}: impact_map rules must be objects")
        prefixes = rule.get("prefixes")
        if not isinstance(prefixes, list) or not prefixes:
            raise ManifestError(
                f"{label}: an impact_map rule has no prefixes"
            )
        if not all(isinstance(p, str) and p.strip() for p in prefixes):
            raise ManifestError(
                f"{label}: impact_map prefixes must be non-empty strings"
            )
        board = rule.get("board")
        if board is not None and board not in boards:
            raise ManifestError(
                f"{label}: impact_map rule scopes to unknown board {board!r}"
            )
        selected = rule.get("guards")
        if selected == "all":
            continue
        if not isinstance(selected, list):
            raise ManifestError(
                f"{label}: impact_map rule guards must be \"all\" or a list"
            )
        unknown = sorted(set(selected) - set(workloads))
        if unknown:
            raise ManifestError(
                f"{label}: impact_map rule selects guards absent from this "
                f"registry: {unknown}"
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
    if report_schema == "cairo_proof_v1":
        _validate_cairo_mechanism_telemetry(gid, telemetry)
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


def _validate_cairo_mechanism_telemetry(gid: str, telemetry: object) -> None:
    """TRACKS §3.2: Cairo phase and identity telemetry is mandatory, fail-closed."""
    if not isinstance(telemetry, dict) or set(telemetry) != {
        "fail_closed", "required_fields",
    }:
        raise ManifestError(
            f"workload group {gid}: Cairo mechanism_telemetry requires exactly "
            "fail_closed and required_fields"
        )
    if telemetry["fail_closed"] is not True:
        raise ManifestError(
            f"workload group {gid}: Cairo mechanism telemetry must fail closed"
        )
    fields = telemetry["required_fields"]
    if (not isinstance(fields, list) or not fields or
            any(not isinstance(name, str) for name in fields) or
            len(fields) != len(set(fields))):
        raise ManifestError(
            f"workload group {gid}: mechanism required_fields must be a unique "
            "non-empty list"
        )
    unknown = sorted(set(fields) - CAIRO_MECHANISM_FIELDS)
    if unknown:
        raise ManifestError(
            f"workload group {gid}: unsupported mechanism field(s): "
            + ", ".join(unknown)
        )
    missing = sorted(CAIRO_STABLE_MECHANISM_FIELDS - set(fields))
    if missing:
        raise ManifestError(
            f"workload group {gid}: mechanism telemetry omits stable field(s): "
            + ", ".join(missing)
        )
    if "phase_seconds" not in fields:
        raise ManifestError(
            f"workload group {gid}: Cairo mechanism telemetry must require "
            "phase_seconds; TRACKS §3.2 makes the named phase cutpoints mandatory"
        )


def _validate_group_retirement(gid: str, spec: dict) -> None:
    """TRACKS §6: retirement is explicit, dated, reasoned, and unpromotable."""
    retirement = spec.get("retirement")
    if retirement is None:
        return
    if not isinstance(retirement, dict) or set(retirement) != RETIREMENT_KEYS:
        raise ManifestError(
            f"workload group {gid}: 'retirement' must contain exactly "
            + ", ".join(sorted(RETIREMENT_KEYS))
        )
    retired_at = retirement["retired_at_utc"]
    if not isinstance(retired_at, str) or not _UTC_TIMESTAMP_RE.fullmatch(retired_at):
        raise ManifestError(
            f"workload group {gid}: retirement.retired_at_utc must be ISO-8601 UTC"
        )
    if not str(retirement["reason"] or "").strip():
        raise ManifestError(
            f"workload group {gid}: retirement.reason must be a non-empty string"
        )
    if spec.get("promotion_eligible"):
        raise ManifestError(
            f"workload group {gid}: a retired group cannot be promotion eligible; "
            "TRACKS §6 retires by refusing new promotions while history stays served"
        )
    if not str(spec.get("promotion_blocked_reason") or "").strip():
        raise ManifestError(
            f"workload group {gid}: a retired group must state a "
            "promotion_blocked_reason so its refusal is legible"
        )
    closing = retirement["closing_audit"]
    if closing is None:
        return
    if not isinstance(closing, dict) or set(closing) != CLOSING_AUDIT_KEYS:
        raise ManifestError(
            f"workload group {gid}: retirement.closing_audit must be null or "
            "contain exactly " + ", ".join(sorted(CLOSING_AUDIT_KEYS))
        )
    if not _UTC_TIMESTAMP_RE.fullmatch(str(closing["completed_utc"])):
        raise ManifestError(
            f"workload group {gid}: closing_audit.completed_utc must be ISO-8601 UTC"
        )
    if not _SHA256_ID_RE.fullmatch(str(closing["bundle_sha256"])):
        raise ManifestError(
            f"workload group {gid}: closing_audit.bundle_sha256 must be sha256:<hex>"
        )
    row_ids = closing["row_ids"]
    if (
        not isinstance(row_ids, list)
        or not row_ids
        or any(not _SHA256_ID_RE.fullmatch(str(value)) for value in row_ids)
        or len(row_ids) != len(set(row_ids))
    ):
        raise ManifestError(
            f"workload group {gid}: closing_audit.row_ids must be a unique "
            "non-empty list of sha256:<hex> ledger row IDs"
        )


def _validate_group_scored_dimension(gid: str, spec: dict) -> None:
    """TRACKS §3.1: the scored boundary is declared, never inferred."""
    if "scored_dimension" not in spec:
        return
    dimension = spec["scored_dimension"]
    if dimension not in SCORED_DIMENSIONS:
        raise ManifestError(
            f"workload group {gid}: 'scored_dimension' must be one of "
            f"{SCORED_DIMENSIONS}"
        )


def _validate_group_report_adapter(gid: str, spec: dict) -> None:
    """A group with no report adapter cannot run, so it cannot be live.

    `report_schema` declares the envelope a board's rows must carry. For a
    parity-gated product that installs only a human-readable benchmark, the
    schema is a target rather than a capability, and saying so is the whole
    point of this block: the alternative is a group that looks runnable and
    fabricates the moment anyone enables it.
    """
    adapter = spec.get("report_adapter")
    if adapter is None:
        return
    if not isinstance(adapter, dict) or set(adapter) != REPORT_ADAPTER_KEYS:
        raise ManifestError(
            f"workload group {gid}: report_adapter requires exactly "
            + ", ".join(sorted(REPORT_ADAPTER_KEYS))
        )
    if adapter["status"] not in REPORT_ADAPTER_STATUSES:
        raise ManifestError(
            f"workload group {gid}: report_adapter.status must be one of "
            f"{REPORT_ADAPTER_STATUSES}"
        )
    for key in ("emits", "note"):
        if not isinstance(adapter[key], str) or not adapter[key].strip():
            raise ManifestError(
                f"workload group {gid}: report_adapter.{key} must be non-empty"
            )
    if adapter["status"] != "absent":
        return
    if spec.get("enabled") or spec.get("promotion_eligible"):
        raise ManifestError(
            f"workload group {gid}: report_adapter.status is 'absent', so the "
            "product emits nothing the harness can parse; such a group can be "
            "neither enabled nor promotion eligible"
        )


def _validate_group_era_staged_basket(
    gid: str, basket: object, workloads: object, classes: dict,
) -> None:
    """TRACKS §7: era-gated basket rows are admitted but out of the universe.

    The staging is structural. Rows live outside `workloads`, so no runner,
    scorer, holdout draw, or guard mapping can reach them; the only way one
    scores is for the named era to open and the row to be moved in, which is a
    reviewed recalibration event rather than a silent basket edit.
    """
    if basket is None:
        return
    if not isinstance(basket, dict) or set(basket) != ERA_STAGED_BASKET_KEYS:
        raise ManifestError(
            f"workload group {gid}: era_staged_basket requires exactly "
            + ", ".join(sorted(ERA_STAGED_BASKET_KEYS))
        )
    for key in ("note", "reason"):
        if not isinstance(basket[key], str) or not basket[key].strip():
            raise ManifestError(
                f"workload group {gid}: era_staged_basket.{key} must be non-empty"
            )
    era = basket["activates_in_era"]
    if type(era) is not int or era < 2:
        raise ManifestError(
            f"workload group {gid}: era_staged_basket.activates_in_era must be "
            "an integer era of 2 or later; era 1 is history and cannot be staged into"
        )
    admission = basket["admission"]
    if (
        not isinstance(admission, dict)
        or set(admission) != ERA_STAGED_ADMISSION_KEYS
    ):
        raise ManifestError(
            f"workload group {gid}: era_staged_basket.admission requires exactly "
            + ", ".join(sorted(ERA_STAGED_ADMISSION_KEYS))
        )
    path = admission["path"]
    if (
        not isinstance(path, str) or not path.startswith("vectors/")
        or Path(path).is_absolute() or ".." in Path(path).parts
    ):
        raise ManifestError(
            f"workload group {gid}: era_staged_basket.admission.path must be a "
            "repository vectors path"
        )
    digest = admission["sha256"]
    if (
        not isinstance(digest, str) or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise ManifestError(
            f"workload group {gid}: era_staged_basket.admission.sha256 must be "
            "canonical lowercase SHA-256 hex"
        )
    for key in ("authority", "driver", "build_step", "note"):
        if not isinstance(admission[key], str) or not admission[key].strip():
            raise ManifestError(
                f"workload group {gid}: era_staged_basket.admission.{key} must "
                "be non-empty"
            )
    rows = basket["rows"]
    if not isinstance(rows, dict) or not rows:
        raise ManifestError(
            f"workload group {gid}: era_staged_basket.rows must be a non-empty object"
        )
    declared = set(workloads) if isinstance(workloads, dict) else set()
    killers = 0
    for rid, row in rows.items():
        if rid in declared:
            raise ManifestError(
                f"workload group {gid}: {rid} is both a runnable workload and an "
                "era-staged row; a staged row must be outside the scoring universe"
            )
        if not isinstance(row, dict):
            raise ManifestError(f"workload group {gid}: staged row {rid} must be an object")
        unknown = sorted(set(row) - ERA_STAGED_ROW_KEYS)
        missing = sorted(ERA_STAGED_ROW_REQUIRED_KEYS - set(row))
        if unknown or missing:
            raise ManifestError(
                f"workload group {gid}: staged row {rid} has unsupported key(s) "
                f"{unknown} and omits {missing}"
            )
        if row["class"] not in classes:
            raise ManifestError(
                f"workload group {gid}: staged row {rid} references an unknown "
                f"class: {row['class']!r}"
            )
        for key in ("args", "native_unit"):
            if not isinstance(row[key], str) or not row[key].strip():
                raise ManifestError(
                    f"workload group {gid}: staged row {rid}.{key} must be non-empty"
                )
        role = row["role"]
        if role not in ERA_STAGED_ROLES:
            raise ManifestError(
                f"workload group {gid}: staged row {rid} has unsupported role "
                f"{role!r}; expected one of {ERA_STAGED_ROLES}"
            )
        family = row.get("killer_family")
        if role == "killer":
            killers += 1
            if not isinstance(family, str) or not family.strip():
                raise ManifestError(
                    f"workload group {gid}: staged killer {rid} must name its "
                    "killer_family so the adversarial coverage is legible"
                )
        elif family is not None:
            raise ManifestError(
                f"workload group {gid}: staged row {rid} is not a killer but "
                "declares a killer_family"
            )
        row_admission = row["admission"]
        if (
            not isinstance(row_admission, dict)
            or set(row_admission) != ERA_STAGED_ROW_ADMISSION_KEYS
        ):
            raise ManifestError(
                f"workload group {gid}: staged row {rid}.admission requires "
                "exactly " + ", ".join(sorted(ERA_STAGED_ROW_ADMISSION_KEYS))
            )
        if (
            not isinstance(row_admission["target"], str)
            or not row_admission["target"].strip()
        ):
            raise ManifestError(
                f"workload group {gid}: staged row {rid}.admission.target must "
                "name the corpus target"
            )
        for key in ("input_size", "expected_cycles"):
            value = row_admission[key]
            if type(value) is not int or value <= 0:
                raise ManifestError(
                    f"workload group {gid}: staged row {rid}.admission.{key} "
                    "must be a positive integer"
                )
    if killers < ERA_STAGED_MIN_KILLERS:
        raise ManifestError(
            f"workload group {gid}: era_staged_basket declares {killers} killer "
            f"row(s); TRACKS §3.3 requires at least {ERA_STAGED_MIN_KILLERS}"
        )


def _validate_cairo_group(gid: str, spec: dict) -> None:
    """Cairo tracks are oracle-pinned and never promotion eligible in wave 1."""
    if spec.get("promotion_eligible"):
        raise ManifestError(
            f"workload group {gid}: no Cairo board may be promotion eligible "
            "before its judge-host calibration is frozen (TRACKS §7)"
        )
    if not str(spec.get("promotion_blocked_reason") or "").strip():
        raise ManifestError(
            f"workload group {gid} cannot promote and states no "
            "promotion_blocked_reason; a silently unpromotable Cairo board is "
            "not allowed"
        )
    oracle = spec.get("correctness_oracle")
    required = (
        "authority", "repository", "commit", "stwo_repository", "stwo_commit",
        "adapter", "build_command", "final_validator",
    )
    if not isinstance(oracle, dict) or any(key not in oracle for key in required):
        raise ManifestError(
            f"workload group {gid}: Cairo correctness_oracle must pin "
            + ", ".join(required)
        )
    if oracle["authority"] != "official-stwo-cairo-verifier":
        raise ManifestError(
            f"workload group {gid}: the only admissible Cairo authority is the "
            "official stwo-cairo verifier"
        )
    if oracle["final_validator"] is not True:
        raise ManifestError(
            f"workload group {gid}: the Cairo oracle must be the final validator"
        )
    for key, repository in (
        ("repository", "https://github.com/starkware-libs/stwo-cairo"),
        ("stwo_repository", "https://github.com/starkware-libs/stwo"),
    ):
        if oracle[key] != repository:
            raise ManifestError(
                f"workload group {gid}: Cairo oracle {key} must be {repository}"
            )
    for key in ("commit", "stwo_commit"):
        value = oracle[key]
        if (not isinstance(value, str) or len(value) != 40
                or any(char not in "0123456789abcdef" for char in value)):
            raise ManifestError(
                f"workload group {gid}: Cairo oracle {key} must be a full "
                "lowercase Git commit"
            )
    adapter = oracle["adapter"]
    if (not isinstance(adapter, str)
            or adapter != "tools/stwo-cairo-official-verifier-rs"):
        raise ManifestError(
            f"workload group {gid}: the Cairo oracle adapter must be the pinned "
            "in-repository official verifier package"
        )


def _validate_group_acceptance_corpus(gid: str, corpus: object) -> None:
    if not isinstance(corpus, dict):
        raise ManifestError(f"workload group {gid}: acceptance_corpus must be an object")
    if not corpus:
        return
    allowed = {"path", "sha256", "note"}
    if set(corpus) - allowed or not {"path", "sha256"} <= set(corpus):
        raise ManifestError(
            f"workload group {gid}: acceptance_corpus requires path and sha256 "
            "(note optional)"
        )
    path = corpus["path"]
    if (
        not isinstance(path, str) or not path.startswith("vectors/")
        or Path(path).is_absolute() or ".." in Path(path).parts
    ):
        raise ManifestError(
            f"workload group {gid}: acceptance_corpus.path must be a repository "
            "vectors path"
        )
    digest = corpus["sha256"]
    if (
        not isinstance(digest, str) or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise ManifestError(
            f"workload group {gid}: acceptance_corpus.sha256 must be canonical "
            "lowercase SHA-256 hex"
        )
    if "note" in corpus and (
        not isinstance(corpus["note"], str) or not corpus["note"].strip()
    ):
        raise ManifestError(
            f"workload group {gid}: acceptance_corpus.note must be non-empty"
        )


def _validate_group_workload_provisioning(
    gid: str, provisioning: object, workloads: object,
) -> None:
    """Declared-but-unprovisioned basket entries stay loud and never runnable."""
    if not isinstance(provisioning, dict):
        raise ManifestError(
            f"workload group {gid}: workload_provisioning must be an object"
        )
    if not provisioning:
        return
    if set(provisioning) != {"note", "documentation", "pending"}:
        raise ManifestError(
            f"workload group {gid}: workload_provisioning requires exactly note, "
            "documentation, and pending"
        )
    for key in ("note", "documentation"):
        if not isinstance(provisioning[key], str) or not provisioning[key].strip():
            raise ManifestError(
                f"workload group {gid}: workload_provisioning.{key} must be non-empty"
            )
    pending = provisioning["pending"]
    if not isinstance(pending, dict) or not pending:
        raise ManifestError(
            f"workload group {gid}: workload_provisioning.pending must be a "
            "non-empty object"
        )
    declared = set(workloads) if isinstance(workloads, dict) else set()
    for wid, entry in pending.items():
        if wid in declared:
            raise ManifestError(
                f"workload group {gid}: {wid} is both a runnable workload and a "
                "pending provisioning entry"
            )
        if not isinstance(entry, dict) or set(entry) != {
            "vm_steps", "committed_cells", "reason",
        }:
            raise ManifestError(
                f"workload group {gid}: pending workload {wid} requires exactly "
                "vm_steps, committed_cells, and reason"
            )
        for key in ("vm_steps", "committed_cells"):
            value = entry[key]
            if type(value) is not int or value <= 0:
                raise ManifestError(
                    f"workload group {gid}: pending workload {wid}.{key} must be "
                    "a positive integer"
                )
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise ManifestError(
                f"workload group {gid}: pending workload {wid} has no reason"
            )


def _validate_acceptance_corpora(repo: Path, raw: dict) -> None:
    """Bind every declared acceptance corpus to its committed bytes.

    Harness-only fixture trees (the synthetic `autoresearch/`-only repositories
    several tests and tools build) carry no `vectors/`; there is nothing to
    bind and nothing to drift. Whenever the vectors tree IS present the binding
    is mandatory: a missing or altered corpus fails the load.
    """
    import hashlib

    if not (repo / "vectors").is_dir():
        return
    for gid, spec in raw["workload_registry"]["groups"].items():
        bindings = [("acceptance corpus", spec.get("acceptance_corpus") or {})]
        # An era-staged basket's admission evidence is bound the same way: the
        # staged rows are only as honest as the corpus that pins their guests,
        # inputs, and exact retirement counts.
        staged = spec.get("era_staged_basket") or {}
        if isinstance(staged, dict) and isinstance(staged.get("admission"), dict):
            bindings.append(("era-staged admission corpus", staged["admission"]))
        for label, corpus in bindings:
            # Shape is _validate's job; this pass only binds bytes to digests,
            # and must not crash when called on a manifest that failed it.
            if not isinstance(corpus, dict) or not {"path", "sha256"} <= set(corpus):
                continue
            path = repo / corpus["path"]
            try:
                payload = path.read_bytes()
            except OSError as exc:
                raise ManifestError(
                    f"workload group {gid}: {label} {corpus['path']} is "
                    f"not readable: {exc}"
                ) from exc
            actual = hashlib.sha256(payload).hexdigest()
            if actual != corpus["sha256"]:
                raise ManifestError(
                    f"workload group {gid}: {label} {corpus['path']} digest "
                    f"drifted (manifest {corpus['sha256']}, file {actual})"
                )


def _validate_classes(classes: object) -> None:
    if not isinstance(classes, dict) or not classes:
        raise ManifestError("workload_registry.classes must be a non-empty object")
    for name, spec in classes.items():
        if not isinstance(name, str) or not name or not name.replace("_", "").isalnum():
            raise ManifestError(f"invalid workload class name: {name!r}")
        required = {"scored", "resource", "sampling"}
        if not isinstance(spec, dict) or not required <= set(spec):
            raise ManifestError(
                f"workload class {name} requires exactly scored, resource, and sampling"
            )
        unknown = sorted(set(spec) - required - {"proxy_fixture"})
        if unknown:
            raise ManifestError(
                f"workload class {name} has unsupported key(s): " + ", ".join(unknown)
            )
        _validate_class_proxy_fixture(name, spec.get("proxy_fixture"))
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


def _positive_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) > 0
    )


def _validate_confirmation_ladder(gates_policy: object) -> None:
    """Validate the optional pre-registered confirmation ladder (TRACKS §3.5).

    Absent block = pre-ladder manifest = pre-ladder behavior. Present block
    must be complete: half-registered spending rules are not pre-registered.
    """
    if not isinstance(gates_policy, dict):
        raise ManifestError("gates_policy must be an object")
    ladder = gates_policy.get("confirmation_ladder")
    if ladder is None:
        return
    if not isinstance(ladder, dict) or set(ladder) != {
        "schema", "sequential_stop", "tiers", "proxy_validity",
        "cost_telemetry", "note",
    }:
        raise ManifestError(
            "gates_policy.confirmation_ladder requires exactly schema, "
            "sequential_stop, tiers, proxy_validity, cost_telemetry, and note"
        )
    if ladder["schema"] != CONFIRMATION_LADDER_SCHEMA:
        raise ManifestError(
            "gates_policy.confirmation_ladder.schema must be "
            + CONFIRMATION_LADDER_SCHEMA
        )
    if not isinstance(ladder["note"], str) or not ladder["note"].strip():
        raise ManifestError("gates_policy.confirmation_ladder.note must be non-empty")

    stop = ladder["sequential_stop"]
    if not isinstance(stop, dict) or set(stop) != SEQUENTIAL_STOP_KEYS:
        raise ManifestError(
            "gates_policy.confirmation_ladder.sequential_stop requires exactly "
            + ", ".join(sorted(SEQUENTIAL_STOP_KEYS))
        )
    if not isinstance(stop["enabled"], bool):
        raise ManifestError("confirmation_ladder.sequential_stop.enabled must be a boolean")
    if not isinstance(stop["stop_on_decisive_miss"], bool):
        raise ManifestError(
            "confirmation_ladder.sequential_stop.stop_on_decisive_miss must be a boolean"
        )
    if stop["rule"] != SEQUENTIAL_STOP_RULE:
        raise ManifestError(
            "confirmation_ladder.sequential_stop.rule must be "
            + SEQUENTIAL_STOP_RULE
            + " (the only pre-registered spending rule)"
        )
    alpha = stop["alpha"]
    if not _positive_number(alpha) or float(alpha) > 0.5:
        raise ManifestError(
            "confirmation_ladder.sequential_stop.alpha must be in (0, 0.5]"
        )

    tiers = ladder["tiers"]
    if not isinstance(tiers, dict) or tuple(tiers) != LADDER_TIERS:
        raise ManifestError(
            "confirmation_ladder.tiers must declare exactly "
            + ", ".join(LADDER_TIERS)
            + " in ladder order"
        )
    for tier, spec in tiers.items():
        allowed = LADDER_TIER_KEYS | (
            LADDER_T0_EXTRA_KEYS if tier == "T0" else frozenset()
        )
        if not isinstance(spec, dict) or not LADDER_TIER_KEYS <= set(spec):
            raise ManifestError(
                f"confirmation_ladder.tiers.{tier} requires cost_target_seconds and note"
            )
        unknown = sorted(set(spec) - allowed)
        if unknown:
            raise ManifestError(
                f"confirmation_ladder.tiers.{tier} has unsupported key(s): "
                + ", ".join(unknown)
            )
        target = spec["cost_target_seconds"]
        if target is not None and (
            type(target) is not int or not 1 <= target <= MAX_GROUP_WALL_CLOCK_SECONDS
        ):
            raise ManifestError(
                f"confirmation_ladder.tiers.{tier}.cost_target_seconds must be null "
                f"(judge-scheduled) or an integer in [1, {MAX_GROUP_WALL_CLOCK_SECONDS}]"
            )
        if not isinstance(spec["note"], str) or not spec["note"].strip():
            raise ManifestError(
                f"confirmation_ladder.tiers.{tier}.note must be non-empty"
            )
        if tier == "T0":
            if type(spec.get("warmups")) is not int or not 0 <= spec["warmups"] <= 100:
                raise ManifestError(
                    "confirmation_ladder.tiers.T0.warmups must be an integer in [0, 100]"
                )
            if type(spec.get("samples")) is not int or not 1 <= spec["samples"] <= 32:
                raise ManifestError(
                    "confirmation_ladder.tiers.T0.samples must be an integer in [1, 32]"
                )
            move = spec.get("min_phase_move")
            if not _positive_number(move) or float(move) >= 1.0:
                raise ManifestError(
                    "confirmation_ladder.tiers.T0.min_phase_move must be in (0, 1)"
                )
    ordered = [
        tiers[tier]["cost_target_seconds"] for tier in LADDER_TIERS
        if tiers[tier]["cost_target_seconds"] is not None
    ]
    if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
        raise ManifestError(
            "confirmation_ladder tier cost targets must increase strictly down the ladder"
        )

    proxy = ladder["proxy_validity"]
    if not isinstance(proxy, dict) or set(proxy) != PROXY_VALIDITY_POLICY_KEYS:
        raise ManifestError(
            "confirmation_ladder.proxy_validity requires exactly "
            + ", ".join(sorted(PROXY_VALIDITY_POLICY_KEYS))
        )
    if proxy["receipt_schema"] != PROXY_VALIDITY_RECEIPT_SCHEMA:
        raise ManifestError(
            "confirmation_ladder.proxy_validity.receipt_schema must be "
            + PROXY_VALIDITY_RECEIPT_SCHEMA
        )
    receipt_dir = proxy["receipt_dir"]
    if (
        not isinstance(receipt_dir, str)
        or not receipt_dir.startswith("autoresearch/")
        or Path(receipt_dir).is_absolute()
        or ".." in Path(receipt_dir).parts
    ):
        raise ManifestError(
            "confirmation_ladder.proxy_validity.receipt_dir must be a repository "
            "path under autoresearch/"
        )
    correlation = proxy["min_correlation"]
    if not _positive_number(correlation) or float(correlation) > 1.0:
        raise ManifestError(
            "confirmation_ladder.proxy_validity.min_correlation must be in (0, 1]"
        )
    observations = proxy["min_observations"]
    if type(observations) is not int or observations < 3:
        raise ManifestError(
            "confirmation_ladder.proxy_validity.min_observations must be an "
            "integer >= 3 (a correlation from two points is not evidence)"
        )

    telemetry = ladder["cost_telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != COST_TELEMETRY_KEYS:
        raise ManifestError(
            "confirmation_ladder.cost_telemetry requires exactly "
            + ", ".join(sorted(COST_TELEMETRY_KEYS))
        )
    if telemetry["statistic"] not in COST_TELEMETRY_STATISTICS:
        raise ManifestError(
            "confirmation_ladder.cost_telemetry.statistic must be "
            + " or ".join(sorted(COST_TELEMETRY_STATISTICS))
        )
    if type(telemetry["window"]) is not int or not 1 <= telemetry["window"] <= 100:
        raise ManifestError(
            "confirmation_ladder.cost_telemetry.window must be an integer in [1, 100]"
        )


def _validate_class_proxy_fixture(name: str, fixture: object) -> None:
    """Per-class proxy fixture: small shape, OFFICIAL params (TRACKS §3.3)."""
    if fixture is None:
        return
    if not isinstance(fixture, dict) or set(fixture) != PROXY_FIXTURE_KEYS:
        raise ManifestError(
            f"workload class {name}.proxy_fixture requires exactly "
            + ", ".join(sorted(PROXY_FIXTURE_KEYS))
        )
    proxy_id = fixture["proxy_id"]
    if not isinstance(proxy_id, str) or not re.fullmatch(r"[a-z0-9_]{3,64}", proxy_id):
        raise ManifestError(
            f"workload class {name}.proxy_fixture.proxy_id must be lowercase "
            "snake_case (3-64 chars)"
        )
    for key in ("args", "native_unit", "note"):
        value = fixture[key]
        if not isinstance(value, str) or not value.strip():
            raise ManifestError(
                f"workload class {name}.proxy_fixture.{key} must be a non-empty string"
            )
    if fixture["official_params"] is not True:
        raise ManifestError(
            f"workload class {name}.proxy_fixture.official_params must be true — "
            "fast confirmation uses scaled shapes at official parameters, never "
            "weakened parameters at full shapes"
        )
    lowered = fixture["args"].lower()
    offending = sorted(
        token for token in PROXY_FORBIDDEN_ARG_TOKENS if token in lowered
    )
    if offending:
        raise ManifestError(
            f"workload class {name}.proxy_fixture.args restates security "
            "parameter(s) " + ", ".join(offending)
            + "; a proxy scales geometry only"
        )
    targets = fixture["target_workload_ids"]
    if (
        not isinstance(targets, list)
        or not targets
        or any(not isinstance(item, str) or not item.strip() for item in targets)
        or len(targets) != len(set(targets))
    ):
        raise ManifestError(
            f"workload class {name}.proxy_fixture.target_workload_ids must be a "
            "unique non-empty list of workload IDs"
        )


def proxy_receipt_filename(board: str, workload_class: str, era: int) -> str:
    """Deterministic era-frozen receipt name (TRACKS §3.6)."""
    return f"{board}-{workload_class}-era{int(era)}.json"


def pearson_correlation(xs: list[float], ys: list[float]) -> float:
    """Pearson r over paired ln-ratios; stdlib only, deterministic."""
    if len(xs) != len(ys) or len(xs) < 3:
        raise ManifestError("a correlation needs at least three paired observations")
    n = float(len(xs))
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    dx = [x - mean_x for x in xs]
    dy = [y - mean_y for y in ys]
    numerator = sum(a * b for a, b in zip(dx, dy))
    denominator = math.sqrt(sum(a * a for a in dx)) * math.sqrt(sum(b * b for b in dy))
    if denominator <= 0.0:
        raise ManifestError(
            "a degenerate observation series (zero variance) has no correlation"
        )
    return numerator / denominator


def validate_proxy_validity_receipt(
    document: object,
    *,
    board: str | None = None,
    workload_class: str | None = None,
    era: int | None = None,
    policy: dict | None = None,
    proxy_fixture: dict | None = None,
) -> dict:
    """Validate a ``stwo_perf_proxy_validity_receipt_v1`` document.

    The correlation is RECOMPUTED from the receipt's own paired observations:
    a receipt cannot assert a validity number its evidence does not support.
    """
    if not isinstance(document, dict) or set(document) != PROXY_VALIDITY_RECEIPT_KEYS:
        raise ManifestError(
            "proxy validity receipt requires exactly "
            + ", ".join(sorted(PROXY_VALIDITY_RECEIPT_KEYS))
        )
    if document["schema"] != PROXY_VALIDITY_RECEIPT_SCHEMA:
        raise ManifestError(
            "proxy validity receipt schema must be " + PROXY_VALIDITY_RECEIPT_SCHEMA
        )
    for key in ("board", "workload_class"):
        value = document[key]
        if not isinstance(value, str) or not value.strip():
            raise ManifestError(f"proxy validity receipt {key} must be a non-empty string")
    if type(document["era"]) is not int or document["era"] <= 0:
        raise ManifestError("proxy validity receipt era must be a positive integer")
    if board is not None and document["board"] != board:
        raise ManifestError("proxy validity receipt is bound to another board")
    if workload_class is not None and document["workload_class"] != workload_class:
        raise ManifestError("proxy validity receipt is bound to another workload class")
    if era is not None and document["era"] != era:
        raise ManifestError("proxy validity receipt is bound to another era")

    proxy = document["proxy"]
    if not isinstance(proxy, dict) or set(proxy) != PROXY_RECEIPT_PROXY_KEYS:
        raise ManifestError(
            "proxy validity receipt proxy requires exactly "
            + ", ".join(sorted(PROXY_RECEIPT_PROXY_KEYS))
        )
    if proxy["official_params"] is not True:
        raise ManifestError("a receipt may only certify an official-parameter proxy")
    if proxy_fixture is not None:
        for key in ("proxy_id", "args", "native_unit"):
            if proxy.get(key) != proxy_fixture.get(key):
                raise ManifestError(
                    f"proxy validity receipt {key} differs from the manifest proxy fixture"
                )
    target = document["target"]
    if (
        not isinstance(target, dict)
        or set(target) != {"workload_ids"}
        or not isinstance(target["workload_ids"], list)
        or not target["workload_ids"]
        or any(not isinstance(item, str) or not item.strip()
               for item in target["workload_ids"])
    ):
        raise ManifestError(
            "proxy validity receipt target must name the class workload IDs it predicts"
        )
    measured_at = document["measured_at_utc"]
    if not isinstance(measured_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", measured_at,
    ):
        raise ManifestError(
            "proxy validity receipt measured_at_utc must be YYYY-MM-DDTHH:MM:SSZ"
        )
    host = document["host"]
    if not isinstance(host, dict) or set(host) != PROXY_RECEIPT_HOST_KEYS:
        raise ManifestError(
            "proxy validity receipt host requires exactly "
            + ", ".join(sorted(PROXY_RECEIPT_HOST_KEYS))
        )
    if not isinstance(host["identity_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", host["identity_sha256"],
    ):
        raise ManifestError("proxy validity receipt host.identity_sha256 must be sha256 hex")
    if not isinstance(host["chip"], str) or not host["chip"].strip():
        raise ManifestError("proxy validity receipt host.chip must be non-empty")
    if type(host["logical_cpu_count"]) is not int or host["logical_cpu_count"] <= 0:
        raise ManifestError(
            "proxy validity receipt host.logical_cpu_count must be a positive integer"
        )
    if not isinstance(document["harness_commit"], str) or not re.fullmatch(
        r"[0-9a-f]{12,40}", document["harness_commit"],
    ):
        raise ManifestError(
            "proxy validity receipt harness_commit must be lowercase hex (12-40 chars)"
        )
    if not isinstance(document["artifact_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", document["artifact_sha256"],
    ):
        raise ManifestError("proxy validity receipt artifact_sha256 must be sha256 hex")

    measurement = document["measurement"]
    if (
        not isinstance(measurement, dict)
        or set(measurement) != PROXY_RECEIPT_MEASUREMENT_KEYS
    ):
        raise ManifestError(
            "proxy validity receipt measurement requires exactly "
            + ", ".join(sorted(PROXY_RECEIPT_MEASUREMENT_KEYS))
        )
    if measurement["method"] != PROXY_VALIDITY_METHOD:
        raise ManifestError(
            "proxy validity receipt method must be " + PROXY_VALIDITY_METHOD
        )
    observations = measurement["observations"]
    if not isinstance(observations, list) or len(observations) < 3:
        raise ManifestError(
            "proxy validity receipt needs at least three paired observations"
        )
    xs: list[float] = []
    ys: list[float] = []
    for index, item in enumerate(observations):
        if not isinstance(item, dict) or set(item) != PROXY_RECEIPT_OBSERVATION_KEYS:
            raise ManifestError(
                f"proxy validity observation {index} requires exactly "
                + ", ".join(sorted(PROXY_RECEIPT_OBSERVATION_KEYS))
            )
        for key in ("proxy_ln_ratio", "class_ln_ratio"):
            value = item[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise ManifestError(
                    f"proxy validity observation {index}.{key} must be a finite number"
                )
        for key in ("proxy_evidence_sha256", "class_evidence_sha256"):
            value = item[key]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ManifestError(
                    f"proxy validity observation {index}.{key} must be sha256 hex"
                )
        xs.append(float(item["proxy_ln_ratio"]))
        ys.append(float(item["class_ln_ratio"]))
    if measurement["observation_count"] != len(observations):
        raise ManifestError(
            "proxy validity receipt observation_count disagrees with its observations"
        )
    recomputed = pearson_correlation(xs, ys)
    correlation = measurement["correlation"]
    if (
        isinstance(correlation, bool)
        or not isinstance(correlation, (int, float))
        or not math.isclose(float(correlation), recomputed, rel_tol=0, abs_tol=1e-9)
    ):
        raise ManifestError(
            "proxy validity receipt correlation is not the Pearson correlation of "
            f"its own observations (recomputed {recomputed:.12f})"
        )
    floor = measurement["min_correlation"]
    minimum = measurement["min_observations"]
    if not _positive_number(floor) or float(floor) > 1.0:
        raise ManifestError("proxy validity receipt min_correlation must be in (0, 1]")
    if type(minimum) is not int or minimum < 3:
        raise ManifestError("proxy validity receipt min_observations must be >= 3")
    if policy is not None:
        if float(floor) < float(policy["min_correlation"]):
            raise ManifestError(
                "proxy validity receipt weakens the registered correlation floor"
            )
        if minimum < int(policy["min_observations"]):
            raise ManifestError(
                "proxy validity receipt weakens the registered observation minimum"
            )
    expected_valid = (
        float(correlation) >= float(floor) and len(observations) >= minimum
    )
    if measurement["valid"] is not expected_valid:
        raise ManifestError(
            "proxy validity receipt validity flag disagrees with its own thresholds"
        )
    return document


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
