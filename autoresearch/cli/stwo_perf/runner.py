"""Paired A/B reward evaluation.

Composes the checked-in Zig bench harness rather than reimplementing it: each
arm is built with the manifest build step and exercised through the bench
binary; scoring pairs alternating rounds (ABBA order to cancel linear drift)
and estimates the ratio with Hodges-Lehmann plus a bootstrap CI.

v1 honesty note: the bench report exposes per-run medians, not raw samples, so
pairing is at round level (samples_per_round each), not sample level. The
verdict records this in evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import shlex
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from scripts.native_proof_matrix_lib.resource_admission import (
    ACCOUNTED_BYTES_PER_COMMITTED_CELL,
    resource_limits,
)
from scripts.native_cuda_diagnostic_lib.contract import (
    validate_artifact as validate_cuda_artifact,
    validate_report as validate_cuda_report,
)
from scripts.native_cuda_diagnostic_lib.model import (
    BlakeShape,
    DiagnosticError as CudaDiagnosticError,
    PlonkShape,
    PoseidonShape,
    Shape as CudaShape,
    XorShape,
)

from . import dimensions, ledger, search_health, stats
from .manifest import (
    CAIRO_PHASE_NAMES,
    PROXY_VALIDITY_METHOD,
    PROXY_VALIDITY_RECEIPT_SCHEMA,
    REPORT_SCHEMA_VERSIONS,
    RISCV_STABLE_MECHANISM_FIELDS,
    SEQUENTIAL_STOP_RULE,
    Manifest,
    ManifestError,
    Workload,
    WorkloadGroup,
    pearson_correlation,
    validate_proxy_validity_receipt,
)


class RunError(RuntimeError):
    pass


# --- Confirmation ladder (TRACKS §3.5) ------------------------------------
LADDER_T0_SCHEMA = "stwo_perf_ladder_t0_prefilter_v1"
LADDER_T1_SCHEMA = "stwo_perf_ladder_t1_estimate_v1"
#: Boundary label recorded on every WorkloadScore. The default is today's
#: paired quantity; the ladder's fast boundary is the opt-in alternative. The
#: estimated label is a DIFFERENT string on purpose: a cross-invocation
#: subtraction must never be readable as a same-invocation measurement.
FULL_BOUNDARY = "prove_ms"
FAST_BOUNDARY = "verified_request_minus_pow_ms"
FAST_BOUNDARY_ESTIMATED = "verified_request_minus_pow_ms_cross_invocation_estimate"
#: The only tier allowed to pair on a cross-invocation PoW estimate.
CROSS_INVOCATION_POW_TIER = "T1"


@dataclass(frozen=True)
class PowBoundarySource:
    """Where a report schema's MEASURED proof-of-work seconds come from.

    ``invocation`` is the honesty-critical field. ``scored_sample`` means the
    PoW time was measured on the very invocation being timed, so subtracting it
    yields a measurement. ``discarded_warmup`` means it was measured on another
    invocation of the same arm in the same round, so subtracting it yields an
    ESTIMATE — admissible only on a tier that never ranks (TRACKS §3.5).
    """

    kind: str
    invocation: str
    note: str
    field_path: tuple[str, ...] = ()
    stage_ids: tuple[str, ...] = ()

    @property
    def cross_invocation(self) -> bool:
        return self.invocation != "scored_sample"

    @property
    def boundary_label(self) -> str:
        return FAST_BOUNDARY_ESTIMATED if self.cross_invocation else FAST_BOUNDARY

    def describe(self, report_schema: str) -> dict:
        return {
            "report_schema": report_schema,
            "kind": self.kind,
            "invocation": self.invocation,
            "stage_ids": list(self.stage_ids),
            "field_path": list(self.field_path),
            "cross_invocation": self.cross_invocation,
            "estimate": self.cross_invocation,
            "note": self.note,
        }


#: report_schema -> where its measured proof-of-work seconds live. A schema
#: absent from this registry cannot use ``--fast-boundary`` at all: the harness
#: subtracts only measured PoW time, never a modeled or assumed one.
POW_PHASE_SECONDS_FIELDS: dict[str, PowBoundarySource] = {
    # Cairo records `proof_of_work` in its stage profile, which the runner
    # writes as a sidecar next to the bench envelope. That profile comes from
    # the discarded warmup (scored samples run uninstrumented), so this is a
    # cross-invocation ESTIMATE and is restricted to T1 accordingly.
    "cairo_proof_v1": PowBoundarySource(
        kind="stage_profile_sidecar",
        invocation="discarded_warmup",
        stage_ids=("proof_of_work",),
        note=(
            "Cairo scored samples run uninstrumented, so the PoW seconds come "
            "from the same arm's discarded warmup in the same round. pow 26 is "
            "~constant work (TRACKS §3.5), so this is a sound estimate for a "
            "paired delta — but it is an estimate, it is labelled as one, and "
            "only T1 (which never ranks) may pair on it. The long-term fix is "
            "per-sample PoW seconds in the cairo_proof_v1 envelope."
        ),
    ),
}
#: Suffix of the stage-profile sidecar the Cairo arm writes beside its envelope.
STAGE_PROFILE_SIDECAR_SUFFIX = ".stages.json"

#: report_schema -> phase name -> path to that phase's seconds. Phase names
#: follow the §3.2 cutpoint vocabulary. Groups whose reports carry stage
#: profiles contribute their stage tree on top of this map, so T0 attribution
#: is generic over whatever phase evidence a schema actually provides.
PHASE_SECONDS_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "native_proof_v7": {
        "input": ("timing", "input_seconds", "median"),
        "prove": ("timing", "prove_seconds", "median"),
        "serialize": ("timing", "proof_encode_seconds", "median"),
        "verify": ("timing", "verify_seconds", "median"),
        "request": ("timing", "request_seconds", "median"),
    },
    "riscv_proof_v2": {
        "execute": ("mean_execution_seconds",),
        "witness": ("mean_witness_seconds",),
        "prove": ("mean_proving_seconds",),
        "verify": ("mean_verification_seconds",),
        "request": ("median_seconds",),
    },
    # The Cairo envelope publishes the §3.2 cutpoints directly, so the row is
    # DERIVED from the canonical name tuple rather than restated: a schema that
    # gains or renames a cutpoint cannot leave T0 quietly reading a stale set.
    # ``serialize`` is always null (proof encode/write/hash is outside the
    # recorder), so it drops out of the measured phase set and a claim on it
    # fails T0 closed — the honest answer for an uninstrumented cutpoint.
    "cairo_proof_v1": {
        phase: ("phase_seconds", phase) for phase in CAIRO_PHASE_NAMES
    },
}


_RESOURCE_ADMISSION_KEYS = {
    "profile",
    "accounted_bytes_per_committed_cell",
    "committed_cells",
    "accounted_bytes",
    "max_committed_cells",
    "max_accounted_bytes",
}
_MAX_U64 = (1 << 64) - 1
_NATIVE_RESOURCE_KEYS = {
    "measurement_scope",
    "source",
    "measured_warmups",
    "measured_samples",
    "lifetime_peak_physical_footprint_bytes",
    "energy_nj",
    "instructions",
    "cycles",
    "canonical_proof_bytes",
    "complete",
    "unavailable_reason",
}


# --- Cairo (cairo_proof_v1) ------------------------------------------------
#
# `cairo_proof_v1` is the harness envelope, not the product's own report
# version: the focused Cairo CLIs emit a `schema_version: 2` proving report on
# stdout and an optional `schema_version: 1` stage profile. See
# autoresearch/schema/cairo-proof-v1.md.
CAIRO_PRODUCT_REPORT_SCHEMA_VERSION = 2
CAIRO_STAGE_PROFILE_SCHEMA_VERSION = 1
CAIRO_PROOF_FORMATS = frozenset({"json", "binary", "cairo-serde"})
CAIRO_IMPLEMENTATION_REPOSITORY = "https://github.com/teddyjfpender/stwo-zig"
CAIRO_COMMANDS = frozenset({"prove", "run-and-prove"})

_CAIRO_REPORT_KEYS = {
    "schema_version", "product", "frontend", "backend", "backend_evidence",
    "preprocessed_cache", "profile", "execution", "input", "proof", "timing",
    "verification",
}
_CAIRO_PRODUCT_KEYS = {
    "schema_version", "name", "frontend", "backend", "role",
    "protocol_features", "protocol_manifest_sha256", "identity_sha256",
    "source", "zig_version", "target", "optimize", "runtime", "upstream",
}
_CAIRO_SOURCE_KEYS = {
    "repository", "commit", "tree", "dirty", "dirty_content_sha256",
}
_CAIRO_TARGET_KEYS = {"arch", "os", "abi", "cpu_model", "cpu_features_sha256"}
_CAIRO_RUNTIME_KEYS = {"manifest", "sdk", "aot"}
_CAIRO_UPSTREAM_KEYS = {
    "stwo_cairo_revision", "stwo_revision", "cairo_language_version",
    "cairo_vm_version",
}
_CAIRO_BACKEND_EVIDENCE_KEYS = {
    "execution", "classification", "metal_dispatches", "cpu_fallbacks",
    "runtime_initializations", "runtime_shutdowns",
    "commit_source_arena_aliases", "commit_source_arena_memcpys",
    "commit_source_uploads",
}
_CAIRO_PREPROCESSED_CACHE_KEYS = {
    "enabled", "budget_bytes", "hits", "misses", "stores", "evictions",
    "loaded_bytes", "stored_bytes", "evicted_bytes", "directory_bytes",
    "eviction_ns",
}
_CAIRO_EXECUTION_KEYS = {
    "program_type", "program_sha256", "arguments_sha256", "adapter_sha256",
    "wall_ns",
}

# TRACKS §3.2 named cutpoints -> the stage-profile ROOT ids that compose them.
# `execute` and `verify` come from the report's own timing block; `serialize`
# is a documented instrumentation gap (the CLI writes and hashes the proof
# outside the recorder). Unknown roots fail closed so a product change forces a
# harness update instead of silently dropping proving time.
CAIRO_PHASE_STAGES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "witness": (
        (
            "preprocessed_plan",
            "preprocessed_table_build",
            "base_trace_build",
            "air_template_instantiation",
        ),
        (),
    ),
    "commit": (
        ("preprocessed_materialize_and_commit", "main_trace_commit"),
        (),
    ),
    "interaction": (
        ("interaction_trace_build", "interaction_trace_commit"),
        (),
    ),
    "composition": (
        (
            "draw_random_coeff",
            "composition_trace_extract",
            "composition_evaluation",
            "composition_interpolate_and_split",
            "composition_commit",
        ),
        (
            # Metal-lane device-composition admission markers.
            "composition_device_admission",
            "composition_device_declined",
            "composition_device_components",
            "composition_device_host_components",
            "composition_device_fallbacks",
        ),
    ),
    "fri": (
        (
            "oods_point_and_mask_points",
            "sampled_value_evaluation",
            "sampled_value_channel_mix",
            "fri_quotient_build_and_commit",
            "proof_of_work",
            "fri_decommit",
            "trace_decommit",
            "constraint_check_and_assembly",
        ),
        (),
    ),
}
CAIRO_UNINSTRUMENTED_PHASES = ("serialize",)


def _workload_resource_profile(workload: Workload) -> str:
    tokens = shlex.split(workload.args)
    positions = [index for index, token in enumerate(tokens) if token == "--resource-profile"]
    if not positions:
        return "standard"
    if len(positions) != 1 or positions[0] + 1 == len(tokens):
        raise ValueError("workload args contain an invalid resource profile selector")
    profile = tokens[positions[0] + 1]
    resource_limits(profile)
    return profile


def _validate_native_resource_admission(report: dict, workload: Workload) -> None:
    reported_workload = report.get("workload")
    admission = report.get("resource_admission")
    if not isinstance(reported_workload, dict):
        raise ValueError("workload must be an object")
    if not isinstance(admission, dict) or set(admission) != _RESOURCE_ADMISSION_KEYS:
        raise ValueError("resource_admission has the wrong schema")
    cells = reported_workload.get("committed_trace_cells")
    if type(cells) is not int or cells <= 0:
        raise ValueError("workload.committed_trace_cells must be a positive integer")
    if admission["committed_cells"] != cells:
        raise ValueError("resource_admission.committed_cells disagrees with workload")
    if cells > _MAX_U64 // ACCOUNTED_BYTES_PER_COMMITTED_CELL:
        raise ValueError("resource admission accounted-byte calculation overflows u64")
    accounted = cells * ACCOUNTED_BYTES_PER_COMMITTED_CELL
    if admission["accounted_bytes_per_committed_cell"] != ACCOUNTED_BYTES_PER_COMMITTED_CELL:
        raise ValueError("resource admission accounting factor differs from Zig authority")
    if admission["accounted_bytes"] != accounted:
        raise ValueError("resource_admission.accounted_bytes is inconsistent")
    profile = _workload_resource_profile(workload)
    limits = resource_limits(profile)
    if admission["profile"] != profile:
        raise ValueError("resource admission profile differs from workload args")
    if (
        admission["max_committed_cells"] != limits.max_committed_cells
        or admission["max_accounted_bytes"] != limits.max_accounted_bytes
    ):
        raise ValueError("resource admission budgets differ from Zig authority")
    if cells > limits.max_committed_cells or accounted > limits.max_accounted_bytes:
        raise ValueError("workload exceeds its reported resource admission budget")


def _parse_native_resources(
    report: dict,
    proof_samples: list,
    warmups: int,
    samples: int,
) -> dict[str, float | int | None]:
    resources = report.get("resources")
    if not isinstance(resources, dict) or set(resources) != _NATIVE_RESOURCE_KEYS:
        raise ValueError("resources has the wrong schema")
    if resources["measurement_scope"] != "verified_process_request_batch":
        raise ValueError("resources.measurement_scope is not the governed scope")
    if resources["measured_warmups"] != warmups:
        raise ValueError("resources.measured_warmups differs from the request")
    if resources["measured_samples"] != samples:
        raise ValueError("resources.measured_samples differs from the request")

    proof_sizes: set[int] = set()
    for item in proof_samples:
        size = item.get("bytes") if isinstance(item, dict) else None
        if type(size) is not int or size <= 0:
            raise ValueError("proof.samples[].bytes must be a positive integer")
        proof_sizes.add(size)
    if len(proof_sizes) != 1:
        raise ValueError("proof.samples contain different canonical proof sizes")
    proof_bytes = next(iter(proof_sizes))
    if resources["canonical_proof_bytes"] != proof_bytes:
        raise ValueError("resources.canonical_proof_bytes disagrees with proof bytes")

    complete = resources["complete"]
    if type(complete) is not bool:
        raise ValueError("resources.complete must be a boolean")
    source = resources["source"]
    reason = resources["unavailable_reason"]
    counter_names = (
        "lifetime_peak_physical_footprint_bytes",
        "energy_nj",
        "instructions",
        "cycles",
    )
    if complete:
        if source != "darwin_proc_pid_rusage_v6" or reason is not None:
            raise ValueError("complete resources require the Darwin v6 source")
        for name in counter_names:
            value = resources[name]
            if type(value) is not int or value <= 0:
                raise ValueError(f"resources.{name} must be a positive integer")
    else:
        if source != "unsupported":
            raise ValueError("incomplete resources require source=unsupported")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("incomplete resources require an unavailable reason")
        if any(resources[name] is not None for name in counter_names):
            raise ValueError("unsupported resource counters must be null")

    peak_bytes = resources["lifetime_peak_physical_footprint_bytes"]
    energy_nj = resources["energy_nj"]
    return {
        "peak_rss_mib": (
            float(peak_bytes) / float(1024 * 1024)
            if isinstance(peak_bytes, int) else None
        ),
        "energy_j": (
            float(energy_nj) / 1_000_000_000.0
            if isinstance(energy_nj, int) else None
        ),
        "proof_bytes": proof_bytes,
        "instructions": resources["instructions"],
        "cycles": resources["cycles"],
    }


@dataclass
class ArmResult:
    prove_ms: float
    proof_verified: int
    byte_identical: bool
    peak_rss_mib: float | None
    report_path: str
    proof_digest: str | None = None
    proof_bytes: int | None = None
    request_ms: float | None = None
    mechanism: dict | None = None
    energy_j: float | None = None
    instructions: int | None = None
    cycles: int | None = None
    resources_complete: bool | None = None
    #: Measured proof-of-work milliseconds, when the group's report schema
    #: exposes the cutpoint. None means "not measured" — never "zero".
    pow_ms: float | None = None


@dataclass
class WorkloadScore:
    workload: Workload
    ratios: list[float]
    r: float
    ci: tuple[float, float]
    a_median_ms: float
    b_median_ms: float
    rss_ratio: float | None
    reports: list[str] = field(default_factory=list)
    proof_digest: str | None = None
    request_ratio: float | None = None
    report_sha256s: list[str] = field(default_factory=list)
    mechanism_verified: bool | None = None
    resource_estimates: dict[str, dimensions.RatioEstimate] = field(default_factory=dict)
    candidate_resources: dict[str, float] = field(default_factory=dict)
    proof_bytes: int = 0
    measurement_seconds: float = 0.0
    resources_complete: bool | None = None
    #: Which paired quantity ``ratios`` measures (FULL_BOUNDARY by default).
    boundary: str = FULL_BOUNDARY
    #: Pre-registered sequential-stop evidence, present only when armed.
    sequential_stop: dict | None = None
    #: Median PoW-excluded request ratio, present only under the fast boundary.
    fast_request_ratio: float | None = None
    #: What the fast boundary subtracted and how it was measured, present only
    #: under ``fast_boundary``. Carries the cross-invocation estimate label.
    boundary_evidence: dict | None = None


def portfolio_summary(scores: list[WorkloadScore], ci_level: float) -> dict:
    """Aggregate a deterministic, independently resampled workload portfolio."""
    if not scores:
        raise RunError("cannot score an empty workload portfolio")
    if any(
        type(score.proof_bytes) is not int
        or score.proof_bytes <= 0
        or not math.isfinite(score.measurement_seconds)
        or score.measurement_seconds <= 0
        for score in scores
    ):
        raise RunError("portfolio is missing proof-size or measurement-time evidence")
    ordered = sorted(scores, key=lambda score: score.workload.workload_id)
    seed = _seed(
        "portfolio:" + "|".join(score.workload.workload_id for score in ordered),
        0,
    )
    estimate, ci = stats.portfolio_geomean_ci(
        [score.ratios for score in ordered],
        level=ci_level,
        iterations=stats.PORTFOLIO_BOOTSTRAP_ITERATIONS,
        seed=seed,
    )
    return {
        "r": estimate,
        "ci": ci,
        "ci_method": stats.PORTFOLIO_CI_METHOD,
        "ci_level": ci_level,
        "bootstrap_iterations": stats.PORTFOLIO_BOOTSTRAP_ITERATIONS,
        "seed": seed,
        "prove_ms_method": stats.PORTFOLIO_PROVE_MS_METHOD,
        "b_median_ms_geomean": stats.geometric_mean(
            [score.b_median_ms for score in ordered]
        ),
        "proof_bytes_method": stats.PORTFOLIO_PROOF_BYTES_METHOD,
        "proof_bytes": round(stats.geometric_mean(
            [float(score.proof_bytes) for score in ordered]
        )),
        "measurement_seconds": sum(score.measurement_seconds for score in ordered),
        "measurement_rounds": sum(len(score.ratios) for score in ordered),
    }


def _complete_metric_geomean(
    scores: list[WorkloadScore], field_name: str,
) -> float | None:
    values = [getattr(score, field_name) for score in scores]
    if not values or any(value is None for value in values):
        return None
    return stats.geometric_mean([float(value) for value in values])


def portfolio_promotion_status(
    dimension: str, portfolio_ci: tuple[float, float], theta: float,
) -> tuple[bool, bool, dict]:
    if dimension != "time":
        return False, False, {
            "eligible": False,
            "method": None,
            "reason": (
                f"{dimension} objective is diagnostic until a dimension-specific "
                "portfolio CI is implemented"
            ),
        }
    significant = portfolio_ci[1] < 1.0 - theta
    neutral = (
        not significant
        and portfolio_ci[0] >= 1.0 - theta
        and portfolio_ci[1] <= 1.0 + theta
    )
    return significant, neutral, {
        "eligible": True,
        "method": stats.PORTFOLIO_CI_METHOD,
        "reason": "prove-time objective uses the deterministic workload portfolio CI",
    }


def _run(
    cmd: str,
    cwd: Path,
    timeout: float,
    deadline_monotonic: float | None = None,
) -> str:
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise RunError(f"class wall deadline expired before command: {cmd}")
        timeout = min(timeout, remaining)
    try:
        proc = subprocess.run(
            shlex.split(cmd), cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        if deadline_monotonic is not None:
            raise RunError(f"command reached the fixed class wall deadline: {cmd}") from exc
        raise RunError(f"command timed out after {timeout}s: {cmd}") from exc
    if proc.returncode != 0:
        raise RunError(f"command failed ({cmd}):\n{proc.stderr.strip()[-800:]}")
    return proc.stdout


def announce_skipped_groups(manifest: Manifest) -> list[dict]:
    """Print one loud line per disabled group and return the skip records.

    Every runner entry point calls this so a disabled group is never
    silently dropped from a run.
    """
    skipped = []
    for group in manifest.groups():
        if group.enabled:
            continue
        reason = group.disabled_reason or "no reason recorded"
        print(f"skipped group {group.group_id}: {reason}")
        skipped.append({"group": group.group_id, "reason": reason})
    return skipped


def build_arm(arm_root: Path, manifest: Manifest, timeout: int = 900,
              groups: list[WorkloadGroup] | None = None) -> None:
    """Build the bench binaries for the given groups (default: all enabled)."""
    if groups is None:
        groups = [g for g in manifest.groups() if g.enabled]
    seen: set[str] = set()
    for group in groups:
        if group.build_step in seen:
            continue
        seen.add(group.build_step)
        _run(group.build_step, arm_root, timeout)


def _riscv_admission_state(arm_root: Path) -> tuple[str, str, bool]:
    capability_path = arm_root / "src/products/riscv_cpu/capabilities.zig"
    artifact_path = arm_root / "src/interop/riscv_artifact.zig"
    try:
        capability_source = capability_path.read_text(encoding="utf-8")
        artifact_source = artifact_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RunError(f"cannot read typed RISC-V admission state: {exc}") from exc
    capabilities = re.findall(
        r"^pub const adapter_release_gated = (true|false);$",
        capability_source,
        flags=re.MULTILINE,
    )
    statuses = re.findall(
        r'^pub const RELEASE_STATUS = "([^"]+)";$',
        artifact_source,
        flags=re.MULTILINE,
    )
    if len(capabilities) != 1 or len(statuses) != 1:
        raise RunError("RISC-V admission state is missing or ambiguous")
    state = (capabilities[0], statuses[0])
    if state == ("false", "not_release_gated"):
        return "--experimental", "not_release_gated", True
    if state == ("true", "release_gated"):
        return "", "release_gated", False
    raise RunError(
        "RISC-V capability and artifact release states disagree "
        f"(adapter_release_gated={state[0]}, RELEASE_STATUS={state[1]!r})"
    )


def _format_workload_args(
    arm_root: Path,
    group: WorkloadGroup,
    workload: Workload,
    warmups: int,
    samples: int,
) -> str:
    admission = ""
    if group.report_schema == "riscv_proof_v2":
        if "{admission}" not in workload.args:
            raise RunError(
                f"{workload.workload_id}: RISC-V workload command lacks "
                "the required {admission} token"
            )
        admission = _riscv_admission_state(arm_root)[0]
    try:
        return workload.args.format(
            warmups=warmups,
            samples=samples,
            admission=admission,
        )
    except (KeyError, IndexError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: invalid workload command template: {exc}"
        ) from exc


def bench_once(
    arm_root: Path,
    manifest: Manifest,
    workload: Workload,
    warmups: int,
    samples: int,
    out_dir: Path,
    tag: str,
    timeout_seconds: float | int | None = None,
    deadline_monotonic: float | None = None,
) -> ArmResult:
    group = manifest.group(workload.group_id)
    binary = arm_root / group.binary
    if not binary.is_file():
        raise RunError(
            f"group {group.group_id}: bench binary not found at {binary} — "
            f"build it first ({group.build_step}); refusing to fabricate measurements"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    if group.report_schema == "cairo_proof_v1":
        # The Cairo CLIs prove one statement per process, so the harness owns
        # the warmup/sample loop and reads a cold-process boundary per sample.
        cairo_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else manifest.workload_class(workload.workload_class).command_timeout_seconds
        )
        if cairo_timeout <= 0:
            raise RunError(f"{workload.workload_id}: no command time budget remains")
        try:
            cairo_result = _bench_cairo(
                arm_root, group, workload, warmups, samples, out_dir,
                tag, float(cairo_timeout), deadline_monotonic,
            )
            # Ladder telemetry (TRACKS §3.5): Cairo's PoW seconds live in the
            # stage-profile sidecar this call just wrote, so the envelope is
            # only read when a PoW cutpoint is actually registered.
            if group.report_schema in POW_PHASE_SECONDS_FIELDS:
                cairo_result.pow_ms = _pow_ms(
                    _load_json_object(
                        Path(cairo_result.report_path).read_text(encoding="utf-8"),
                        "Cairo bench envelope",
                    ),
                    group,
                    cairo_result.report_path,
                )
            return cairo_result
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise RunError(
                f"{workload.workload_id}: malformed {group.report_schema} report: {exc}"
            ) from exc
    proof_path = None
    product_report_path = None
    if group.report_schema == "riscv_proof_v2":
        proof_path = (out_dir / f"{workload.workload_id}.{tag}.proof.json").resolve()
    elif group.report_schema == "native_cuda_product_v6":
        proof_path = (out_dir / f"{workload.workload_id}.{tag}.proof.json").resolve()
        product_report_path = (
            out_dir / f"{workload.workload_id}.{tag}.product.json"
        ).resolve()
    command_samples = (
        1 + warmups + samples
        if group.report_schema == "native_cuda_product_v6"
        else samples
    )
    args = _format_workload_args(
        arm_root, group, workload, warmups, command_samples,
    )
    if group.report_schema == "riscv_proof_v2":
        extra = f" --proof-out {shlex.quote(str(proof_path))}"
    elif group.report_schema == "native_cuda_product_v6":
        assert proof_path is not None and product_report_path is not None
        extra = (
            f" --output {shlex.quote(str(proof_path))}"
            f" --report-out {shlex.quote(str(product_report_path))}"
        )
    else:
        extra = ""
    timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else manifest.workload_class(workload.workload_class).command_timeout_seconds
    )
    if timeout <= 0:
        raise RunError(f"{workload.workload_id}: no command time budget remains")
    run_kwargs = (
        {"deadline_monotonic": deadline_monotonic}
        if deadline_monotonic is not None else {}
    )
    stdout = _run(
        f"{binary} {args}{extra}", arm_root, timeout=float(timeout), **run_kwargs,
    )
    try:
        report = _load_json_object(stdout, "bench report")
    except (json.JSONDecodeError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: bench emitted non-JSON output "
            f"(first 200 chars: {stdout[:200]!r})"
        ) from exc
    out_path = out_dir / f"{workload.workload_id}.{tag}.json"
    try:
        if group.report_schema == "native_proof_v7":
            result = _parse_native_report(
                report, group, workload, warmups, samples, out_path,
            )
        elif group.report_schema == "riscv_proof_v2":
            assert proof_path is not None
            result = _parse_riscv_report(
                report, group, workload, warmups, samples, out_path, proof_path, arm_root,
            )
        elif group.report_schema == "native_cuda_product_v6":
            assert proof_path is not None and product_report_path is not None
            result = _parse_cuda_report(
                report,
                group,
                workload,
                warmups,
                samples,
                out_path,
                proof_path,
                product_report_path,
            )
        else:  # Manifest validation owns the supported schema set.
            raise RunError(
                f"{workload.workload_id}: unsupported report schema "
                f"{group.report_schema!r}"
            )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: malformed {group.report_schema} report: {exc}"
        ) from exc
    # Ladder telemetry (TRACKS §3.5): carried on every run so the PoW-excluded
    # boundary is a projection of measured evidence, never a separate run.
    result.pow_ms = _pow_ms(report, group, out_path)
    out_path.write_text(json.dumps(report, indent=1))
    return result


def _argument_value(tokens: list[str], flag: str) -> str:
    positions = [index for index, token in enumerate(tokens) if token == flag]
    if len(positions) != 1 or positions[0] + 1 >= len(tokens):
        raise ValueError(f"CUDA workload must contain exactly one {flag}")
    return tokens[positions[0] + 1]


def _cuda_shape_from_args(
    args: str,
) -> CudaShape | XorShape | PlonkShape | BlakeShape | PoseidonShape:
    tokens = shlex.split(args)
    if _argument_value(tokens, "--backend") != "cuda":
        raise ValueError("CUDA workload backend must equal cuda")
    application = _argument_value(tokens, "--air")
    try:
        if application == "wide_fibonacci":
            shape = CudaShape(
                int(_argument_value(tokens, "--log-n-rows")),
                int(_argument_value(tokens, "--sequence-len")),
            )
        elif application == "xor":
            shape = XorShape(
                int(_argument_value(tokens, "--log-size")),
                int(_argument_value(tokens, "--log-step")),
                int(_argument_value(tokens, "--offset")),
            )
        elif application == "plonk":
            shape = PlonkShape(
                int(_argument_value(tokens, "--log-n-rows")),
            )
        elif application == "blake":
            shape = BlakeShape(
                int(_argument_value(tokens, "--log-n-rows")),
                int(_argument_value(tokens, "--n-rounds")),
            )
        elif application == "poseidon":
            shape = PoseidonShape(
                int(_argument_value(tokens, "--log-n-instances")),
            )
        else:
            raise ValueError(f"unsupported CUDA AIR {application!r}")
        shape.validate()
    except CudaDiagnosticError as exc:
        raise ValueError(str(exc)) from exc
    if _argument_value(tokens, "--protocol") != shape.protocol:
        raise ValueError("CUDA workload protocol does not match its AIR")
    return shape


def _parse_cuda_report(
    report: dict,
    group: WorkloadGroup,
    workload: Workload,
    warmups: int,
    samples: int,
    out_path: Path,
    proof_path: Path,
    product_report_path: Path,
) -> ArmResult:
    expected = REPORT_SCHEMA_VERSIONS[group.report_schema]
    if report.get("schema_version") != expected:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} expected "
            f"{group.report_schema} (schema_version={expected}), got "
            f"schema_version={report.get('schema_version')!r}"
        )
    shape = _cuda_shape_from_args(
        _format_workload_args(
            Path("."),
            group,
            workload,
            warmups,
            1 + warmups + samples,
        )
    )
    try:
        artifact = validate_cuda_artifact(proof_path, shape)
        validated = validate_cuda_report(
            report,
            shape,
            proof_path,
            artifact,
            expected_repetitions=1 + warmups + samples,
        )
    except CudaDiagnosticError as exc:
        raise ValueError(str(exc)) from exc
    persisted = _load_json_object(
        product_report_path.read_text(encoding="utf-8"),
        "persisted CUDA product report",
    )
    if persisted != report:
        raise ValueError("persisted CUDA product report differs from stdout")
    repetition = validated["process_repetition"]
    first = 1 + warmups
    stop = first + samples

    def selected(key: str) -> list[float]:
        values = repetition[key][first:stop]
        if len(values) != samples:
            raise ValueError(f"CUDA steady vector is incomplete: {key}")
        return [float(value) for value in values]

    resident = selected("resident_prove_ns")
    verified = selected("verified_request_ns")
    if not repetition["all_canonical_bytes_identical"]:
        raise ValueError("CUDA product repetitions are not byte-identical")
    return ArmResult(
        prove_ms=statistics.median(resident) / 1_000_000.0,
        proof_verified=samples,
        byte_identical=True,
        peak_rss_mib=None,
        report_path=str(out_path),
        proof_digest=artifact["canonical_sha256"],
        proof_bytes=artifact["canonical_bytes"],
        request_ms=statistics.median(verified) / 1_000_000.0,
        mechanism={
            "residency": validated["residency"],
            "plan": validated["plan"],
            "aot": validated["aot"],
        },
        resources_complete=False,
    )


def _load_json_object(raw: str, label: str) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} has duplicate field {key!r}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return value


def _finite_number(value: object, field_name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0) or result < 0:
        qualifier = "a positive finite number" if positive else "a finite non-negative number"
        raise ValueError(f"{field_name} must be {qualifier}")
    return result


def _sha256_hex(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{field_name} must be canonical lowercase SHA-256 hex")
    return value


def _commit_hex(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError(f"{field_name} must be a full lowercase Git commit")
    return value


def _parse_native_report(
    report: dict,
    group: WorkloadGroup,
    workload: Workload,
    warmups: int,
    samples: int,
    out_path: Path,
) -> ArmResult:
    expected = REPORT_SCHEMA_VERSIONS[group.report_schema]
    actual = report.get("schema_version")
    if type(actual) is not int or actual != expected:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} expected "
            f"{group.report_schema} (schema_version={expected}), got "
            f"schema_version={actual!r}"
        )
    _validate_native_resource_admission(report, workload)
    timing = report["timing"]
    proof = report["proof"]
    if not isinstance(timing, dict) or not isinstance(proof, dict):
        raise ValueError("timing and proof must be objects")
    verified = proof.get("verified_samples")
    if type(verified) is not int or verified != samples:
        raise ValueError(f"proof.verified_samples must equal requested samples ({samples})")
    identical = proof.get("all_samples_byte_identical")
    if type(identical) is not bool:
        raise ValueError("proof.all_samples_byte_identical must be a boolean")
    sample_meta = proof.get("samples")
    if not isinstance(sample_meta, list) or len(sample_meta) != samples:
        raise ValueError(f"proof.samples must contain exactly {samples} entries")
    digests = {
        _sha256_hex(item.get("sha256") if isinstance(item, dict) else None,
                    "proof.samples[].sha256")
        for item in sample_meta
    }
    if len(digests) != 1:
        raise ValueError("proof.samples contain different proof digests")
    resources = _parse_native_resources(
        report, sample_meta, warmups, samples,
    )
    prove = timing.get("prove_seconds")
    if not isinstance(prove, dict):
        raise ValueError("timing.prove_seconds must be an object")
    request = timing.get("request_seconds")
    request_ms = None
    if request is not None:
        if not isinstance(request, dict):
            raise ValueError("timing.request_seconds must be an object")
        request_ms = _finite_number(
            request.get("median"), "timing.request_seconds.median", positive=True,
        ) * 1000.0
    return ArmResult(
        prove_ms=_finite_number(
            prove.get("median"), "timing.prove_seconds.median", positive=True,
        ) * 1000.0,
        proof_verified=verified,
        byte_identical=identical and len(digests) == 1,
        peak_rss_mib=resources["peak_rss_mib"],
        report_path=str(out_path),
        proof_digest=next(iter(digests)),
        request_ms=request_ms,
        energy_j=resources["energy_j"],
        proof_bytes=resources["proof_bytes"],
        instructions=resources["instructions"],
        cycles=resources["cycles"],
    )


def _parse_riscv_report(
    report: dict,
    group: WorkloadGroup,
    workload: Workload,
    warmups: int,
    samples: int,
    out_path: Path,
    proof_path: Path,
    arm_root: Path,
) -> ArmResult:
    expected_fields = {
        "schema", "release_status", "mode", "experimental", "profiled",
        "warmups", "samples", "verified_samples", "total_steps", "n_components",
        "throughput_numerator", "median_seconds", "throughput_mhz",
        "mean_execution_seconds", "mean_witness_seconds", "mean_proving_seconds",
        "mean_verification_seconds", "sample_seconds", "statement_sha256",
        "transcript_state_blake2s", "implementation_commit", "implementation_dirty",
        "executable_sha256", "artifact_sha256", "proof_path",
        "resources",
    }
    if set(report) != expected_fields:
        raise ValueError(
            "report fields differ: "
            f"missing={sorted(expected_fields - set(report))} "
            f"unknown={sorted(set(report) - expected_fields)}"
        )
    if report.get("schema") != group.report_schema:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} expected "
            f"schema={group.report_schema!r}, got {report.get('schema')!r}"
        )
    _admission, expected_status, expected_experimental = _riscv_admission_state(arm_root)
    if (report.get("release_status"), report.get("experimental")) != (
        expected_status, expected_experimental,
    ):
        raise ValueError("RISC-V report does not match the typed admission phase")
    if report.get("mode") != "bench" or report.get("profiled") is not False:
        raise ValueError("RISC-V report must be an unprofiled bench run")
    if type(report.get("warmups")) is not int or report["warmups"] != warmups:
        raise ValueError(f"warmups must equal requested warmups ({warmups})")
    reported_samples = report.get("samples")
    verified = report.get("verified_samples")
    if type(reported_samples) is not int or reported_samples != samples:
        raise ValueError(f"samples must equal requested samples ({samples})")
    if type(verified) is not int or verified != samples:
        raise ValueError(f"verified_samples must equal requested samples ({samples})")
    sample_seconds = report.get("sample_seconds")
    if not isinstance(sample_seconds, list) or len(sample_seconds) != samples:
        raise ValueError(f"sample_seconds must contain exactly {samples} entries")
    parsed_samples = [
        _finite_number(value, "sample_seconds[]", positive=True)
        for value in sample_seconds
    ]
    median_seconds = _finite_number(
        report.get("median_seconds"), "median_seconds", positive=True,
    )
    expected_median = sorted(parsed_samples)[len(parsed_samples) // 2]
    if not math.isclose(median_seconds, expected_median, rel_tol=1e-12, abs_tol=1e-15):
        raise ValueError("median_seconds does not match sample_seconds")
    if report.get("throughput_numerator") != "vm_steps":
        raise ValueError("throughput_numerator must equal 'vm_steps'")
    throughput = _finite_number(
        report.get("throughput_mhz"), "throughput_mhz", positive=True,
    )
    for field_name in ("total_steps", "n_components"):
        value = report.get(field_name)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{field_name} must be a positive integer")
    expected_throughput = report["total_steps"] / median_seconds / 1_000_000.0
    if not math.isclose(throughput, expected_throughput, rel_tol=1e-12, abs_tol=1e-15):
        raise ValueError("throughput_mhz is inconsistent with steps and median")
    for field_name in (
        "mean_execution_seconds", "mean_witness_seconds",
        "mean_proving_seconds", "mean_verification_seconds",
    ):
        _finite_number(
            report.get(field_name), field_name,
            positive=field_name == "mean_proving_seconds",
        )
    _sha256_hex(report.get("statement_sha256"), "statement_sha256")
    _sha256_hex(report.get("transcript_state_blake2s"), "transcript_state_blake2s")
    _commit_hex(report.get("implementation_commit"), "implementation_commit")
    if type(report.get("implementation_dirty")) is not bool:
        raise ValueError("implementation_dirty must be a boolean")
    _sha256_hex(report.get("executable_sha256"), "executable_sha256")
    if report.get("proof_path") != str(proof_path):
        raise ValueError("proof_path does not bind the requested retained artifact")
    if not proof_path.is_file():
        raise ValueError("bench did not retain the requested RISC-V proof artifact")
    artifact_bytes = proof_path.read_bytes()
    expected_artifact_digest = _sha256_hex(
        report.get("artifact_sha256"), "artifact_sha256",
    )
    if hashlib.sha256(artifact_bytes).hexdigest() != expected_artifact_digest:
        raise ValueError("artifact_sha256 does not match the retained artifact")
    artifact = _load_json_object(artifact_bytes.decode("utf-8"), "RISC-V proof artifact")
    artifact_fields = {
        "artifact_kind", "schema_version", "exchange_mode", "release_status",
        "generator", "air", "backend", "protocol", "source", "provenance",
        "pcs_config", "statement", "interaction_claim", "proof_bytes_hex",
    }
    if set(artifact) != artifact_fields:
        raise ValueError(
            "retained artifact fields differ: "
            f"missing={sorted(artifact_fields - set(artifact))} "
            f"unknown={sorted(set(artifact) - artifact_fields)}"
        )
    required = {
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 3,
        "exchange_mode": "riscv_proof_json_wire_v3",
        "release_status": expected_status,
        "generator": "zig",
        "air": "stark_v_rv32im",
        "backend": "cpu",
    }
    for field_name, expected in required.items():
        if artifact.get(field_name) != expected:
            raise ValueError(
                f"retained artifact {field_name} must equal {expected!r}"
            )
    if artifact.get("protocol") not in ("functional", "secure"):
        raise ValueError("retained artifact protocol is unsupported")
    source = artifact.get("source")
    if not isinstance(source, dict) or set(source) != {"elf_sha256", "input_sha256"}:
        raise ValueError("retained artifact source is not canonical")
    _sha256_hex(source.get("elf_sha256"), "artifact.source.elf_sha256")
    _sha256_hex(source.get("input_sha256"), "artifact.source.input_sha256")
    provenance = artifact.get("provenance")
    provenance_fields = {
        "oracle_repository", "oracle_commit", "implementation_repository",
        "implementation_commit", "implementation_dirty", "witness_layout_sha256",
    }
    if not isinstance(provenance, dict) or set(provenance) != provenance_fields:
        raise ValueError("retained artifact provenance is not canonical")
    if (
        provenance.get("oracle_repository") != "https://github.com/ClementWalter/stark-v"
        or provenance.get("oracle_commit") != "d478f783055aa0d73a93768a433a3c6c31c91d1c"
        or provenance.get("implementation_repository")
        != "https://github.com/teddyjfpender/stwo-zig"
        or provenance.get("implementation_commit") != report["implementation_commit"]
        or provenance.get("implementation_dirty") is not report["implementation_dirty"]
    ):
        raise ValueError("retained artifact provenance does not bind the report")
    _sha256_hex(
        provenance.get("witness_layout_sha256"),
        "artifact.provenance.witness_layout_sha256",
    )
    for field_name in ("pcs_config", "statement", "interaction_claim"):
        if not isinstance(artifact.get(field_name), dict):
            raise ValueError(f"retained artifact {field_name} must be an object")
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str) or not proof_hex or len(proof_hex) % 2:
        raise ValueError("proof_bytes_hex must be non-empty even-length lowercase hex")
    try:
        proof_bytes = bytes.fromhex(proof_hex)
    except ValueError as exc:
        raise ValueError("proof_bytes_hex is not hexadecimal") from exc
    if proof_bytes.hex() != proof_hex:
        raise ValueError("proof_bytes_hex is not canonical lowercase hex")
    resources = _parse_riscv_resources(
        report.get("resources"), group.resource_telemetry,
    )
    mechanism = {}
    for field_name in group.mechanism_telemetry.get("required_fields", []):
        # Every supported mechanism field was type/canonical validated above.
        mechanism[field_name] = report[field_name]
    return ArmResult(
        prove_ms=_finite_number(
            report.get("mean_proving_seconds"), "mean_proving_seconds", positive=True,
        ) * 1000.0,
        proof_verified=verified,
        # The RISC-V bench aborts before reporting if sample artifacts differ.
        byte_identical=True,
        peak_rss_mib=resources["peak_rss_mib"],
        report_path=str(out_path),
        proof_digest=hashlib.sha256(proof_bytes).hexdigest(),
        proof_bytes=len(proof_bytes),
        request_ms=_finite_number(
            median_seconds, "median_seconds", positive=True,
        ) * 1000.0,
        mechanism=mechanism,
        energy_j=resources["energy_j"],
        instructions=resources["instructions"],
        cycles=resources["cycles"],
        resources_complete=resources["complete"],
    )

def _nonnegative_integer(
    value: object, field_name: str, *, positive: bool = False,
) -> int:
    if type(value) is not int or value < 0 or (positive and value == 0):
        qualifier = "a positive integer" if positive else "a non-negative integer"
        raise ValueError(f"{field_name} must be {qualifier}")
    return value


def _parse_riscv_resources(
    resources: object, policy: dict,
) -> dict[str, float | int | bool | None]:
    if not isinstance(resources, dict):
        raise ValueError("resources must be an object")
    expected_fields = {
        "availability", "source", "scope", "unavailable_reason",
        "before_warmups", "after_verified_samples", "interval_delta",
    }
    if set(resources) != expected_fields:
        raise ValueError(
            "resources fields differ: "
            f"missing={sorted(expected_fields - set(resources))} "
            f"unknown={sorted(set(resources) - expected_fields)}"
        )
    if resources.get("source") != policy.get("source"):
        raise ValueError("resources.source does not match the manifest policy")
    if resources.get("scope") != policy.get("scope"):
        raise ValueError("resources.scope does not match the manifest policy")
    if resources.get("availability") == "unavailable":
        reasons = {
            "unsupported_platform", "before_warmups_sampling_failed",
            "after_verified_samples_sampling_failed", "counter_regression",
        }
        if resources.get("unavailable_reason") not in reasons:
            raise ValueError("unavailable resources have an invalid reason")
        if any(resources.get(field) is not None for field in (
                "before_warmups", "after_verified_samples", "interval_delta")):
            raise ValueError("unavailable resource counters must all be null")
        return {
            "complete": False,
            "peak_rss_mib": None,
            "energy_j": None,
            "instructions": None,
            "cycles": None,
        }
    if resources.get("availability") != "available":
        raise ValueError("resources.availability is invalid")
    if resources.get("unavailable_reason") is not None:
        raise ValueError("available resources must have null unavailable_reason")

    snapshot_fields = {
        "lifetime_max_phys_footprint_bytes", "energy_nj", "instructions", "cycles",
    }
    snapshots = []
    for point in ("before_warmups", "after_verified_samples"):
        snapshot = resources.get(point)
        if not isinstance(snapshot, dict) or set(snapshot) != snapshot_fields:
            raise ValueError(f"resources.{point} is not an exact RUSAGE_INFO_V6 snapshot")
        snapshots.append({
            field: _nonnegative_integer(
                snapshot.get(field), f"resources.{point}.{field}",
                positive=field == "lifetime_max_phys_footprint_bytes",
            )
            for field in snapshot_fields
        })
    before, after = snapshots
    for field in snapshot_fields:
        if after[field] < before[field]:
            raise ValueError(f"resources.{field} regressed between sampling points")

    delta = resources.get("interval_delta")
    delta_fields = {"energy_nj", "instructions", "cycles"}
    if not isinstance(delta, dict) or set(delta) != delta_fields:
        raise ValueError("resources.interval_delta is not an exact counter delta")
    for field in delta_fields:
        value = _nonnegative_integer(
            delta.get(field), f"resources.interval_delta.{field}", positive=True,
        )
        if value != after[field] - before[field]:
            raise ValueError(f"resources.interval_delta.{field} is inconsistent")
    return {
        "complete": True,
        "peak_rss_mib": (
            after["lifetime_max_phys_footprint_bytes"] / (1024.0 * 1024.0)
        ),
        "energy_j": delta["energy_nj"] / 1_000_000_000.0,
        "instructions": delta["instructions"],
        "cycles": delta["cycles"],
    }


def _exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        missing = sorted(keys - set(value)) if isinstance(value, dict) else sorted(keys)
        unknown = sorted(set(value) - keys) if isinstance(value, dict) else []
        raise ValueError(
            f"{label} fields differ: missing={missing} unknown={unknown}"
        )
    return value


def _nonempty_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _cairo_command(workload: Workload) -> tuple[str, str, bool]:
    """(command, requested proof format, verification requested) from args."""
    tokens = shlex.split(workload.args)
    if not tokens or tokens[0] not in CAIRO_COMMANDS:
        raise ValueError(
            "Cairo workload args must start with prove or run-and-prove"
        )
    proof_format = "json"
    positions = [i for i, token in enumerate(tokens) if token == "--proof-format"]
    if positions:
        if len(positions) != 1 or positions[0] + 1 >= len(tokens):
            raise ValueError("Cairo workload has a malformed --proof-format")
        proof_format = tokens[positions[0] + 1]
    if proof_format not in CAIRO_PROOF_FORMATS:
        raise ValueError(f"unsupported Cairo proof format {proof_format!r}")
    for reserved in ("--proof", "--stage-profile-out", "--report-out"):
        if reserved in tokens:
            raise ValueError(
                f"Cairo workload args must not carry {reserved}; the runner owns "
                "the output paths"
            )
    return tokens[0], proof_format, "--verify" in tokens


def _parse_cairo_report(
    report: dict,
    group: WorkloadGroup,
    workload: Workload,
    proof_path: Path,
) -> dict:
    """Fail-closed validation of ONE Cairo product proving report.

    Everything the report claims is either checked against the manifest (the
    pinned official oracle revisions, the declared binary, the requested proof
    format) or against the retained artifact on disk. Nothing is inferred and
    nothing missing is defaulted.
    """
    command, requested_format, verify_requested = _cairo_command(workload)
    if not verify_requested:
        raise ValueError(
            "a scored Cairo workload must request --verify; unverified proofs "
            "never enter a boundary measurement"
        )
    _exact_object(report, _CAIRO_REPORT_KEYS, "report")
    actual = report["schema_version"]
    if type(actual) is not int or actual != CAIRO_PRODUCT_REPORT_SCHEMA_VERSION:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} expected "
            f"{group.report_schema} (product schema_version="
            f"{CAIRO_PRODUCT_REPORT_SCHEMA_VERSION}), got schema_version={actual!r}"
        )
    if report["frontend"] != "cairo":
        raise ValueError("report.frontend must equal 'cairo'")
    backend = _nonempty_text(report["backend"], "report.backend")

    product = _exact_object(report["product"], _CAIRO_PRODUCT_KEYS, "report.product")
    if product["schema_version"] != CAIRO_PRODUCT_REPORT_SCHEMA_VERSION:
        raise ValueError("report.product.schema_version is not the pinned version")
    expected_name = Path(group.binary).name
    if product["name"] != expected_name:
        raise ValueError(
            f"report.product.name {product['name']!r} is not the group's declared "
            f"binary {expected_name!r}"
        )
    if product["frontend"] != "cairo" or product["backend"] != backend:
        raise ValueError("report.product frontend/backend disagree with the report")
    if product["role"] != "cli":
        raise ValueError("report.product.role must equal 'cli'")
    if product["optimize"] != "ReleaseFast":
        raise ValueError("a measured Cairo product must be built ReleaseFast")
    _nonempty_text(product["protocol_features"], "report.product.protocol_features")
    _nonempty_text(product["zig_version"], "report.product.zig_version")
    protocol_manifest_sha256 = _sha256_hex(
        product["protocol_manifest_sha256"], "report.product.protocol_manifest_sha256",
    )
    identity_sha256 = _sha256_hex(
        product["identity_sha256"], "report.product.identity_sha256",
    )
    source = _exact_object(
        product["source"], _CAIRO_SOURCE_KEYS, "report.product.source",
    )
    if source["repository"] != CAIRO_IMPLEMENTATION_REPOSITORY:
        raise ValueError("report.product.source.repository is not this implementation")
    _commit_hex(source["commit"], "report.product.source.commit")
    _commit_hex(source["tree"], "report.product.source.tree")
    if type(source["dirty"]) is not bool:
        raise ValueError("report.product.source.dirty must be a boolean")
    if source["dirty"]:
        _sha256_hex(
            source["dirty_content_sha256"],
            "report.product.source.dirty_content_sha256",
        )
    elif source["dirty_content_sha256"] is not None:
        raise ValueError("a clean Cairo source must have null dirty_content_sha256")
    target = _exact_object(
        product["target"], _CAIRO_TARGET_KEYS, "report.product.target",
    )
    for key in ("arch", "os", "abi", "cpu_model"):
        _nonempty_text(target[key], f"report.product.target.{key}")
    _sha256_hex(target["cpu_features_sha256"], "report.product.target.cpu_features_sha256")
    runtime = _exact_object(
        product["runtime"], _CAIRO_RUNTIME_KEYS, "report.product.runtime",
    )
    for key in sorted(_CAIRO_RUNTIME_KEYS):
        _nonempty_text(runtime[key], f"report.product.runtime.{key}")
    upstream = _exact_object(
        product["upstream"], _CAIRO_UPSTREAM_KEYS, "report.product.upstream",
    )
    oracle = group.correctness_oracle
    if oracle.get("final_validator") is not True:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} has no final-validator "
            "Cairo correctness oracle"
        )
    if upstream["stwo_cairo_revision"] != oracle.get("commit"):
        raise ValueError(
            "report.product.upstream.stwo_cairo_revision is not the manifest-pinned "
            "official stwo-cairo commit"
        )
    if upstream["stwo_revision"] != oracle.get("stwo_commit"):
        raise ValueError(
            "report.product.upstream.stwo_revision is not the manifest-pinned "
            "official stwo commit"
        )
    for key in ("cairo_language_version", "cairo_vm_version"):
        _nonempty_text(upstream[key], f"report.product.upstream.{key}")

    evidence = _exact_object(
        report["backend_evidence"], _CAIRO_BACKEND_EVIDENCE_KEYS,
        "report.backend_evidence",
    )
    _nonempty_text(evidence["execution"], "report.backend_evidence.execution")
    _nonempty_text(evidence["classification"], "report.backend_evidence.classification")
    for key in sorted(_CAIRO_BACKEND_EVIDENCE_KEYS - {"execution", "classification"}):
        _nonnegative_integer(evidence[key], f"report.backend_evidence.{key}")
    if evidence["cpu_fallbacks"] != 0:
        raise ValueError(
            "report.backend_evidence.cpu_fallbacks must be zero; a lane that fell "
            "back is not the declared product"
        )

    cache = _exact_object(
        report["preprocessed_cache"], _CAIRO_PREPROCESSED_CACHE_KEYS,
        "report.preprocessed_cache",
    )
    if type(cache["enabled"]) is not bool:
        raise ValueError("report.preprocessed_cache.enabled must be a boolean")
    for key in sorted(_CAIRO_PREPROCESSED_CACHE_KEYS - {"enabled"}):
        _nonnegative_integer(cache[key], f"report.preprocessed_cache.{key}")

    profile = _nonempty_text(report["profile"], "report.profile")
    input_sha256 = _sha256_hex(
        _exact_object(report["input"], {"sha256"}, "report.input")["sha256"],
        "report.input.sha256",
    )
    proof = _exact_object(
        report["proof"], {"format", "bytes", "sha256"}, "report.proof",
    )
    if proof["format"] != requested_format:
        raise ValueError(
            f"report.proof.format {proof['format']!r} is not the requested "
            f"{requested_format!r}"
        )
    proof_bytes = _nonnegative_integer(proof["bytes"], "report.proof.bytes", positive=True)
    proof_sha256 = _sha256_hex(proof["sha256"], "report.proof.sha256")

    timing = _exact_object(
        report["timing"], {"execute_ns", "prove_ns", "verify_ns"}, "report.timing",
    )
    execute_ns = _nonnegative_integer(timing["execute_ns"], "report.timing.execute_ns")
    prove_ns = _nonnegative_integer(
        timing["prove_ns"], "report.timing.prove_ns", positive=True,
    )
    verify_ns = _nonnegative_integer(
        timing["verify_ns"], "report.timing.verify_ns", positive=True,
    )
    verification = _exact_object(
        report["verification"], {"requested", "zig"}, "report.verification",
    )
    if verification["requested"] is not True or verification["zig"] is not True:
        raise ValueError(
            "report.verification must record a requested and completed in-process "
            "verification"
        )

    execution = report["execution"]
    if command == "prove":
        if execution is not None:
            raise ValueError("a prove report must have null execution")
        if execute_ns != 0:
            raise ValueError("a prove report must have zero execute_ns")
    else:
        execution = _exact_object(
            execution, _CAIRO_EXECUTION_KEYS, "report.execution",
        )
        _nonempty_text(execution["program_type"], "report.execution.program_type")
        _sha256_hex(execution["program_sha256"], "report.execution.program_sha256")
        if execution["arguments_sha256"] is not None:
            _sha256_hex(
                execution["arguments_sha256"], "report.execution.arguments_sha256",
            )
        _sha256_hex(execution["adapter_sha256"], "report.execution.adapter_sha256")
        wall_ns = _nonnegative_integer(
            execution["wall_ns"], "report.execution.wall_ns", positive=True,
        )
        if wall_ns != execute_ns:
            raise ValueError("report.execution.wall_ns disagrees with timing.execute_ns")

    if not proof_path.is_file():
        raise ValueError("the Cairo product did not retain the requested proof")
    artifact = proof_path.read_bytes()
    if len(artifact) != proof_bytes:
        raise ValueError("report.proof.bytes does not match the retained proof")
    if hashlib.sha256(artifact).hexdigest() != proof_sha256:
        raise ValueError("report.proof.sha256 does not match the retained proof")

    return {
        "product_identity_sha256": identity_sha256,
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "profile": profile,
        "input_sha256": input_sha256,
        "proof_format": proof["format"],
        "proof_bytes": proof_bytes,
        "proof_sha256": proof_sha256,
        "stwo_cairo_revision": upstream["stwo_cairo_revision"],
        "stwo_revision": upstream["stwo_revision"],
        "metal_dispatches": evidence["metal_dispatches"],
        "cpu_fallbacks": evidence["cpu_fallbacks"],
        "execute_seconds": execute_ns / 1_000_000_000.0,
        "prove_seconds": prove_ns / 1_000_000_000.0,
        "verify_seconds": verify_ns / 1_000_000_000.0,
        "implementation_commit": source["commit"],
    }


def _parse_cairo_stage_profile(profile: dict, workload: Workload) -> dict:
    """TRACKS §3.2 named cutpoints from one `--stage-profile-out` snapshot."""
    _exact_object(
        profile, {"schema_version", "runtime", "example", "stages"},
        "stage profile",
    )
    if profile["schema_version"] != CAIRO_STAGE_PROFILE_SCHEMA_VERSION:
        raise ValueError(
            "stage profile schema_version is not "
            f"{CAIRO_STAGE_PROFILE_SCHEMA_VERSION}"
        )
    if profile["example"] != "cairo":
        raise ValueError("stage profile is not a Cairo profile")
    _nonempty_text(profile["runtime"], "stage profile runtime")
    stages = profile["stages"]
    if not isinstance(stages, list) or not stages:
        raise ValueError("stage profile has no stages")

    owner = {}
    for phase, (required, optional) in CAIRO_PHASE_STAGES.items():
        for stage_id in required + optional:
            owner[stage_id] = phase
    seconds = {phase: 0.0 for phase in CAIRO_PHASE_STAGES}
    observed: set[str] = set()
    for index, node in enumerate(stages):
        if not isinstance(node, dict) or not {"id", "label", "seconds"} <= set(node):
            raise ValueError(f"stage profile root {index} is not a stage node")
        if set(node) - {"id", "label", "seconds", "children"}:
            raise ValueError(f"stage profile root {index} has unknown fields")
        stage_id = _nonempty_text(node["id"], f"stage profile root {index} id")
        phase = owner.get(stage_id)
        if phase is None:
            raise ValueError(
                f"{workload.workload_id}: unclassified Cairo stage root "
                f"{stage_id!r}; the phase cutpoint table must be updated before "
                "this product can be measured"
            )
        seconds[phase] += _finite_number(node["seconds"], f"stage {stage_id} seconds")
        observed.add(stage_id)
    for phase, (required, _optional) in CAIRO_PHASE_STAGES.items():
        missing = sorted(set(required) - observed)
        if missing:
            raise ValueError(
                f"{workload.workload_id}: Cairo phase {phase} is missing mandatory "
                "cutpoint stage(s): " + ", ".join(missing)
            )
    return seconds


def _bench_cairo(
    arm_root: Path,
    group: WorkloadGroup,
    workload: Workload,
    warmups: int,
    samples: int,
    out_dir: Path,
    tag: str,
    timeout: float,
    deadline_monotonic: float | None,
) -> ArmResult:
    """One arm of one Cairo round: warmups + samples cold CLI processes.

    The focused Cairo CLIs prove exactly one statement per process, so the
    harness owns the warmup/sample loop and one sample is one cold process. The
    mandatory phase profile is recorded on the FIRST discarded warmup so scored
    samples run uninstrumented.
    """
    if warmups < 1:
        raise RunError(
            f"{workload.workload_id}: Cairo measurement needs at least one warmup; "
            "the mandatory phase profile is recorded on a discarded warmup"
        )
    if samples < 1:
        raise RunError(f"{workload.workload_id}: Cairo measurement needs a sample")
    binary = arm_root / group.binary
    args = _format_workload_args(arm_root, group, workload, warmups, samples)
    run_kwargs = (
        {"deadline_monotonic": deadline_monotonic}
        if deadline_monotonic is not None else {}
    )
    stage_seconds: dict | None = None
    measured: list[dict] = []
    reports: list[dict] = []
    for index in range(warmups + samples):
        scored = index >= warmups
        proof_path = (
            out_dir / f"{workload.workload_id}.{tag}.i{index}.proof"
        ).resolve()
        proof_path.unlink(missing_ok=True)
        extra = f" --proof {shlex.quote(str(proof_path))}"
        stage_path = None
        if index == warmups - 1:
            stage_path = (
                out_dir / f"{workload.workload_id}.{tag}.stages.json"
            ).resolve()
            stage_path.unlink(missing_ok=True)
            extra += f" --stage-profile-out {shlex.quote(str(stage_path))}"
        started = time.monotonic()
        stdout = _run(
            f"{binary} {args}{extra}", arm_root, timeout=float(timeout), **run_kwargs,
        )
        cold_seconds = time.monotonic() - started
        try:
            report = _load_json_object(stdout, "Cairo product report")
        except (json.JSONDecodeError, ValueError) as exc:
            raise RunError(
                f"{workload.workload_id}: Cairo product emitted non-JSON output "
                f"(first 200 chars: {stdout[:200]!r})"
            ) from exc
        parsed = _parse_cairo_report(report, group, workload, proof_path)
        if stage_path is not None:
            stage_seconds = _parse_cairo_stage_profile(
                _load_json_object(
                    stage_path.read_text(encoding="utf-8"), "Cairo stage profile",
                ),
                workload,
            )
        if scored:
            parsed["cold_process_seconds"] = cold_seconds
            measured.append(parsed)
            reports.append(report)
        else:
            proof_path.unlink(missing_ok=True)
    if stage_seconds is None:
        raise RunError(
            f"{workload.workload_id}: no Cairo phase profile was recorded"
        )

    for field_name in (
        "profile", "input_sha256", "proof_format", "proof_bytes", "proof_sha256",
        "stwo_cairo_revision", "stwo_revision", "product_identity_sha256",
        "protocol_manifest_sha256",
    ):
        values = {sample[field_name] for sample in measured}
        if len(values) != 1:
            raise RunError(
                f"{workload.workload_id}: {field_name} changed between measured "
                f"Cairo samples ({sorted(values)})"
            )
    phase_seconds = {
        "execute": statistics.mean(s["execute_seconds"] for s in measured),
        "witness": stage_seconds["witness"],
        "commit": stage_seconds["commit"],
        "interaction": stage_seconds["interaction"],
        "composition": stage_seconds["composition"],
        "fri": stage_seconds["fri"],
        # Documented gap: proof encode/write/hash is outside the recorder.
        "serialize": None,
        "verify": statistics.mean(s["verify_seconds"] for s in measured),
    }
    available = {
        "product_identity_sha256": measured[0]["product_identity_sha256"],
        "protocol_manifest_sha256": measured[0]["protocol_manifest_sha256"],
        "profile": measured[0]["profile"],
        "input_sha256": measured[0]["input_sha256"],
        "proof_format": measured[0]["proof_format"],
        "proof_bytes": measured[0]["proof_bytes"],
        "proof_sha256": measured[0]["proof_sha256"],
        "stwo_cairo_revision": measured[0]["stwo_cairo_revision"],
        "stwo_revision": measured[0]["stwo_revision"],
        "metal_dispatches": measured[0]["metal_dispatches"],
        "cpu_fallbacks": measured[0]["cpu_fallbacks"],
        "mean_execute_seconds": phase_seconds["execute"],
        "mean_prove_seconds": statistics.mean(s["prove_seconds"] for s in measured),
        "mean_verify_seconds": phase_seconds["verify"],
        "mean_cold_process_seconds": statistics.mean(
            s["cold_process_seconds"] for s in measured
        ),
        "phase_seconds": phase_seconds,
    }
    required_fields = group.mechanism_telemetry.get("required_fields", [])
    if group.mechanism_telemetry.get("fail_closed") is not True or not required_fields:
        raise RunError(
            f"{workload.workload_id}: group {group.group_id} declares no "
            "fail-closed Cairo mechanism telemetry"
        )
    missing = sorted(set(required_fields) - set(available))
    if missing:
        raise RunError(
            f"{workload.workload_id}: Cairo mechanism telemetry cannot supply "
            + ", ".join(missing)
        )
    mechanism = {name: available[name] for name in required_fields}

    out_path = out_dir / f"{workload.workload_id}.{tag}.json"
    out_path.write_text(json.dumps({
        "schema": group.report_schema,
        "workload": workload.workload_id,
        "group": group.group_id,
        "board": group.board,
        "warmups": warmups,
        "samples": samples,
        "measurement_boundary": "cold_process",
        "phase_profile_source": {
            "invocation_index": warmups - 1,
            "scored": False,
            "note": "The stage profile is recorded on the last discarded warmup "
                    "so scored samples run uninstrumented; phase seconds are "
                    "diagnostic telemetry and are never scored (TRACKS §3.2).",
        },
        "phase_seconds": phase_seconds,
        "mechanism": mechanism,
        "measured_samples": measured,
        "product_reports": reports,
    }, indent=1))
    return ArmResult(
        # prove_ms is diagnostic telemetry on a v3 track (TRACKS §3.1).
        prove_ms=statistics.median(s["prove_seconds"] for s in measured) * 1000.0,
        proof_verified=len(measured),
        byte_identical=len({s["proof_sha256"] for s in measured}) == 1,
        peak_rss_mib=None,
        report_path=str(out_path),
        proof_digest=measured[0]["proof_sha256"],
        proof_bytes=measured[0]["proof_bytes"],
        # The scored boundary: before process creation -> after exit, with
        # independent in-process verification inside it (TRACKS §3.1).
        request_ms=statistics.median(
            s["cold_process_seconds"] for s in measured
        ) * 1000.0,
        mechanism=mechanism,
        resources_complete=False,
    )


@dataclass(frozen=True)
class SequentialStopPolicy:
    """The pre-registered group-sequential spending rule (TRACKS §3.5).

    Constant (Pocock-style) boundary: the family-wise error ``alpha`` is spent
    evenly over the ``K`` planned looks, so look ``k`` decides on a bootstrap CI
    at level ``1 - alpha/K``. Two consequences make it honest:

    * the boundary is strictly stricter than the fixed-sample gate
      (``alpha/K < alpha``), so a decisive clear at any look would also have
      cleared the full-power gate — early stopping can never admit a run that
      the fixed design would have rejected;
    * the looks, their count, and alpha come from the manifest, never from the
      run, so the design is pre-registered rather than chosen after seeing data.
    """

    rule: str
    alpha: float
    stop_on_decisive_miss: bool

    def adjusted_level(self, looks: int) -> float:
        if looks < 1:
            raise RunError("a sequential design needs at least one planned look")
        return 1.0 - (self.alpha / float(looks))


def sequential_stop_policy(
    policy: dict, *, armed: bool | None = None,
) -> SequentialStopPolicy | None:
    """Resolve the spending rule; ``None`` keeps pre-ladder round behavior.

    ``armed=True`` is how a tier that never ranks (T1) turns the rule on even
    when the manifest leaves it off for scored runs; it still refuses to invent
    parameters when the manifest has not pre-registered them.
    """
    ladder = policy.get("confirmation_ladder")
    spec = ladder.get("sequential_stop") if isinstance(ladder, dict) else None
    if not isinstance(spec, dict):
        if armed:
            raise RunError(
                "sequential early stopping requires a pre-registered "
                "gates_policy.confirmation_ladder.sequential_stop block"
            )
        return None
    enabled = bool(spec.get("enabled")) if armed is None else bool(armed)
    if not enabled:
        return None
    if spec.get("rule") != SEQUENTIAL_STOP_RULE:
        raise RunError(
            f"unsupported sequential stop rule {spec.get('rule')!r}: only "
            f"{SEQUENTIAL_STOP_RULE} is pre-registered"
        )
    alpha = spec.get("alpha")
    if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
        raise RunError("sequential stop alpha must be a number")
    alpha = float(alpha)
    if not 0.0 < alpha <= 0.5:
        raise RunError("sequential stop alpha must be in (0, 0.5]")
    return SequentialStopPolicy(
        rule=SEQUENTIAL_STOP_RULE,
        alpha=alpha,
        stop_on_decisive_miss=bool(spec.get("stop_on_decisive_miss", True)),
    )


def _dig(report: object, path: tuple[str, ...]) -> object:
    node: object = report
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _finite_or_none(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _flatten_stage_nodes(nodes: object, prefix: str, out: dict[str, float]) -> None:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id:
            continue
        name = f"{prefix}{node_id}"
        seconds = _finite_or_none(node.get("seconds"))
        if seconds is not None:
            out[f"stage:{name}"] = seconds
        _flatten_stage_nodes(node.get("children"), f"{name}.", out)


def report_phases(report: dict, group: WorkloadGroup) -> dict[str, float]:
    """Named phase seconds from whatever the group's report schema provides.

    Combines the schema's declared §3.2 cutpoints with any stage-profile tree
    the report carries (``--stage-profile-out`` shape), flattened to dotted
    ``stage:<parent>.<child>`` names. Never scored — phase telemetry gates
    scheduling and G3 only.
    """
    phases: dict[str, float] = {}
    for name, path in PHASE_SECONDS_FIELDS.get(group.report_schema, {}).items():
        seconds = _finite_or_none(_dig(report, path))
        if seconds is not None:
            phases[name] = seconds
    timing = report.get("timing")
    if isinstance(timing, dict):
        profiles = timing.get("stage_profiles")
        if isinstance(profiles, list):
            for profile in profiles:
                if isinstance(profile, dict):
                    _flatten_stage_nodes(profile.get("stages"), "", phases)
    single = report.get("stage_profile")
    if isinstance(single, dict):
        _flatten_stage_nodes(single.get("stages"), "", phases)
    _flatten_stage_nodes(report.get("stages"), "", phases)
    return phases


def resolve_phase(phases: dict[str, float], phase: str) -> str:
    """Map a submission's claimed phase name onto a measured phase key."""
    if phase in phases:
        return phase
    stage_key = f"stage:{phase}"
    if stage_key in phases:
        return stage_key
    suffixes = sorted(
        key for key in phases
        if key.split(":")[-1].split(".")[-1] == phase
    )
    if len(suffixes) == 1:
        return suffixes[0]
    if len(suffixes) > 1:
        raise RunError(
            f"claimed phase {phase!r} is ambiguous across measured phases: "
            + ", ".join(suffixes[:6])
        )
    raise RunError(
        f"claimed phase {phase!r} is not reported by this group; measured "
        "phases: " + (", ".join(sorted(phases)[:12]) or "none")
    )


def _stage_profile_sidecar(report_path: str | Path) -> Path:
    """The stage-profile document written beside a bench envelope."""
    path = Path(report_path)
    return path.with_suffix(STAGE_PROFILE_SIDECAR_SUFFIX)


def _pow_ms(
    report: dict, group: WorkloadGroup, report_path: str | Path,
) -> float | None:
    """Measured proof-of-work milliseconds, or None when the schema has none."""
    source = POW_PHASE_SECONDS_FIELDS.get(group.report_schema)
    if source is None:
        return None
    if source.kind == "report_field":
        seconds = _finite_or_none(_dig(report, source.field_path))
    elif source.kind == "stage_profile_sidecar":
        sidecar = _stage_profile_sidecar(report_path)
        if not sidecar.is_file():
            raise RunError(
                f"group {group.group_id}: the proof-of-work stage profile is "
                f"missing at {sidecar}; the PoW-excluded boundary refuses to "
                "guess a duration that was not recorded"
            )
        try:
            profile = _load_json_object(
                sidecar.read_text(encoding="utf-8"), "stage profile",
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise RunError(
                f"group {group.group_id}: unreadable proof-of-work stage "
                f"profile at {sidecar}: {exc}"
            ) from exc
        stages: dict[str, float] = {}
        _flatten_stage_nodes(profile.get("stages"), "", stages)
        missing = [
            stage_id for stage_id in source.stage_ids
            if f"stage:{stage_id}" not in stages
        ]
        if missing:
            raise RunError(
                f"group {group.group_id}: the stage profile does not record "
                + ", ".join(missing)
                + "; the PoW-excluded boundary cannot subtract an unrecorded stage"
            )
        seconds = sum(stages[f"stage:{stage_id}"] for stage_id in source.stage_ids)
    else:  # The registry is code; an unknown kind is a programming error.
        raise RunError(
            f"group {group.group_id}: unsupported proof-of-work source kind "
            f"{source.kind!r}"
        )
    if seconds is None or seconds < 0.0:
        raise RunError(
            f"group {group.group_id}: report declares a proof-of-work cutpoint "
            "but did not report a finite non-negative value"
        )
    return seconds * 1000.0


def require_pow_boundary(
    group: WorkloadGroup, tier: str | None = None,
) -> PowBoundarySource:
    """Resolve a group's PoW source, failing closed on both honesty rules.

    Rule one: a schema with no measured PoW cutpoint cannot exclude one.
    Rule two: a CROSS-INVOCATION source is an estimate, so only the tier that
    never ranks may pair on it.
    """
    source = POW_PHASE_SECONDS_FIELDS.get(group.report_schema)
    if source is None:
        raise RunError(
            f"group {group.group_id}: report schema {group.report_schema!r} "
            "exposes no proof-of-work cutpoint, so the PoW-excluded fast "
            "boundary cannot be measured. The product must report the PoW "
            "phase (§3.2) before --fast-boundary can subtract it; the harness "
            "never subtracts an unmeasured cost."
        )
    if source.cross_invocation and tier != CROSS_INVOCATION_POW_TIER:
        raise RunError(
            f"group {group.group_id}: its proof-of-work seconds are measured on "
            f"the {source.invocation} rather than the scored sample, so "
            "subtracting them yields a cross-invocation ESTIMATE. That is "
            f"admissible only at {CROSS_INVOCATION_POW_TIER}, which never ranks "
            f"(TRACKS §3.5); this call declared tier={tier!r}."
        )
    return source


def paired_rounds(
    a_root: Path,
    b_root: Path,
    manifest: Manifest,
    workload: Workload,
    policy: dict,
    out_dir: Path,
    stop_theta: float | None = None,
    round_budget: int | None = None,
    minimum_rounds_override: int | None = None,
    deadline_monotonic: float | None = None,
    sequential_stop: bool | None = None,
    fast_boundary: bool = False,
    tier: str | None = None,
) -> WorkloadScore:
    """ABBA round pairs until the CI half-width is under theta/2 or a cap hits.

    ``tier`` is declared by ladder callers only; it gates the cross-invocation
    PoW estimate to the tier that never ranks (see ``require_pow_boundary``).
    """
    warmups = int(policy["warmups"])
    samples = int(policy["samples_per_round"])
    min_rounds = (
        int(minimum_rounds_override)
        if minimum_rounds_override is not None
        else int(policy["min_rounds"])
    )
    max_rounds = round_budget or int(policy["max_rounds"])
    if min_rounds > max_rounds:
        raise RunError("minimum round target exceeds the round budget")
    stop_theta = stop_theta if stop_theta is not None else float(policy["theta_floor"])
    cap = int(policy["wall_clock_cap_seconds"][workload.workload_class])
    started = time.monotonic()

    ratios: list[float] = []
    a_meds: list[float] = []
    b_meds: list[float] = []
    reports: list[str] = []
    rss_a: list[float] = []
    rss_b: list[float] = []
    energy_a: list[float] = []
    energy_b: list[float] = []
    proof_sizes_a: list[int] = []
    proof_sizes_b: list[int] = []
    request_ratios: list[float] = []
    requests_b: list[float] = []
    fast_ratios: list[float] = []
    fast_requests_b: list[float] = []
    cross_digest: str | None = None
    cross_proof_bytes: int | None = None
    mechanism_reference: dict | None = None
    mechanism_verified: bool | None = None
    resources_complete: bool | None = None
    group = manifest.group(workload.group_id)
    stop_policy = sequential_stop_policy(policy, armed=sequential_stop)
    stop_evidence: dict | None = None
    boundary = FULL_BOUNDARY
    pow_source: PowBoundarySource | None = None
    pow_ms_a: list[float] = []
    pow_ms_b: list[float] = []
    if fast_boundary:
        pow_source = require_pow_boundary(group, tier)
        boundary = pow_source.boundary_label

    round_no = 0
    while round_no < max_rounds:
        if round_no >= min_rounds:
            now = time.monotonic()
            if now - started >= cap or (
                deadline_monotonic is not None and now >= deadline_monotonic
            ):
                break
        round_no += 1
        order = ("a", "b") if round_no % 2 == 1 else ("b", "a")
        results: dict[str, ArmResult] = {}
        for arm in order:
            root = a_root if arm == "a" else b_root
            now = time.monotonic()
            remaining = cap - (now - started)
            if deadline_monotonic is not None:
                remaining = min(remaining, deadline_monotonic - now)
            if remaining <= 0:
                raise RunError(
                    f"{workload.workload_id}: class wall-clock budget exhausted "
                    f"before completing paired round {round_no}"
                )
            command_timeout = min(
                float(policy.get("command_timeout_seconds", 1200)),
                remaining,
            )
            results[arm] = bench_once(
                root, manifest, workload, warmups, samples, out_dir, f"{arm}{round_no}",
                timeout_seconds=command_timeout,
                deadline_monotonic=deadline_monotonic,
            )
        a, b = results["a"], results["b"]
        if a.proof_verified < samples or b.proof_verified < samples:
            raise RunError(f"{workload.workload_id}: unverified proofs in round {round_no}")
        if not a.byte_identical or not b.byte_identical:
            raise RunError(
                f"{workload.workload_id}: proof bytes changed across verified samples "
                f"in round {round_no}"
            )
        # G1 conformance is CROSS-ARM: the candidate's proof bytes must equal
        # the predecessor's, per round, not merely be self-consistent per arm.
        if a.proof_digest and b.proof_digest and a.proof_digest != b.proof_digest:
            raise RunError(
                f"{workload.workload_id}: cross-arm proof digest mismatch in round "
                f"{round_no} (predecessor {a.proof_digest[:12]} vs candidate "
                f"{b.proof_digest[:12]}) — conformance failure"
            )
        if cross_digest is None:
            cross_digest = b.proof_digest
        elif b.proof_digest and b.proof_digest != cross_digest:
            raise RunError(
                f"{workload.workload_id}: proof digest changed between rounds — "
                f"nondeterministic proof bytes"
            )
        if not a.proof_bytes or not b.proof_bytes or a.proof_bytes != b.proof_bytes:
            raise RunError(
                f"{workload.workload_id}: cross-arm proof byte length mismatch"
            )
        if cross_proof_bytes is None:
            cross_proof_bytes = b.proof_bytes
        elif b.proof_bytes != cross_proof_bytes:
            raise RunError(
                f"{workload.workload_id}: proof byte length changed between rounds"
            )
        if group.report_schema == "riscv_proof_v2":
            if a.mechanism is None or b.mechanism is None:
                raise RunError(
                    f"{workload.workload_id}: RISC-V mechanism telemetry is absent"
                )
            stable_a = {
                key: a.mechanism.get(key) for key in RISCV_STABLE_MECHANISM_FIELDS
            }
            stable_b = {
                key: b.mechanism.get(key) for key in RISCV_STABLE_MECHANISM_FIELDS
            }
            if stable_a != stable_b:
                raise RunError(
                    f"{workload.workload_id}: semantic mechanism telemetry differs "
                    f"across A/B in round {round_no}"
                )
            if mechanism_reference is not None and stable_b != mechanism_reference:
                raise RunError(
                    f"{workload.workload_id}: semantic mechanism telemetry changed "
                    "between rounds"
                )
            mechanism_reference = stable_b
            mechanism_verified = True
            if a.resources_complete is not b.resources_complete:
                raise RunError(
                    f"{workload.workload_id}: RISC-V resource availability differs "
                    f"across A/B in round {round_no}"
                )
            if resources_complete is None:
                resources_complete = bool(b.resources_complete)
            else:
                resources_complete = resources_complete and bool(b.resources_complete)
        if a.request_ms and b.request_ms:
            request_ratios.append(b.request_ms / a.request_ms)
            requests_b.append(b.request_ms)
        if fast_boundary:
            # BOTH numbers are reported: the full verified-request boundary
            # above, and the PoW-excluded one that T0/T1 actually pair on.
            fast_a = _fast_boundary_ms(a, workload)
            fast_b_ms = _fast_boundary_ms(b, workload)
            fast_ratios.append(fast_b_ms / fast_a)
            fast_requests_b.append(fast_b_ms)
            ratios.append(fast_b_ms / fast_a)
            a_meds.append(fast_a)
            b_meds.append(fast_b_ms)
            # The subtracted quantity is itself evidence: record it per arm so
            # a reader can see what was removed, not just the remainder.
            pow_ms_a.append(float(a.pow_ms or 0.0))
            pow_ms_b.append(float(b.pow_ms or 0.0))
        else:
            ratios.append(b.prove_ms / a.prove_ms)
            a_meds.append(a.prove_ms)
            b_meds.append(b.prove_ms)
        reports.extend([a.report_path, b.report_path])
        for dimension, a_value, b_value, a_values, b_values in (
            ("peak_rss_mib", a.peak_rss_mib, b.peak_rss_mib, rss_a, rss_b),
            ("energy_j", a.energy_j, b.energy_j, energy_a, energy_b),
            ("proof_bytes", a.proof_bytes, b.proof_bytes, proof_sizes_a, proof_sizes_b),
        ):
            if (a_value is None) != (b_value is None):
                raise RunError(
                    f"{workload.workload_id}: {dimension} availability differs "
                    f"across A/B in round {round_no}"
                )
            if a_value is not None and b_value is not None:
                a_values.append(a_value)
                b_values.append(b_value)

        elapsed = time.monotonic() - started
        if round_no >= min_rounds:
            ci = stats.bootstrap_ci(ratios, seed=_seed(workload.workload_id, 0))
            if (ci[1] - ci[0]) / 2.0 <= stop_theta / 2.0:
                break
            if stop_policy is not None:
                stop_evidence = _sequential_stop_look(
                    stop_policy, ratios, workload, stop_theta,
                    round_no, min_rounds, max_rounds,
                )
                if stop_evidence["decision"] != "continue":
                    break
            if elapsed > cap:
                break
        elif elapsed > cap and round_no >= 3:
            break

    if len(ratios) < 3:
        raise RunError(
            f"{workload.workload_id}: class wall deadline left fewer than "
            "three complete paired rounds"
        )

    r = stats.hodges_lehmann(ratios)
    ci = stats.bootstrap_ci(ratios, seed=_seed(workload.workload_id, 0))
    resource_estimates: dict[str, dimensions.RatioEstimate] = {}
    for dimension, a_values, b_values in (
        ("peak_rss_mib", rss_a, rss_b),
        ("energy_j", energy_a, energy_b),
    ):
        if a_values:
            resource_estimates[dimension] = dimensions.paired_ratio_estimate(
                a_values,
                b_values,
                ci_level=float(policy["ci_level"]),
                seed=_seed(f"{workload.workload_id}:{dimension}", 0),
            )
    if proof_sizes_a:
        if len(set(proof_sizes_a)) != 1 or len(set(proof_sizes_b)) != 1:
            raise RunError(
                f"{workload.workload_id}: canonical proof size changed between rounds"
            )
        resource_estimates["proof_bytes"] = dimensions.exact_ratio(
            proof_sizes_a[0], proof_sizes_b[0],
        )
    rss_estimate = resource_estimates.get("peak_rss_mib")
    rss_ratio = rss_estimate.ratio if rss_estimate is not None else None
    candidate_resources = {}
    for dimension, values in (
        ("request_ms", requests_b),
        ("peak_rss_mib", rss_b),
        ("energy_j", energy_b),
        ("proof_bytes", proof_sizes_b),
        ("fast_request_ms", fast_requests_b),
    ):
        if values:
            ordered_values = sorted(float(value) for value in values)
            candidate_resources[dimension] = ordered_values[len(ordered_values) // 2]
    request_ratio = (
        sorted(request_ratios)[len(request_ratios) // 2] if request_ratios else None
    )
    fast_request_ratio = (
        sorted(fast_ratios)[len(fast_ratios) // 2] if fast_ratios else None
    )
    if stop_policy is not None and (
        stop_evidence is None or stop_evidence["decision"] == "continue"
    ):
        stop_evidence = _sequential_stop_look(
            stop_policy, ratios, workload, stop_theta,
            len(ratios), min_rounds, max_rounds, exhausted=True,
        )
    return WorkloadScore(
        workload=workload,
        ratios=ratios,
        r=r,
        ci=ci,
        a_median_ms=sorted(a_meds)[len(a_meds) // 2],
        b_median_ms=sorted(b_meds)[len(b_meds) // 2],
        rss_ratio=rss_ratio,
        reports=reports,
        proof_digest=cross_digest,
        request_ratio=request_ratio,
        report_sha256s=[
            hashlib.sha256(Path(rp).read_bytes()).hexdigest() for rp in reports
        ],
        mechanism_verified=mechanism_verified,
        resource_estimates=resource_estimates,
        candidate_resources=candidate_resources,
        proof_bytes=cross_proof_bytes or 0,
        measurement_seconds=elapsed,
        resources_complete=resources_complete,
        boundary=boundary,
        sequential_stop=stop_evidence,
        fast_request_ratio=fast_request_ratio,
        boundary_evidence=_boundary_evidence(
            pow_source, tier, pow_ms_a, pow_ms_b,
            group.report_schema, fast_ratios, request_ratios,
        ),
    )


def _fast_boundary_ms(arm: ArmResult, workload: Workload) -> float:
    """Verified-request milliseconds minus the MEASURED proof-of-work phase."""
    if arm.request_ms is None or arm.pow_ms is None:
        raise RunError(
            f"{workload.workload_id}: the PoW-excluded boundary needs both a "
            "verified-request time and a measured proof-of-work phase"
        )
    remainder = arm.request_ms - arm.pow_ms
    if not math.isfinite(remainder) or remainder <= 0.0:
        raise RunError(
            f"{workload.workload_id}: measured proof-of-work time is not "
            "smaller than the verified request time"
        )
    return remainder


def _median(values: list[float]) -> float | None:
    return sorted(values)[len(values) // 2] if values else None


def _boundary_evidence(
    pow_source: PowBoundarySource | None,
    tier: str | None,
    pow_ms_a: list[float],
    pow_ms_b: list[float],
    report_schema: str,
    fast_ratios: list[float],
    request_ratios: list[float],
) -> dict | None:
    """Label what the fast boundary removed, and how well it knew it.

    An estimate that reads like a measurement is the failure mode this block
    exists to prevent, so the label is spelled out in words next to the numbers.
    """
    if pow_source is None:
        return None
    estimate = pow_source.cross_invocation
    label = (
        "cross-invocation estimate: the subtracted proof-of-work seconds were "
        f"measured on the {pow_source.invocation} of the same arm in the same "
        "round, not on the scored sample. pow 26 is ~constant work, so this is "
        "sound for a paired delta on a tier that never ranks — it is not a "
        "measurement of the scored invocation and must never be reported as one."
        if estimate else
        "measurement: the subtracted proof-of-work seconds were measured on the "
        "scored sample itself."
    )
    return {
        "boundary": pow_source.boundary_label,
        "full_boundary": "verified_request_ms",
        "estimate": estimate,
        "label": label,
        "tier": tier,
        "pow_source": pow_source.describe(report_schema),
        "pow_ms": {
            "predecessor_median": _median(pow_ms_a),
            "candidate_median": _median(pow_ms_b),
        },
        "rounds": len(fast_ratios),
        "full_request_rounds": len(request_ratios),
    }


def _sequential_stop_look(
    stop_policy: SequentialStopPolicy,
    ratios: list[float],
    workload: Workload,
    stop_theta: float,
    round_no: int,
    min_rounds: int,
    max_rounds: int,
    *,
    exhausted: bool = False,
) -> dict:
    """One pre-registered look at the theta bar; deterministic by construction."""
    looks = max(max_rounds - min_rounds + 1, 1)
    level = stop_policy.adjusted_level(looks)
    adjusted = stats.bootstrap_ci(
        ratios, level=level, seed=_seed(workload.workload_id, 0),
    )
    bar = 1.0 - stop_theta
    if adjusted[1] < bar:
        decision = "decisive_clear"
    elif stop_policy.stop_on_decisive_miss and adjusted[0] > bar:
        decision = "decisive_miss"
    else:
        decision = "budget_exhausted" if exhausted else "continue"
    return {
        "rule": stop_policy.rule,
        "alpha": stop_policy.alpha,
        "planned_looks": looks,
        "look": max(round_no - min_rounds + 1, 1),
        "min_rounds": min_rounds,
        "max_rounds": max_rounds,
        "rounds": len(ratios),
        "adjusted_ci_level": level,
        "adjusted_ci": [adjusted[0], adjusted[1]],
        "theta_bar": bar,
        "decision": decision,
        "stop_on_decisive_miss": stop_policy.stop_on_decisive_miss,
    }


def _seed(workload_id: str, round_no: int) -> int:
    digest = hashlib.sha256(f"{workload_id}:{round_no}".encode()).digest()
    return int.from_bytes(digest[:4], "big")


def environment_block(
    repo_root: Path,
    judged: bool,
    admission_preflight: dict | None = None,
) -> dict:
    clean = _git(repo_root, "status", "--porcelain") == ""
    zig = _try(lambda: _run("zig version", repo_root, 60).strip())
    return {
        "host": hashlib.sha256(platform.node().encode()).hexdigest()[:12],
        "os": f"{platform.system()} {platform.release()}",
        "zig_version": zig,
        "release_fast": True,
        "clean_tree": clean,
        "judge_lock_held": judged,
        # Preserve the state that admitted the measurement. Re-sampling here,
        # after the battery, can hide a busy start or falsely blame the run for
        # load created by its own work.
        "preflight": (
            admission_preflight
            if admission_preflight is not None
            else _preflight()
        ),
    }


def _preflight() -> dict:
    try:
        load1 = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        return {"load_ok": load1 < cores * 0.75, "load1": round(load1, 2)}
    except OSError:
        return {"load_ok": True, "load1": None}


def require_quiet_preflight() -> dict:
    """Fail closed before Apple timing when the host is already busy.

    Linux qualification runners retain the existing telemetry-only behavior:
    their load average is not calibrated to the Apple quiet-host policy.
    """
    preflight = _preflight()
    if platform.system() == "Darwin" and not preflight["load_ok"]:
        cores = os.cpu_count() or 1
        threshold = cores * 0.75
        raise RunError(
            "Apple timing refused before measurement: "
            f"load1={preflight['load1']} exceeds the quiet-host threshold "
            f"{threshold:.2f} ({cores} logical cores). Wait for cooldown and "
            "stop co-runners, then rerun; no timing samples were taken."
        )
    return preflight


def acquire_judge_lock(repo_root: Path) -> Path:
    """Host-wide exclusivity: judged and searcher runs refuse to overlap.

    Atomic O_CREAT|O_EXCL create; a lock whose recorded pid is dead is stale
    and reclaimed. The path is host-wide by design (one judge per machine).
    """
    lock = Path("/tmp/stwo-perf-judge.lock")
    payload = f"{os.getpid()} {repo_root}\n".encode()
    for _ in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, payload)
            os.close(fd)
            return lock
        except FileExistsError:
            try:
                pid = int(lock.read_text().split()[0])
                os.kill(pid, 0)
            except PermissionError as exc:
                # Process exists under another user: the lock is live.
                raise RunError(f"judge lock held by another user ({lock})") from exc
            except (ValueError, IndexError, ProcessLookupError, OSError):
                lock.unlink(missing_ok=True)  # stale; retry once
                continue
            raise RunError(f"judge lock held by pid {pid} ({lock})")
    raise RunError(f"could not acquire judge lock ({lock})")


def draw_holdout(manifest: Manifest, workload_class: str, seed: int,
                 board: str = "core_cpu") -> Workload | None:
    """Seeded jittered hold-out inside class bounds (playbook F.7)."""
    import random

    group = manifest.group_for_board(board)
    group_generator = group.holdout_generator
    if group_generator.get("strategy") == "seeded_workload_pool_v1":
        candidates = [
            workload for workload in group.workloads
            if workload.workload_class == workload_class
        ]
        if not candidates:
            return None
        primary = candidates[0]
        by_id = {workload.workload_id: workload for workload in candidates}
        pool_ids = group_generator.get("pools", {}).get(workload_class, [])
        pool = [
            by_id[workload_id]
            for workload_id in pool_ids
            if workload_id in by_id and workload_id != primary.workload_id
        ]
        if not pool:
            raise RunError(
                f"group {group.group_id}: holdout pool for {workload_class} "
                "has no workload different from the primary workload"
            )
        selected = random.Random(seed).choice(pool)
        return Workload(
            f"holdout_{selected.workload_id}",
            workload_class,
            selected.args,
            selected.native_unit,
            selected.group_id,
        )

    gen = manifest.raw["workload_registry"].get("holdout_generator", {})
    bounds = gen.get(workload_class)
    if not bounds:
        return None
    candidates = manifest.workloads(workload_class, board=board)
    if not candidates:
        return None
    rng = random.Random(seed)
    base = candidates[0]
    log_lo, log_hi = bounds["log_n_rows"]
    log_n = rng.randint(log_lo, log_hi)
    args = _replace_flag(base.args, "--log-n-rows", str(log_n))
    if bounds.get("sequence_len"):
        seq_lo, seq_hi = bounds["sequence_len"]
        args = _replace_flag(args, "--sequence-len", str(rng.randint(seq_lo, seq_hi)))
    return Workload(f"holdout_{workload_class}", workload_class, args,
                    base.native_unit, base.group_id)


def _replace_flag(args: str, flag: str, value: str) -> str:
    parts = args.split()
    if flag in parts:
        parts[parts.index(flag) + 1] = value
    return " ".join(parts)


def aa_dispersion(ci: tuple[float, float] | list[float]) -> float:
    """Conservatively cover both interval width and A/A center bias."""
    return max(abs(ci[0] - 1.0), abs(ci[1] - 1.0))


def evaluate_aa(repo_root: Path, manifest: Manifest, workload_class: str,
                out_dir: Path, board: str = "core_cpu",
                allow_staged: bool = False,
                require_quiet_host: bool = False) -> dict:
    """A/A run (both arms = this tree): measures the per-class dispersion that
    theta is built from. ``allow_staged`` is an explicit calibration-only path
    for a disabled board; ordinary evaluation remains fail-closed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    skipped = announce_skipped_groups(manifest)
    workloads = _board_workloads(
        manifest, board, workload_class, allow_staged=allow_staged
    )
    if not workloads:
        raise RunError(
            f"no enabled workloads registered for board {board}, class {workload_class}"
        )
    group_ids = {workload.group_id for workload in workloads}
    if len(group_ids) != 1:
        raise RunError(f"board {board} selected workloads from multiple groups")
    group_id = next(iter(group_ids))
    policy = manifest.gates_for_workload(group_id, workload_class)
    build_arm(repo_root, manifest, groups=[manifest.group(group_id)])
    admission_preflight = (
        require_quiet_preflight() if require_quiet_host else _preflight()
    )
    scores = [
        paired_rounds(repo_root, repo_root, manifest, workload, policy, out_dir)
        for workload in workloads
    ]
    portfolio = portfolio_summary(scores, float(policy["ci_level"]))
    half_width = (portfolio["ci"][1] - portfolio["ci"][0]) / 2.0
    dispersion = aa_dispersion(portfolio["ci"])
    return {
        "workload_class": workload_class,
        "board": board,
        "workload": (
            workloads[0].workload_id if len(workloads) == 1
            else f"portfolio[{len(workloads)}]"
        ),
        "workloads": [workload.workload_id for workload in workloads],
        "rounds": min(len(score.ratios) for score in scores),
        "rounds_per_workload": {
            score.workload.workload_id: len(score.ratios) for score in scores
        },
        "aa_r": round(portfolio["r"], 6),
        "portfolio": {
            "ci_method": portfolio["ci_method"],
            "ci_level": portfolio["ci_level"],
            "bootstrap_iterations": portfolio["bootstrap_iterations"],
            "seed": portfolio["seed"],
            "ci": [round(portfolio["ci"][0], 6), round(portfolio["ci"][1], 6)],
            "prove_ms_method": portfolio["prove_ms_method"],
            "b_median_ms_geomean": round(
                portfolio["b_median_ms_geomean"], 6
            ),
            "proof_bytes_method": portfolio["proof_bytes_method"],
            "proof_bytes": portfolio["proof_bytes"],
            "measurement_seconds": round(portfolio["measurement_seconds"], 6),
            "measurement_rounds": portfolio["measurement_rounds"],
        },
        "anchor_prove_ms": round(portfolio["b_median_ms_geomean"], 6),
        "anchor_request_ms": _rounded_candidate_geomean(scores, "request_ms"),
        "anchor_resources": {
            name: _rounded_candidate_geomean(scores, name)
            for name in ("peak_rss_mib", "energy_j", "proof_bytes")
        },
        "per_workload": {
            score.workload.workload_id: {
                "rounds": len(score.ratios),
                "r": round(score.r, 6),
                "ci": [round(score.ci[0], 6), round(score.ci[1], 6)],
                "a_median_ms": round(score.a_median_ms, 6),
                "b_median_ms": round(score.b_median_ms, 6),
            }
            for score in scores
        },
        "half_width": round(half_width, 6),
        "dispersion": round(dispersion, 6),
        "preflight": admission_preflight,
        "skipped_groups": skipped,
        "record_as": {
            "ledger/epochs.json": {"aa_dispersion": {
                board: {workload_class: round(dispersion, 6)},
            }},
            "MANIFEST.json": {"harness": {"anchor_prove_ms": {
                board: {
                    workload_class: round(portfolio["b_median_ms_geomean"], 6)
                },
            }}},
        },
    }


def _rounded_candidate_geomean(
    scores: list[WorkloadScore], dimension: str,
) -> float | None:
    values = [score.candidate_resources.get(dimension) for score in scores]
    if not values or any(value is None for value in values):
        return None
    return round(stats.geometric_mean([float(value) for value in values]), 6)


def _current_era(repo_root: Path, era: int | None) -> int:
    if era is not None:
        return int(era)
    try:
        return int(ledger.current_epoch(repo_root)["epoch"])
    except (ledger.LedgerError, KeyError, OSError, ValueError) as exc:
        raise RunError(f"cannot resolve the current era: {exc}") from exc


def proxy_selection(
    manifest: Manifest, board: str, workload_class: str, era: int,
) -> tuple[list[Workload], dict | None, dict, list[str]]:
    """Resolve the class's proxy fixture and its era validity state.

    Returns ``(workloads, fixture, validity, markers)``. A class without a
    declared proxy falls back to its real workloads and says so loudly: the
    ladder degrades to "slow but honest", never to "fast but unlabelled".
    """
    group = manifest.group_for_board(board)
    fixture = manifest.proxy_fixture(workload_class)
    validity = manifest.proxy_validity_state(board, workload_class, era)
    markers: list[str] = []
    if fixture is None:
        markers.append(
            f"no proxy fixture declared for class {workload_class}; iterating "
            "on the full class basket"
        )
        return (
            _board_workloads(manifest, board, workload_class),
            None,
            validity,
            markers,
        )
    if not validity["validated"]:
        markers.append("proxy unvalidated: " + str(validity["reason"]))
    workload = Workload(
        fixture["proxy_id"],
        workload_class,
        fixture["args"],
        fixture["native_unit"],
        group.group_id,
    )
    return [workload], fixture, validity, markers


def phase_prefilter(
    predecessor_root: Path,
    repo_root: Path,
    manifest: Manifest,
    workload_class: str,
    out_dir: Path,
    *,
    board: str,
    phase: str,
    era: int | None = None,
) -> dict:
    """T0: one stage-profiled sample per arm; the claimed phase must move.

    A claimed FRI win that only moves witness time dies here in seconds
    instead of surviving to a 45-minute T2 run (TRACKS §3.5). T0 never ranks.
    """
    era = _current_era(repo_root, era)
    ladder = manifest.confirmation_ladder
    tier = (ladder.get("tiers") or {}).get("T0")
    if not isinstance(tier, dict):
        raise RunError(
            "T0 requires a pre-registered gates_policy.confirmation_ladder.tiers.T0"
        )
    warmups = int(tier["warmups"])
    samples = int(tier["samples"])
    min_move = float(tier["min_phase_move"])
    workloads, fixture, validity, markers = proxy_selection(
        manifest, board, workload_class, era,
    )
    if not workloads:
        raise RunError(
            f"no enabled workloads registered for board {board}, class {workload_class}"
        )
    workload = workloads[0]
    group = manifest.group(workload.group_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    build_arm(predecessor_root, manifest, groups=[group])
    build_arm(repo_root, manifest, groups=[group])
    started = time.monotonic()
    arms: dict[str, ArmResult] = {}
    reports: dict[str, dict] = {}
    for arm, root in (("a", predecessor_root), ("b", repo_root)):
        arms[arm] = bench_once(
            root, manifest, workload, warmups, samples, out_dir, f"t0{arm}",
        )
        reports[arm] = _load_json_object(
            Path(arms[arm].report_path).read_text(encoding="utf-8"),
            "T0 bench report",
        )
    elapsed = time.monotonic() - started
    a, b = arms["a"], arms["b"]
    # Correctness smoke: the cross-arm proof identity that G1 demands, checked
    # before any timing claim is believed.
    smoke_ok = bool(a.proof_digest and b.proof_digest and a.proof_digest == b.proof_digest)
    phases_a = report_phases(reports["a"], group)
    phases_b = report_phases(reports["b"], group)
    if not phases_a or not phases_b:
        raise RunError(
            f"group {group.group_id}: report schema {group.report_schema!r} "
            "exposes no phase cutpoints (§3.2); T0 phase attribution is "
            "impossible for this group"
        )
    key = resolve_phase(phases_a, phase)
    if key not in phases_b:
        raise RunError(f"candidate arm does not report the claimed phase {phase!r}")
    before, after = phases_a[key], phases_b[key]
    if before <= 0.0:
        raise RunError(f"predecessor phase {key} is not a positive duration")
    relative_move = (before - after) / before
    moved = relative_move >= min_move
    target = manifest.tier_cost_target_seconds("T0")
    return {
        "schema": LADDER_T0_SCHEMA,
        "tier": "T0",
        "ranks": False,
        "board": board,
        "workload_class": workload_class,
        "workload": workload.workload_id,
        "era": era,
        "claimed_phase": phase,
        "resolved_phase": key,
        "phase_seconds": {"predecessor": before, "candidate": after},
        "relative_move": relative_move,
        "min_phase_move": min_move,
        "phase_moved": moved,
        "correctness_smoke": {
            "pass": smoke_ok,
            "predecessor_proof_digest": a.proof_digest,
            "candidate_proof_digest": b.proof_digest,
        },
        "pass": bool(moved and smoke_ok),
        "measured_phases": {
            "predecessor": phases_a,
            "candidate": phases_b,
        },
        "proxy": fixture,
        "proxy_validity": validity,
        "markers": markers,
        "measurement_seconds": elapsed,
        "cost_target_seconds": target,
        "within_cost_target": target is None or elapsed <= float(target),
        "reports": [a.report_path, b.report_path],
        "note": (
            "T0 gates scheduling only: it never ranks and never writes a "
            "scored row (TRACKS §3.5)."
        ),
    }


def iterate_estimate(
    repo_root: Path,
    predecessor_root: Path,
    manifest: Manifest,
    workload_class: str,
    out_dir: Path,
    *,
    board: str,
    fast_boundary: bool = False,
    era: int | None = None,
    round_budget: int | None = None,
) -> dict:
    """T1: paired ABBA on proxy fixtures with sequential early stopping.

    The agent's inner loop. It produces an ESTIMATE document, never a verdict:
    T1 output can never be promoted, submitted, or ranked (TRACKS §3.5b's
    local-iterate vs ranked separation).
    """
    era = _current_era(repo_root, era)
    workloads, fixture, validity, markers = proxy_selection(
        manifest, board, workload_class, era,
    )
    if not workloads:
        raise RunError(
            f"no enabled workloads registered for board {board}, class {workload_class}"
        )
    group_ids = {workload.group_id for workload in workloads}
    if len(group_ids) != 1:
        raise RunError(f"board {board} selected workloads from multiple groups")
    group = manifest.group(next(iter(group_ids)))
    policy = manifest.gates_for_workload(group.group_id, workload_class)
    if fast_boundary:
        # Resolve before building anything: a group that cannot honestly
        # exclude PoW should cost the agent zero seconds to find out.
        require_pow_boundary(group, CROSS_INVOCATION_POW_TIER)
    dispersion = ledger.aa_dispersion(repo_root, board, workload_class)
    theta = stats.theta(
        dispersion,
        float(policy["theta_floor"]),
        float(policy["dispersion_multiplier"]),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    build_arm(predecessor_root, manifest, groups=[group])
    build_arm(repo_root, manifest, groups=[group])
    started = time.monotonic()
    scores = [
        paired_rounds(
            predecessor_root, repo_root, manifest, workload, policy, out_dir,
            stop_theta=theta,
            round_budget=round_budget,
            sequential_stop=True,
            fast_boundary=fast_boundary,
            tier=CROSS_INVOCATION_POW_TIER,
        )
        for workload in workloads
    ]
    elapsed = time.monotonic() - started
    portfolio = portfolio_summary(scores, float(policy["ci_level"]))
    target = manifest.tier_cost_target_seconds("T1")
    return {
        "schema": LADDER_T1_SCHEMA,
        "tier": "T1",
        "ranks": False,
        "board": board,
        "workload_class": workload_class,
        "era": era,
        # The label comes from the scores, not from the request: a fast run on
        # a cross-invocation source says "estimate" in the boundary name itself.
        "boundary": scores[0].boundary,
        "boundary_evidence": scores[0].boundary_evidence,
        "theta": theta,
        "aa_dispersion": dispersion,
        "r_geomean": portfolio["r"],
        "ci": [portfolio["ci"][0], portfolio["ci"][1]],
        "ci_level": portfolio["ci_level"],
        "per_workload": {
            score.workload.workload_id: {
                "r": score.r,
                "ci": [score.ci[0], score.ci[1]],
                "rounds": len(score.ratios),
                "boundary": score.boundary,
                "a_median_ms": score.a_median_ms,
                "b_median_ms": score.b_median_ms,
                "request_ratio": score.request_ratio,
                "fast_request_ratio": score.fast_request_ratio,
                "boundary_evidence": score.boundary_evidence,
                "sequential_stop": score.sequential_stop,
                "measurement_seconds": score.measurement_seconds,
            }
            for score in scores
        },
        "proxy": fixture,
        "proxy_validity": validity,
        "markers": markers,
        "measurement_seconds": elapsed,
        "cost_target_seconds": target,
        "within_cost_target": target is None or elapsed <= float(target),
        "note": (
            "T1 is a CI-bearing LOCAL estimate on proxy fixtures. It never "
            "ranks; ranked rows come only from the judge path (TRACKS §3.5)."
        ),
    }


def _proxy_observation_ln_ratio(document: dict, label: str) -> float:
    """Extract a measured ln-ratio from a T1 estimate or a claimed/judged verdict."""
    if document.get("schema") == LADDER_T1_SCHEMA:
        ratio = document.get("r_geomean")
    elif document.get("schema_version") == 1 and "score" in document:
        score = document.get("score")
        ratio = score.get("R_geomean") if isinstance(score, dict) else None
    else:
        raise RunError(
            f"{label}: not a T1 estimate or a stwo-perf verdict; refusing to "
            "read a ratio from an unknown document"
        )
    if (
        isinstance(ratio, bool)
        or not isinstance(ratio, (int, float))
        or not math.isfinite(float(ratio))
        or float(ratio) <= 0.0
    ):
        raise RunError(f"{label}: measured ratio is missing or not positive")
    return math.log(float(ratio))


def _proxy_document_board_class(document: dict) -> tuple[str | None, str | None]:
    if document.get("schema") == LADDER_T1_SCHEMA:
        return document.get("board"), document.get("workload_class")
    objective = document.get("declared_objective")
    if isinstance(objective, dict):
        return objective.get("board"), objective.get("workload_class")
    return None, None


def _host_chip() -> str:
    if platform.system() == "Darwin":
        try:
            chip = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=30,
            )
            if chip.returncode == 0 and chip.stdout.strip():
                return chip.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.processor() or platform.machine() or "unknown"


def build_proxy_validity_receipt(
    repo_root: Path,
    manifest: Manifest,
    *,
    board: str,
    workload_class: str,
    era: int,
    observations: list[tuple[Path, Path]],
    measured_at_utc: str | None = None,
) -> dict:
    """Assemble a ``stwo_perf_proxy_validity_receipt_v1`` from measured runs.

    Every number in the receipt is read from measurement documents that already
    exist on disk: this function measures nothing and invents nothing. It runs
    on the designated judge host, once per era, per (board, class).
    """
    fixture = manifest.proxy_fixture(workload_class)
    if fixture is None:
        raise RunError(
            f"class {workload_class} declares no proxy_fixture; there is "
            "nothing to certify"
        )
    policy = manifest.confirmation_ladder.get("proxy_validity")
    if not isinstance(policy, dict):
        raise RunError(
            "gates_policy.confirmation_ladder.proxy_validity is not registered"
        )
    minimum = int(policy["min_observations"])
    if len(observations) < minimum:
        raise RunError(
            f"refusing to certify a proxy from {len(observations)} observation(s): "
            f"the registered minimum is {minimum}"
        )
    records: list[dict] = []
    xs: list[float] = []
    ys: list[float] = []
    for proxy_path, class_path in observations:
        pairs = []
        for path, label in ((proxy_path, "proxy run"), (class_path, "class run")):
            try:
                raw = Path(path).read_bytes()
                document = _load_json_object(raw.decode("utf-8"), label)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise RunError(f"{label} {path}: unreadable ({exc})") from exc
            observed_board, observed_class = _proxy_document_board_class(document)
            if observed_board != board or observed_class != workload_class:
                raise RunError(
                    f"{label} {path}: measured {observed_board}/{observed_class}, "
                    f"expected {board}/{workload_class}"
                )
            pairs.append((
                _proxy_observation_ln_ratio(document, f"{label} {path}"),
                hashlib.sha256(raw).hexdigest(),
            ))
        (proxy_ln, proxy_sha), (class_ln, class_sha) = pairs
        xs.append(proxy_ln)
        ys.append(class_ln)
        records.append({
            "proxy_ln_ratio": proxy_ln,
            "class_ln_ratio": class_ln,
            "proxy_evidence_sha256": proxy_sha,
            "class_evidence_sha256": class_sha,
        })
    try:
        correlation = pearson_correlation(xs, ys)
    except ManifestError as exc:
        raise RunError(str(exc)) from exc
    floor = float(policy["min_correlation"])
    document = {
        "schema": PROXY_VALIDITY_RECEIPT_SCHEMA,
        "board": board,
        "era": int(era),
        "workload_class": workload_class,
        "proxy": {
            "proxy_id": fixture["proxy_id"],
            "args": fixture["args"],
            "native_unit": fixture["native_unit"],
            "official_params": True,
        },
        "target": {"workload_ids": list(fixture["target_workload_ids"])},
        "measured_at_utc": measured_at_utc or time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(),
        ),
        "host": {
            "identity_sha256": hashlib.sha256(platform.node().encode()).hexdigest(),
            "chip": _host_chip(),
            "logical_cpu_count": os.cpu_count() or 1,
        },
        "harness_commit": _harness_commit(repo_root),
        "measurement": {
            "method": PROXY_VALIDITY_METHOD,
            "observations": records,
            "observation_count": len(records),
            "correlation": correlation,
            "min_correlation": floor,
            "min_observations": minimum,
            "valid": correlation >= floor and len(records) >= minimum,
        },
        "artifact_sha256": hashlib.sha256(
            json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    try:
        validate_proxy_validity_receipt(
            document,
            board=board,
            workload_class=workload_class,
            era=int(era),
            policy=policy,
            proxy_fixture=fixture,
        )
    except ManifestError as exc:
        raise RunError(f"assembled receipt failed its own schema: {exc}") from exc
    return document


RUST_ORACLE_RELPATH = "tools/stwo-interop-rs/target/release/stwo-interop-rs"
RUST_ORACLE_TOOLCHAIN = "nightly-2025-07-14"


def rust_oracle_check(candidate_root: Path, manifest: Manifest,
                      workload: Workload, out_dir: Path) -> dict:
    """Dispatch one scored workload to its group's pinned correctness oracle."""
    group = manifest.group(workload.group_id)
    if group.report_schema == "native_proof_v7":
        return _native_rust_oracle_check(
            candidate_root, group, workload, out_dir,
        )
    if group.report_schema == "riscv_proof_v2":
        return _riscv_sail_oracle_check(
            candidate_root, group, workload, out_dir,
        )
    if group.report_schema == "native_cuda_product_v6":
        return _cuda_rust_oracle_check(
            candidate_root, group, workload, out_dir,
        )
    raise RunError(
        f"{workload.workload_id}: no correctness oracle for "
        f"{group.report_schema!r}"
    )


def _cuda_rust_oracle_check(
    candidate_root: Path,
    group: WorkloadGroup,
    workload: Workload,
    out_dir: Path,
) -> dict:
    expected_oracle = {
        "authority": "pinned-rust-stwo",
        "repository": "https://github.com/starkware-libs/stwo",
        "commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "final_validator": True,
    }
    if group.correctness_oracle != expected_oracle:
        raise RunError(
            f"{workload.workload_id}: CUDA correctness oracle is not the "
            "pinned Rust stwo final validator"
        )
    oracle = candidate_root / RUST_ORACLE_RELPATH
    if not oracle.is_file():
        _run(
            f"cargo +{RUST_ORACLE_TOOLCHAIN} build --release --locked "
            f"--manifest-path tools/stwo-interop-rs/Cargo.toml",
            candidate_root,
            timeout=1200,
        )
    if not oracle.is_file():
        raise RunError("pinned Rust stwo verifier was not produced")
    binary = candidate_root / group.binary
    if not binary.is_file():
        raise RunError(
            f"{workload.workload_id}: CUDA product binary is missing"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = (
        out_dir / f"{workload.workload_id}.cuda-oracle-artifact.json"
    ).resolve()
    product_report = (
        out_dir / f"{workload.workload_id}.cuda-oracle-report.json"
    ).resolve()
    args = _format_workload_args(candidate_root, group, workload, 0, 1)
    shape = _cuda_shape_from_args(args)
    stdout = _run(
        shlex.join(
            [
                str(binary),
                *shlex.split(args),
                "--output",
                str(artifact),
                "--report-out",
                str(product_report),
            ]
        ),
        candidate_root,
        timeout=600,
    )
    report = _load_json_object(stdout, "CUDA oracle product report")
    try:
        artifact_meta = validate_cuda_artifact(artifact, shape)
        validate_cuda_report(
            report,
            shape,
            artifact,
            artifact_meta,
            expected_repetitions=1,
        )
    except CudaDiagnosticError as exc:
        raise RunError(
            f"{workload.workload_id}: malformed CUDA oracle artifact: {exc}"
        ) from exc
    persisted = _load_json_object(
        product_report.read_text(encoding="utf-8"),
        "persisted CUDA oracle product report",
    )
    if persisted != report:
        raise RunError("persisted CUDA oracle report differs from stdout")
    oracle_sha256 = hashlib.sha256(oracle.read_bytes()).hexdigest()
    _run(
        shlex.join(
            [str(oracle), "--mode", "verify", "--artifact", str(artifact)]
        ),
        candidate_root,
        timeout=600,
    )
    if hashlib.sha256(oracle.read_bytes()).hexdigest() != oracle_sha256:
        raise RunError("pinned Rust stwo verifier changed during validation")
    return {
        "workload": workload.workload_id,
        "verified": True,
        "oracle": "pinned-rust-stwo",
        "oracle_commit": expected_oracle["commit"],
        "oracle_binary_sha256": oracle_sha256,
        "artifact_sha256": artifact_meta["artifact_sha256"],
        "canonical_proof_sha256": artifact_meta["canonical_sha256"],
    }


def _native_rust_oracle_check(
    candidate_root: Path,
    group: WorkloadGroup,
    workload: Workload,
    out_dir: Path,
) -> dict:
    oracle = candidate_root / RUST_ORACLE_RELPATH
    if not oracle.is_file():
        _run(
            f"cargo +{RUST_ORACLE_TOOLCHAIN} build --release --locked "
            f"--manifest-path tools/stwo-interop-rs/Cargo.toml",
            candidate_root, timeout=1200,
        )
    binary = candidate_root / group.binary
    artifact = out_dir / f"{workload.workload_id}.oracle-artifact.json"
    args = _format_workload_args(candidate_root, group, workload, 0, 1)
    command = shlex.join([
        str(binary), *shlex.split(args), "--proof-artifact-out", str(artifact),
    ])
    _run(command, candidate_root, timeout=600)
    if not artifact.is_file():
        raise RunError(
            f"{workload.workload_id}: bench did not write the oracle artifact"
        )
    _run(f"{oracle} --mode verify --artifact {artifact}", candidate_root,
         timeout=600)
    return {
        "workload": workload.workload_id,
        "verified": True,
        "oracle": "pinned-rust-stwo",
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }


def _riscv_sail_oracle_check(
    candidate_root: Path,
    group: WorkloadGroup,
    workload: Workload,
    out_dir: Path,
) -> dict:
    oracle_policy = group.correctness_oracle
    pinned_commit = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
    if (
        oracle_policy.get("authority"),
        oracle_policy.get("repository"),
        oracle_policy.get("commit"),
        oracle_policy.get("final_validator"),
    ) != (
        "sail-riscv",
        "https://github.com/riscv/sail-riscv",
        pinned_commit,
        True,
    ):
        raise RunError(
            f"{workload.workload_id}: RISC-V group is not bound to the pinned "
            "Sail correctness authority"
        )
    evidence_path, evidence_bytes = _riscv_sail_evidence(
        candidate_root, oracle_policy, workload.workload_id,
    )
    try:
        payload = _load_json_object(
            evidence_bytes.decode("utf-8"), "Sail corpus evidence",
        )
        if (
            payload.get("schema") != "stwo-riscv-formal-corpus-evidence-v1"
            or payload.get("result") != "equivalent"
            or payload.get("semantic_authority") != "Sail"
            or payload.get("independent_cross_check") != "Spike"
        ):
            raise ValueError("unexpected Sail/Spike evidence identity or verdict")
        sail = payload.get("sail")
        if (
            not isinstance(sail, dict)
            or sail.get("repository_revision") != pinned_commit
        ):
            raise ValueError("evidence is not bound to the pinned Sail revision")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: invalid pinned Sail corpus evidence: {exc}"
        ) from exc
    validator = candidate_root / "scripts" / "riscv_sail_gate.py"
    if not validator.is_file():
        raise RunError(f"missing Sail evidence validator: {validator}")
    _run(
        shlex.join(["python3", str(validator), "bind"]),
        candidate_root,
        timeout=600,
    )
    try:
        if evidence_path.read_bytes() != evidence_bytes:
            raise ValueError("Sail corpus evidence changed during validation")
        report_path, proof_path = _latest_riscv_candidate_artifact(out_dir, workload)
        report = _load_json_object(
            report_path.read_text(encoding="utf-8"), "candidate RISC-V bench report",
        )
        artifact_bytes = proof_path.read_bytes()
        if report.get("proof_path") != str(proof_path):
            raise ValueError("candidate report does not bind the retained proof path")
        if _sha256_hex(
            report.get("artifact_sha256"), "candidate artifact_sha256",
        ) != hashlib.sha256(artifact_bytes).hexdigest():
            raise ValueError("candidate report does not bind the retained proof bytes")
        artifact = _load_json_object(
            artifact_bytes.decode("utf-8"), "candidate RISC-V proof artifact",
        )
        statement_digest = _sha256_hex(
            report.get("statement_sha256"), "candidate statement_sha256",
        )
        proof_hex = artifact.get("proof_bytes_hex")
        if (not isinstance(proof_hex, str) or not proof_hex or
                bytes.fromhex(proof_hex).hex() != proof_hex):
            raise ValueError("candidate proof bytes are not canonical hex")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: invalid retained candidate artifact: {exc}"
        ) from exc

    binary = candidate_root / group.binary
    if not binary.is_file():
        raise RunError(f"missing RISC-V candidate verifier: {binary}")
    verify_raw = _run(
        shlex.join([
            str(binary), "verify", "--artifact", str(proof_path),
            "--protocol", str(artifact.get("protocol")),
            "--expect-statement-digest", statement_digest,
        ]),
        candidate_root,
        timeout=1200,
    )
    try:
        verified = _validate_riscv_verify_receipt(
            verify_raw, report, artifact, proof_hex,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RunError(
            f"{workload.workload_id}: invalid retained-artifact verification: {exc}"
        ) from exc
    return {
        "workload": workload.workload_id,
        "verified": True,
        "oracle": "pinned-sail-corpus-evidence",
        "oracle_commit": pinned_commit,
        "sail_evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "attested_programs": payload["programs"],
        "attested_retirements": payload["retirements"],
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "proof_sha256": verified["proof_sha256"],
    }


def _riscv_sail_evidence(
    candidate_root: Path,
    oracle_policy: dict,
    workload_id: str,
) -> tuple[Path, bytes]:
    """Resolve immutable finite Sail/Spike evidence for benchmark admission."""
    binding = oracle_policy.get("evidence")
    evidence_raw = os.environ.get("STWO_ZIG_RISCV_SAIL_EVIDENCE")
    if evidence_raw:
        evidence = Path(evidence_raw).expanduser().resolve()
    else:
        if not isinstance(binding, dict):
            raise RunError(
                f"{workload_id}: STWO_ZIG_RISCV_SAIL_EVIDENCE is required "
                "until the manifest pins Sail evidence"
            )
        relative = binding.get("path")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise RunError(f"{workload_id}: manifest Sail evidence path is invalid")
        root = candidate_root.resolve()
        evidence = (root / relative).resolve()
        try:
            evidence.relative_to(root)
        except ValueError as exc:
            raise RunError(
                f"{workload_id}: manifest Sail evidence escapes the repository"
            ) from exc
    if not evidence.is_file():
        raise RunError(
            f"{workload_id}: RISC-V Sail evidence is not a file: {evidence}"
        )
    evidence_bytes = evidence.read_bytes()
    if isinstance(binding, dict):
        expected = binding.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RunError(f"{workload_id}: manifest Sail evidence digest is invalid")
        if hashlib.sha256(evidence_bytes).hexdigest() != expected:
            raise RunError(f"{workload_id}: manifest Sail evidence digest mismatches")
    return evidence, evidence_bytes


def _latest_riscv_candidate_artifact(
    out_dir: Path, workload: Workload,
) -> tuple[Path, Path]:
    pattern = re.compile(rf"^{re.escape(workload.workload_id)}\.b([1-9][0-9]*)\.json$")
    reports = []
    if out_dir.is_dir():
        for path in out_dir.iterdir():
            match = pattern.fullmatch(path.name)
            if match and path.is_file():
                reports.append((int(match.group(1)), path.resolve()))
    if not reports:
        raise ValueError("no retained candidate RISC-V benchmark report")
    _round_no, report_path = max(reports)
    proof_path = report_path.with_suffix(".proof.json")
    if not proof_path.is_file():
        raise ValueError(f"missing retained candidate proof: {proof_path}")
    return report_path, proof_path


def _validate_riscv_verify_receipt(
    raw: str, report: dict, artifact: dict, proof_hex: str,
) -> dict:
    receipt = _load_json_object(raw, "RISC-V verification receipt")
    expected_fields = {
        "schema", "status", "artifact_kind", "artifact_schema_version",
        "release_status", "security_policy", "statement_sha256", "proof_bytes",
        "proof_sha256", "transcript_state_blake2s", "implementation_commit",
        "implementation_dirty", "executable_sha256",
    }
    if set(receipt) != expected_fields:
        raise ValueError("RISC-V verification receipt fields differ")
    proof_bytes = bytes.fromhex(proof_hex)
    expected = {
        "schema": "riscv_verify_v1",
        "status": "verified",
        "artifact_kind": artifact.get("artifact_kind"),
        "artifact_schema_version": artifact.get("schema_version"),
        "release_status": artifact.get("release_status"),
        "security_policy": artifact.get("protocol"),
        "statement_sha256": report.get("statement_sha256"),
        "proof_bytes": len(proof_bytes),
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
        "transcript_state_blake2s": report.get("transcript_state_blake2s"),
        "implementation_commit": report.get("implementation_commit"),
        "implementation_dirty": report.get("implementation_dirty"),
        "executable_sha256": report.get("executable_sha256"),
    }
    for field_name, value in expected.items():
        if receipt.get(field_name) != value or type(receipt.get(field_name)) is not type(value):
            raise ValueError(f"verification receipt {field_name} differs")
    return receipt


def guard_registry(manifest: Manifest) -> dict:
    return manifest.raw.get("workload_registry", {}).get("guards", {}) or {}


def select_guards(manifest: Manifest, touched: list[str],
                  objective_group: WorkloadGroup) -> list[Workload]:
    """Impact-mapped guard selection: generic prover/PCS/FFT/accumulation
    paths exercise every native AIR; an unmatched editable source path fails
    closed to every guard."""
    registry = guard_registry(manifest)
    workloads = registry.get("workloads", {})
    if not workloads:
        return []
    # Rules may scope to a board: a metal-path rule that spares CPU-board
    # runs must not spare metal-board runs from their own portfolio.
    rules = [
        rule for rule in registry.get("impact_map", {}).get("rules", [])
        if rule.get("board") in (None, objective_group.board)
    ]
    selected: set[str] = set()
    source_paths = [p for p in touched if p.startswith("src/")]
    for path in source_paths:
        matched = False
        for rule in rules:
            if any(path.startswith(prefix) for prefix in rule.get("prefixes", [])):
                matched = True
                guards = rule.get("guards")
                if guards == "all":
                    selected.update(workloads)
                else:
                    selected.update(guards or [])
        if not matched:
            selected.update(workloads)  # unknown impact: run everything
    return [
        Workload(gid, "guard", spec["args"], spec.get("native_unit", ""),
                 objective_group.group_id)
        for gid, spec in sorted(workloads.items())
        if gid in selected
    ]


def run_guards(a_root: Path, b_root: Path, manifest: Manifest,
               guards: list[Workload], out_dir: Path) -> dict:
    """Paired ABBA regression guards: pass = upper CI bound <= budget; a guard
    straddling its budget after the base rounds resamples with extra rounds,
    then fails closed."""
    registry = guard_registry(manifest)
    policy = registry.get("policy", {})
    budget = float(policy.get("budget_upper", 1.05))
    guard_policy = {
        "warmups": int(policy.get("warmups", 5)),
        "samples_per_round": int(policy.get("samples_per_round", 2)),
        "min_rounds": int(policy.get("min_rounds", 3)),
        "max_rounds": int(policy.get("max_rounds", 8)),
        "theta_floor": max(budget - 1.0, 0.01),
        "wall_clock_cap_seconds": {"guard": 300},
        "command_timeout_seconds": 300,
        "ci_level": float(manifest.gates["ci_level"]),
    }
    extra = int(policy.get("inconclusive_extra_rounds", 4))
    results: dict[str, dict] = {}
    for guard in guards:
        score = paired_rounds(a_root, b_root, manifest, guard, guard_policy, out_dir)
        if score.ci[0] <= budget <= score.ci[1]:
            # Inconclusive vs the budget: continue sampling once, then decide.
            score = paired_rounds(
                a_root, b_root, manifest, guard, guard_policy, out_dir,
                round_budget=guard_policy["max_rounds"] + extra,
            )
        results[guard.workload_id] = {
            "r": round(score.r, 6),
            "ci": [round(score.ci[0], 6), round(score.ci[1], 6)],
            "rounds": len(score.ratios),
            "budget_upper": budget,
            "pass": score.ci[1] <= budget,
            "proof_digest": score.proof_digest,
        }
    return results


def _credited_log_effect(repo_root: Path, row) -> float:
    """Bridge W10 diagnostics to the Metrics-v2 credit authority when present."""
    try:
        from . import metrics

        epoch = ledger.known_epochs(repo_root)[int(row.epoch)]
        policy = metrics.policy_from_epoch(epoch)
        return float(metrics.credited_log_effect(row, policy.shrinkage_lambda))
    except Exception as exc:
        raise search_health.SearchHealthError(
            f"credited log effect is unavailable for row {getattr(row, 'row_id', '?')}: {exc}"
        ) from exc


def search_health_history(
    repo_root: Path,
    manifest: Manifest,
    board: str,
    workload_class: str,
) -> list[search_health.HistoryPoint]:
    """Load only valid, evidence-bound history used by a pre-run decision."""
    rows = [
        row for row in ledger.load(repo_root)
        if row.board == board and row.workload_class == workload_class
    ]
    series = search_health.class_series(
        rows,
        search_health.load_verdicts_by_evidence(repo_root),
        trailing_window=int(manifest.search_health_policy["trailing_window"]),
        credited_log_effect_fn=lambda row: _credited_log_effect(repo_root, row),
    )
    return search_health.history_from_class_series(series)


def _record_search_health_decision(out_dir: Path, decision) -> Path:
    """Persist the immutable decision before the measurement clock starts."""
    path = out_dir / search_health.DECISION_FILE
    path.write_text(
        json.dumps(search_health.decision_record(decision), indent=2, sort_keys=True)
        + "\n"
    )
    return path


def evaluate(
    repo_root: Path,
    predecessor_root: Path,
    manifest: Manifest,
    workload_class: str,
    dimension: str,
    scope: str,
    judged: bool,
    out_dir: Path,
    board: str = "core_cpu",
    holdout_seed: int | None = None,
    guards_mode: str = "auto",
    audit_mode: bool = False,
    require_quiet_host: bool = False,
    fast_boundary: bool = False,
) -> dict:
    """Run the full paired evaluation and assemble a verdict dict.

    `judged=True` is reachable only from the judge bot; the public CLI always
    evaluates claimed. The judged trust boundary is the HMAC signature applied
    by the judge (signing.py), never this flag alone.

    ``fast_boundary`` exists only to be refused: T2 and T3 keep the full dual
    boundary, so the parameter fails closed here rather than silently producing
    a verdict whose number excluded work (TRACKS §3.5).
    """
    if fast_boundary:
        raise RunError(
            "the PoW-excluded fast boundary is refused on judged/ranked "
            "evaluation: T2 and T3 keep the full dual boundary — the ranked "
            "number never excludes anything (TRACKS §3.5). Iterate with the "
            "T1 path instead (stwo-perf ladder t1 --fast-boundary)."
        )
    if judged and board == "core_metal":
        from .metal_calibration import CalibrationError, require_frozen

        try:
            require_frozen(manifest, workload_class)
        except CalibrationError as exc:
            raise RunError(
                f"judged Metal measurement requires a complete calibration: {exc}"
            ) from exc
    skipped = announce_skipped_groups(manifest)
    workloads = _board_workloads(manifest, board, workload_class)
    if not workloads:
        raise RunError(
            f"no enabled workloads registered for board {board}, class {workload_class}"
        )
    group_ids = {workload.group_id for workload in workloads}
    if len(group_ids) != 1:
        raise RunError(f"board {board} selected workloads from multiple groups")
    policy = manifest.gates_for_workload(next(iter(group_ids)), workload_class)
    try:
        # TRACKS §8: resource budgets are keyed (board, class); a board era
        # that pins none falls back to the epoch's class-only vector.
        epoch_resource_budgets = ledger.resource_budgets(
            repo_root, workload_class, board=board,
        )
        era_scored_dimension = ledger.scored_dimension(repo_root, board)
    except ledger.LedgerError as exc:
        raise RunError(f"invalid epoch resource budgets: {exc}") from exc
    if epoch_resource_budgets is not None:
        policy["resource_budgets"] = epoch_resource_budgets
    if era_scored_dimension != ledger.DEFAULT_SCORED_DIMENSION:
        # TRACKS §3.1 fail-closed gate: a board whose era declares the
        # verified-request boundary must not be scored by a harness that still
        # measures the prove boundary. Opening such an era therefore cannot
        # silently produce prove-boundary rows labelled as request-boundary.
        raise RunError(
            f"board {board} scores {era_scored_dimension} in its current era, but this "
            f"harness measures {ledger.DEFAULT_SCORED_DIMENSION}; the TRACKS §3.1 "
            "boundary re-scoring must land in the runner before that era opens"
        )

    dispersion = ledger.aa_dispersion(repo_root, board, workload_class)
    th = stats.theta(dispersion, float(policy["theta_floor"]), float(policy["dispersion_multiplier"]))

    out_dir.mkdir(parents=True, exist_ok=True)
    active_group_ids = {w.group_id for w in workloads}
    active_groups = [g for g in manifest.groups() if g.group_id in active_group_ids]
    for arm_root in (predecessor_root, repo_root):
        build_arm(arm_root, manifest, groups=active_groups)
    admission_preflight = (
        require_quiet_preflight() if require_quiet_host else _preflight()
    )

    try:
        decision = search_health.decide_rounds(
            board=board,
            workload_class=workload_class,
            configured_rounds=int(policy["max_rounds"]),
            minimum_rounds=int(policy["min_rounds"]),
            workload_count=len(workloads),
            class_wall_deadline_seconds=float(
                policy["wall_clock_cap_seconds"][workload_class]
            ),
            policy=manifest.search_health_policy,
            history=search_health_history(
                repo_root, manifest, board, workload_class
            ),
        )
    except search_health.SearchHealthError as exc:
        raise RunError(f"cannot make search-health round decision: {exc}") from exc
    if audit_mode:
        decision = search_health.require_audit_power(decision)
    decision_path = _record_search_health_decision(out_dir, decision)
    measurement_started = time.monotonic()
    class_deadline = (
        measurement_started + decision.class_wall_deadline_seconds
    )
    scores = [
        paired_rounds(predecessor_root, repo_root, manifest, w, policy, out_dir,
                      stop_theta=th, round_budget=decision.target_rounds,
                      minimum_rounds_override=(
                          decision.target_rounds if decision.auto_boost_applied else None
                      ), deadline_monotonic=class_deadline)
        for w in workloads
    ]
    objective_wall_seconds = time.monotonic() - measurement_started
    if time.monotonic() > class_deadline:
        raise RunError("objective measurement exceeded the fixed class wall deadline")
    portfolio = portfolio_summary(scores, float(policy["ci_level"]))

    touched = changed_paths(repo_root)
    guard_results: dict = {}
    if guards_mode != "none":
        objective_group = manifest.group(workloads[0].group_id)
        if guards_mode == "all":
            registry = guard_registry(manifest).get("workloads", {})
            selected = [
                Workload(gid, "guard", spec["args"], spec.get("native_unit", ""),
                         objective_group.group_id)
                for gid, spec in sorted(registry.items())
            ]
        else:
            selected = select_guards(manifest, touched, objective_group)
        if selected:
            print(f"running {len(selected)} regression guard(s): "
                  + ", ".join(g.workload_id for g in selected))
            guard_results = run_guards(predecessor_root, repo_root, manifest,
                                       selected, out_dir)

    oracle_results: list[dict] = []
    if bool(policy.get("require_rust_oracle", False)):
        for w in workloads:
            oracle_results.append(rust_oracle_check(repo_root, manifest, w, out_dir))

    holdout_result = None
    if judged:
        seed = (
            holdout_seed
            if holdout_seed is not None
            else _seed(_git(repo_root, "rev-parse", "HEAD") or "head", 0)
        )
        holdout = draw_holdout(manifest, workload_class, seed, board)
        if holdout is not None:
            hs = paired_rounds(predecessor_root, repo_root, manifest, holdout,
                               policy, out_dir, stop_theta=th, round_budget=3)
            holdout_result = {
                "seed": seed,
                "pass": hs.r <= float(policy["targeted_class_budget"]),
                "r": round(hs.r, 6),
            }
    significant, neutral, promotion_significance = portfolio_promotion_status(
        dimension, portfolio["ci"], th
    )
    rss_geomean = _complete_metric_geomean(scores, "rss_ratio")
    resource_portfolio = {}
    for resource_dimension in dimensions.RESOURCE_DIMENSIONS:
        estimates = [
            score.resource_estimates.get(resource_dimension) for score in scores
        ]
        if estimates and all(estimate is not None for estimate in estimates):
            admitted = [estimate for estimate in estimates if estimate is not None]
            candidates = [
                score.candidate_resources.get(resource_dimension) for score in scores
            ]
            resource_portfolio[resource_dimension] = {
                "ratio_geomean": stats.geometric_mean(
                    [estimate.ratio for estimate in admitted]
                ),
                "upper_ci_geomean": stats.geometric_mean(
                    [estimate.ci[1] for estimate in admitted]
                ),
                "candidate_geomean": (
                    stats.geometric_mean(
                        [float(value) for value in candidates if value is not None]
                    )
                    if all(value is not None for value in candidates) else None
                ),
            }

    gates = _gates(repo_root, manifest, scores, policy, judged, dispersion,
                   workload_class, board, guard_results, oracle_results)
    measurement_wall_seconds = time.monotonic() - measurement_started
    try:
        health_evidence = search_health.evidence_block(
            decision,
            actual_rounds_per_workload={
                score.workload.workload_id: len(score.ratios) for score in scores
            },
            objective_wall_seconds=objective_wall_seconds,
            measurement_wall_seconds=measurement_wall_seconds,
        )
    except search_health.SearchHealthError as exc:
        raise RunError(f"invalid search-health measurement evidence: {exc}") from exc
    health_evidence["decision_record"] = str(decision_path)
    verdict = {
        "schema_version": 1,
        "kind": "judged" if judged else "claimed",
        "harness_commit": _harness_commit(repo_root),
        "repo_commit": _git(repo_root, "rev-parse", "HEAD")[:12],
        "predecessor_commit": _git(predecessor_root, "rev-parse", "HEAD")[:12],
        "scope": scope,
        "declared_objective": {
            "board": board,
            "workload_class": workload_class,
            "dimension": dimension,
        },
        "environment": environment_block(
            repo_root, judged, admission_preflight=admission_preflight,
        ),
        "search_health": health_evidence,
        "gates": gates,
        "score": {
            "per_workload": {
                s.workload.workload_id: {
                    "r": round(s.r, 6),
                    "ci": [round(s.ci[0], 6), round(s.ci[1], 6)],
                    "rounds": len(s.ratios),
                    "a_median_ms": round(s.a_median_ms, 6),
                    "b_median_ms": round(s.b_median_ms, 6),
                    "request_ratio": (
                        round(s.request_ratio, 6) if s.request_ratio is not None else None
                    ),
                    "rss_ratio": (
                        round(s.rss_ratio, 6) if s.rss_ratio is not None else None
                    ),
                    "resources": {
                        resource_dimension: {
                            "ratio": round(estimate.ratio, 6),
                            "ci": [round(estimate.ci[0], 6), round(estimate.ci[1], 6)],
                            "observations": estimate.observations,
                            "candidate": s.candidate_resources.get(resource_dimension),
                        }
                        for resource_dimension, estimate in sorted(
                            s.resource_estimates.items()
                        )
                    },
                    "mechanism_verified": s.mechanism_verified,
                    "proof_bytes": s.proof_bytes,
                    "measurement_seconds": round(s.measurement_seconds, 6),
                    "resources_complete": s.resources_complete,
                }
                for s in scores
            },
            "R_geomean": round(portfolio["r"], 6),
            "portfolio": {
                "ci_method": portfolio["ci_method"],
                "ci_level": portfolio["ci_level"],
                "bootstrap_iterations": portfolio["bootstrap_iterations"],
                "seed": portfolio["seed"],
                "ci": [
                    round(portfolio["ci"][0], 6),
                    round(portfolio["ci"][1], 6),
                ],
                "prove_ms_method": portfolio["prove_ms_method"],
                "b_median_ms_geomean": round(
                    portfolio["b_median_ms_geomean"], 6
                ),
                "proof_bytes_method": portfolio["proof_bytes_method"],
                "proof_bytes": portfolio["proof_bytes"],
                "measurement_seconds": round(
                    portfolio["measurement_seconds"], 6
                ),
                "measurement_rounds": portfolio["measurement_rounds"],
            },
            "theta": round(th, 6),
            "aa_dispersion": dispersion,
            "significant": bool(significant),
            "neutral": bool(neutral),
            "promotion_significance": promotion_significance,
            "resource_portfolio": resource_portfolio,
        },
        "tiebreakers": {
            "rss_ratio": (
                round(rss_geomean, 6) if rss_geomean is not None else None
            ),
            "waits": None,
            "dispatches": None,
            "energy_j": (
                resource_portfolio.get("energy_j", {}).get("candidate_geomean")
            ),
            "proof_bytes": (
                resource_portfolio.get("proof_bytes", {}).get("candidate_geomean")
            ),
        },
        "holdout": holdout_result,
        "guards": guard_results,
        "rust_oracle": oracle_results,
        "skipped_groups": skipped,
        "evidence": {
            "pairing": "round-level ABBA (bench reports expose medians, not raw samples)",
            "per_workload": {
                s.workload.workload_id: {
                    "round_ratios": [round(x, 6) for x in s.ratios],
                    "proof_digest": s.proof_digest,
                    "request_ratio": (
                        round(s.request_ratio, 6) if s.request_ratio is not None else None
                    ),
                    "rss_ratio": round(s.rss_ratio, 6) if s.rss_ratio is not None else None,
                    "resources": {
                        resource_dimension: {
                            "ratio": round(estimate.ratio, 6),
                            "ci": [round(estimate.ci[0], 6), round(estimate.ci[1], 6)],
                            "observations": estimate.observations,
                            "candidate": s.candidate_resources.get(resource_dimension),
                        }
                        for resource_dimension, estimate in sorted(
                            s.resource_estimates.items()
                        )
                    },
                    "report_sha256s": s.report_sha256s,
                    "mechanism_verified": s.mechanism_verified,
                    "resources_complete": s.resources_complete,
                    # Only present when the pre-registered sequential design was
                    # armed, so pre-ladder verdicts keep their exact shape.
                    **(
                        {"sequential_stop": s.sequential_stop}
                        if s.sequential_stop is not None else {}
                    ),
                }
                for s in scores
            },
            "reports": [p for s in scores for p in s.reports],
        },
    }
    if audit_mode:
        verdict["audit_mode"] = True
    return verdict


def _gates(repo_root, manifest, scores, policy, judged, dispersion,
           workload_class, board, guard_results=None, oracle_results=None) -> dict:
    guard_results = guard_results or {}
    oracle_results = oracle_results or []
    # Per-round verification, per-round CROSS-ARM digest equality, and digest
    # constancy are enforced in paired_rounds (a violation raises, so reaching
    # here means they held); pinned correctness-oracle results land in the detail.
    g1_ok = True
    if bool(policy.get("require_rust_oracle", False)):
        g1_ok = len(oracle_results) == len(scores) and all(
            o.get("verified") for o in oracle_results
        )
    oracle_note = (
        f"; pinned correctness oracle verified {sum(1 for o in oracle_results if o.get('verified'))}/{len(scores)} workloads"
        if policy.get("require_rust_oracle", False)
        else "; correctness oracle not required by policy"
    )
    # Submission and note additions are the point of a submission PR; they are
    # not locked-path violations (mirrors validate_action's carve-out).
    touched = [
        p for p in changed_paths(repo_root)
        if not p.startswith("autoresearch/submissions/")
        and not p.startswith("autoresearch/notes/")
        and not p.startswith("autoresearch/.runs/")
    ]
    violations, strays = manifest.classify_touched(touched)
    g2_ok = not violations and not strays
    if g2_ok:
        g2_detail = "no locked or out-of-scope path touched"
    elif violations:
        g2_detail = f"locked paths touched: {violations[:5]}"
    else:
        g2_detail = "no locked path touched"
    if strays:
        g2_detail += f"; outside editable set: {strays[:5]}"

    riscv_scores = [
        score for score in scores
        if manifest.group(score.workload.group_id).report_schema == "riscv_proof_v2"
    ]
    if riscv_scores:
        g3_ok = all(score.mechanism_verified is True for score in riscv_scores)
        g3_detail = (
            "RISC-V mechanism telemetry present, canonical, and semantically stable "
            f"for {sum(score.mechanism_verified is True for score in riscv_scores)}/"
            f"{len(riscv_scores)} workloads"
        )
    else:
        g3_ok = True
        g3_detail = "native mechanism telemetry policy unchanged"

    # G4: anchor drift budgets, charged against the frozen anchor (never the
    # predecessor). Inactive until the anchor is frozen — G5 blocks judged then.
    anchors = manifest.raw["harness"].get("anchor_prove_ms") or {}
    anchor_ms = anchors.get(board, {}).get(workload_class)
    g4_ok, g4_details = True, []
    if anchor_ms and scores:
        targeted = float(policy["targeted_class_budget"])
        candidate_ms = stats.geometric_mean([score.b_median_ms for score in scores])
        ratio = candidate_ms / float(anchor_ms)
        anchor_ok = ratio <= targeted
        g4_ok = g4_ok and anchor_ok
        g4_details.append(
            f"candidate/anchor {ratio:.4f} vs targeted budget x{targeted}"
            + ("" if anchor_ok else " — cumulative budget exhausted (F.1 guard)")
        )
    else:
        g4_details.append("anchor not frozen; drift budget inactive")
    if scores:
        matrix_budget_raw = policy.get("matrix_row_budget")
        if matrix_budget_raw is None:
            g4_ok = False
            g4_details.append("matrix row budget missing — cannot admit scored rows")
        else:
            matrix_budget = float(matrix_budget_raw)
            matrix_failed = [
                score.workload.workload_id
                for score in scores
                if score.ci[1] > matrix_budget
            ]
            matrix_ok = not matrix_failed
            g4_ok = g4_ok and matrix_ok
            g4_details.append(
                f"matrix row upper CIs {len(scores) - len(matrix_failed)}/{len(scores)} "
                f"within budget x{matrix_budget}"
                + (f" — FAILED: {matrix_failed[:4]}" if matrix_failed else "")
            )
    guards_failed = [g for g, res in guard_results.items() if not res.get("pass")]
    if guard_results:
        g4_ok = g4_ok and not guards_failed
        g4_details.append(
            f"regression guards {len(guard_results) - len(guards_failed)}/{len(guard_results)} within budget"
            + (f" — FAILED: {guards_failed[:4]}" if guards_failed else "")
        )
    request_budget = float(policy.get("request_budget", 0) or 0)
    if scores and request_budget:
        request_present = [score for score in scores if score.request_ratio is not None]
        request_failed = [
            score.workload.workload_id for score in request_present
            if score.request_ratio > request_budget
        ]
        request_missing = [
            score.workload.workload_id for score in scores
            if score.request_ratio is None
        ]
        request_ok = not request_failed
        g4_ok = g4_ok and request_ok
        g4_details.append(
            f"request ratios {len(request_present) - len(request_failed)}/"
            f"{len(request_present)} present rows within budget x{request_budget}"
            + (f" — FAILED: {request_failed[:4]}" if request_failed else "")
            + (f"; absent: {request_missing[:4]}" if request_missing else "")
        )
    resource_budgets = policy.get("resource_budgets")
    if scores and resource_budgets is not None:
        if not isinstance(resource_budgets, dict):
            raise RunError("resource_budgets must be an object")
        resource_vectors_ok = True
        for score in scores:
            assessment = dimensions.assess_budgets(
                {
                    dimension: score.resource_estimates.get(dimension)
                    for dimension in dimensions.RESOURCE_DIMENSIONS
                },
                resource_budgets,
            )
            g4_ok = g4_ok and assessment.passed
            resource_vectors_ok = resource_vectors_ok and assessment.passed
            for failure in assessment.failures:
                margin = (
                    f" by {failure.observed_upper - failure.budget_upper:.4f}"
                    if failure.observed_upper is not None
                    and failure.budget_upper is not None
                    else ""
                )
                g4_details.append(
                    f"{score.workload.workload_id} {failure.dimension} "
                    f"{failure.reason}{margin}"
                )
        if resource_vectors_ok:
            g4_details.append(
                f"resource vectors {len(scores)}/{len(scores)} within named budgets"
            )
    rss_budget = float(policy.get("rss_budget", 0) or 0)
    if scores and rss_budget and resource_budgets is None:
        rss_present = [score for score in scores if score.rss_ratio is not None]
        rss_failed = [
            score.workload.workload_id for score in rss_present
            if score.rss_ratio > rss_budget
        ]
        rss_missing = [
            score.workload.workload_id for score in scores
            if score.rss_ratio is None
        ]
        rss_ok = not rss_failed
        g4_ok = g4_ok and rss_ok
        g4_details.append(
            f"rss ratios {len(rss_present) - len(rss_failed)}/"
            f"{len(rss_present)} present rows within budget x{rss_budget}"
            + (f" — FAILED: {rss_failed[:4]}" if rss_failed else "")
            + (f"; absent: {rss_missing[:4]}" if rss_missing else "")
        )
    g4_detail = "; ".join(g4_details)

    env_ok = True
    env_detail = "local advisory run"
    if judged:
        resources_complete = all(
            set(score.resource_estimates) == set(dimensions.RESOURCE_DIMENSIONS)
            for score in scores
        )
        class_anchor_frozen = (
            isinstance(anchor_ms, (int, float))
            and not isinstance(anchor_ms, bool)
            and math.isfinite(float(anchor_ms))
            and float(anchor_ms) > 0
        )
        class_dispersion_frozen = (
            isinstance(dispersion, (int, float))
            and not isinstance(dispersion, bool)
            and math.isfinite(float(dispersion))
            and float(dispersion) > 0
        )
        env_ok = (
            class_dispersion_frozen
            and class_anchor_frozen
            and manifest.anchor_commit is not None
            and resources_complete
        )
        env_detail = (
            "judge lock, finite per-class A/A dispersion, anchor, and complete resource vectors present"
            if env_ok
            else "judged requires finite positive per-class A/A dispersion, an anchor, and complete resource vectors"
        )
    return {
        "G1": {"pass": g1_ok, "detail": "every timed sample verified; cross-arm proof digests byte-identical per round" + oracle_note},
        "G2": {"pass": g2_ok, "detail": g2_detail},
        "G3": {"pass": g3_ok, "detail": g3_detail},
        "G4": {"pass": g4_ok, "detail": g4_detail},
        "G5": {"pass": env_ok, "detail": env_detail},
    }


def _board_workloads(manifest: Manifest, board: str,
                     workload_class: str,
                     allow_staged: bool = False) -> list[Workload]:
    try:
        return manifest.workloads(
            workload_class, board=board, include_disabled=allow_staged
        )
    except ManifestError as exc:
        raise RunError(str(exc)) from exc


def changed_paths(repo_root: Path) -> list[str]:
    base = _git(repo_root, "merge-base", "HEAD", "origin/main") or "HEAD~1"
    out = _git(repo_root, "diff", "--name-only", base, "HEAD")
    dirty = _git(repo_root, "diff", "--name-only")
    paths = [p for p in (out + "\n" + dirty).splitlines() if p.strip()]
    return sorted(set(paths))


def _harness_commit(repo_root: Path) -> str:
    out = _git(repo_root, "rev-parse", "HEAD:autoresearch")
    return out[:12] if out else "worktree"


def _git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _try(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - environment probe only
        return None
