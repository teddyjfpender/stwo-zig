"""Isolated orchestration for native EthProofs CSP old-vs-current evidence.

The active checkout is an input, never a build directory.  A current arm is
materialized in a private clone from one binary HEAD diff plus every
``git ls-files --others --exclude-standard`` payload.  The source digest is
checked before capture, in the clone, and again in the active checkout before
the clone receives a deterministic temporary commit.  No active index, ref,
or worktree mutation is used to make a dirty development tree benchmarkable.
"""

from __future__ import annotations

import os
import selectors
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.riscv_csp_ab_benchmark_lib import contract
from scripts.riscv_csp_benchmark_lib.host import (
    collect_host,
    official_host_match,
    power_conditions_admissible,
)


CONFIRMATION = "native-ethproof-csp-ab-v1"
SMOKE_CONFIRMATION = "native-ethproof-csp-ab-smoke-v1"
from .workspace import (
    RECURSIVE_PATHS,
    _git_raw,
    _git_text,
    _nul_paths,
    _run,
    assert_no_ignored_source_inputs,
    clone_at,
    digest_paths,
    materialize_ephemeral_current,
    repository_root,
    source_content,
    tracked_and_untracked_paths,
    untracked_paths,
    worktree_status,
)
from .host_gate import (
    QUIET_MAX_NORMALIZED_LOAD_1M,
    QUIET_MEDIAN_IDLE_PERCENT,
    QUIET_MIN_IDLE_PERCENT,
    QUIET_SAMPLE_COUNT,
    _now,
    benchmark_environment,
    bounded_quiet_gate,
    classify_quiet_host,
    quiet_host_preflight,
)
from .report_assembly import (
    _case_for,
    _gate_evidence,
    _pair_gate_relative,
    _partial_relative,
    _receipt_relative,
    assemble_report,
)


def native_guard(root: Path, commit: str) -> dict[str, Any]:
    raw = _git_raw(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        commit,
        "--",
        *RECURSIVE_PATHS,
    )
    paths = _nul_paths(raw, "recursive source inventory")
    return {
        "kind": (
            "recursive_sources_absent_v1"
            if not paths
            else "runtime_native_attestation_v1"
        ),
        "recursive_path_count": len(paths),
        "recursive_paths_sha256": contract.sha256_bytes(raw),
    }


def arm_from_root(
    root: Path,
    *,
    label: str,
    source_kind: str,
    snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    head = _git_text(root, "rev-parse", "HEAD")
    status = worktree_status(root)
    if status["dirty"]:
        raise contract.ABError(f"{label} benchmark clone is dirty")
    content = source_content(root)
    manifest = root / "vectors" / "riscv_csp" / "manifest-v2.json"
    harness = root / "scripts" / "riscv_csp_benchmark.py"
    for name, path in (("manifest", manifest), ("harness", harness)):
        if not path.is_file():
            raise contract.ABError(f"{label} has no {name}: {path}")
    result = {
        "label": label,
        "source_kind": source_kind,
        "head": head,
        "benchmark_tree_dirty": False,
        "source_content_sha256": content["sha256"],
        "source_file_count": content["file_count"],
        "source_payload_bytes": content["payload_bytes"],
        "manifest_sha256": contract.sha256_file(manifest),
        "harness_sha256": contract.sha256_file(harness),
        "native_guard": native_guard(root, head),
    }
    if snapshot is not None:
        result["active_snapshot"] = dict(snapshot)
        if snapshot["temporary_commit"] != head or snapshot["source_content_sha256"] != content["sha256"]:
            raise contract.ABError("current arm and active snapshot provenance differ")
    return result



def create_plan(
    active_path: Path,
    *,
    rounds: int,
    warmups: int,
    samples: int,
    workers: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    active = repository_root(active_path)
    host = collect_host()
    power_admissible, power_reasons = power_conditions_admissible(host)
    preflight = quiet_host_preflight(host)
    selected_workers = workers
    _, environment_policy = benchmark_environment(os.environ, selected_workers)

    with tempfile.TemporaryDirectory(prefix="stwo-native-ab-plan-") as raw:
        staging = Path(raw)
        baseline_root = staging / "baseline"
        current_root = staging / "current"
        clone_at(active, baseline_root, contract.BASELINE_COMMIT)
        baseline = arm_from_root(
            baseline_root,
            label="baseline",
            source_kind="committed_baseline_v1",
        )
        snapshot = materialize_ephemeral_current(active, current_root)
        current = arm_from_root(
            current_root,
            label="current",
            source_kind="ephemeral_active_snapshot_v1",
            snapshot=snapshot,
        )
    if baseline["native_guard"]["kind"] != "recursive_sources_absent_v1":
        raise contract.ABError("frozen baseline unexpectedly contains recursive sources")
    if current["native_guard"]["kind"] != "runtime_native_attestation_v1":
        raise contract.ABError("current snapshot has no source-level recursion boundary")

    official_match, official_reasons = official_host_match(host, backend="cpu")
    plan = contract.attach_seal(
        {
            "schema": contract.PLAN_SCHEMA,
            "schema_version": contract.PLAN_VERSION,
            "generated_at": _now(),
            "status": (
                "ready_ephemeral_current"
                if preflight["admissible"]
                else "diagnostic_smoke_only_host_interference"
            ),
            "active_repository": str(active),
            "host": host,
            "power": {"admissible": power_admissible, "reasons": power_reasons},
            "publishable_preflight": preflight,
            "official_csp_host": {
                "matches": official_match,
                "mismatch_reasons": official_reasons,
                "classification": "context_only_same_host_pair_is_primary",
            },
            "environment": environment_policy,
            "settings": {
                "backend": "cpu",
                "recursion_enabled": False,
                "rounds": rounds,
                "warmups": warmups,
                "samples": samples,
                "workers": selected_workers,
                "timeout_seconds": timeout_seconds,
            },
            "arms": {"baseline": baseline, "current": current},
            "workload": contract.workload_context(),
            "schedule": contract.canonical_schedule(rounds),
            "historical_context": contract.historical_context(),
            "claim_policy": {
                "aggregate_speedup_claim": False,
                "per_case_paired_descriptive_statistics_only": True,
                "reason": "heterogeneous CSP workloads have no justified aggregate weighting",
            },
        }
    )
    contract.validate_plan(plan)
    return plan


def _load_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    plan, raw = contract.load_json(path)
    contract.validate_plan(plan)
    return plan, raw


def _arm_environment(base: Mapping[str, str], root: Path) -> dict[str, str]:
    environment = dict(base)
    environment["ZIG_LOCAL_CACHE_DIR"] = str(root / ".zig-cache")
    environment["ZIG_GLOBAL_CACHE_DIR"] = str(root / ".zig-cache" / "ab-global")
    return environment


def build_command(root: Path) -> list[str]:
    return [
        "zig",
        "build",
        "stwo-zig-riscv-cpu",
        "riscv-trace-dump",
        "-Doptimize=ReleaseFast",
        "--prefix",
        str(root / "zig-out" / "native-ab"),
    ]


def benchmark_command(
    root: Path,
    report_path: Path,
    schedule_entry: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> list[str]:
    prefix = root / "zig-out" / "native-ab" / "bin"
    return [
        sys.executable,
        str(root / "scripts" / "riscv_csp_benchmark.py"),
        "--backend",
        "cpu",
        "--cli",
        str(prefix / "stwo-zig-riscv-cpu"),
        "--trace-cli",
        str(prefix / "riscv-trace-dump"),
        "--manifest",
        str(root / "vectors" / "riscv_csp" / "manifest-v2.json"),
        "--report-out",
        str(report_path),
        "--targets",
        str(schedule_entry["target"]),
        "--sizes",
        str(schedule_entry["input_size"]),
        "--warmups",
        str(settings["warmups"]),
        "--samples",
        str(settings["samples"]),
        "--workers",
        str(settings["workers"]),
        "--timeout",
        str(settings["timeout_seconds"]),
    ]


def _run_logged(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    log_path: Path,
    timeout: int,
) -> None:
    if log_path.exists():
        raise contract.ABError(f"refusing to replace execution log: {log_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    completed_normally = False

    def stop_process_tree(*, force_group: bool = False) -> None:
        if process is None or (process.poll() is not None and not force_group):
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            if process.poll() is None:
                process.wait(timeout=5)
            elif force_group:
                # The direct child may have exited after spawning a descendant
                # that inherited the pipe. The session is ours, so close the
                # whole exceptional-path process group deterministically.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    try:
        with log_path.open("xb") as log:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(env),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            assert process.stdout is not None
            os.set_blocking(process.stdout.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while True:
                    if time.monotonic() - started > timeout:
                        stop_process_tree(force_group=True)
                        raise contract.ABError(f"command timed out: {argv[0]}")
                    events = selector.select(timeout=1.0)
                    for key, _ in events:
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                        if chunk:
                            log.write(chunk)
                            log.flush()
                            sys.stdout.write(chunk.decode("utf-8", "replace"))
                            sys.stdout.flush()
                    if process.poll() is not None:
                        while True:
                            try:
                                remainder = os.read(process.stdout.fileno(), 64 * 1024)
                            except BlockingIOError:
                                break
                            if not remainder:
                                break
                            log.write(remainder)
                            log.flush()
                            sys.stdout.write(remainder.decode("utf-8", "replace"))
                            sys.stdout.flush()
                        break
            finally:
                selector.close()
            returncode = process.wait()
            completed_normally = True
    except OSError as error:
        raise contract.ABError(f"cannot run logged command {argv[0]}: {error}") from error
    finally:
        stop_process_tree(force_group=not completed_normally)
        if process is not None and process.stdout is not None:
            process.stdout.close()
    if returncode != 0:
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        raise contract.ABError(
            f"command exited {returncode}: {' '.join(argv)}\n{tail}"
        )


def _validate_arm_matches(planned: Mapping[str, Any], actual: Mapping[str, Any]) -> None:
    if planned != actual:
        raise contract.ABError(f"recreated {planned['label']} arm differs from the sealed plan")


def _prepare_run_roots(
    active: Path,
    staging: Path,
    plan: Mapping[str, Any],
) -> dict[str, Path]:
    baseline_root = staging / "baseline"
    current_root = staging / "current"
    clone_at(active, baseline_root, contract.BASELINE_COMMIT)
    baseline = arm_from_root(
        baseline_root,
        label="baseline",
        source_kind="committed_baseline_v1",
    )
    _validate_arm_matches(plan["arms"]["baseline"], baseline)
    snapshot = materialize_ephemeral_current(active, current_root)
    current = arm_from_root(
        current_root,
        label="current",
        source_kind="ephemeral_active_snapshot_v1",
        snapshot=snapshot,
    )
    _validate_arm_matches(plan["arms"]["current"], current)
    return {"baseline": baseline_root, "current": current_root}


def _write_bytes_new(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise contract.ABError(f"refusing to replace evidence: {path}") from error


def _bundle_current(root: Path, artifact: Path, base_head: str) -> dict[str, Any]:
    bundle = artifact / "source" / "current-snapshot.bundle"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    if bundle.exists():
        raise contract.ABError(f"refusing to replace source bundle: {bundle}")
    snapshot_ref = "refs/benchmarks/native-ab-snapshot"
    _run(["git", "update-ref", snapshot_ref, "HEAD"], cwd=root)
    _run(
        ["git", "bundle", "create", bundle, snapshot_ref, f"^{base_head}"],
        cwd=root,
        timeout=1800,
    )
    return {
        "path": str(bundle.relative_to(artifact)),
        "sha256": contract.sha256_file(bundle),
        "bytes": bundle.stat().st_size,
        "prerequisite_commit": base_head,
        "temporary_commit": _git_text(root, "rev-parse", "HEAD"),
    }



def _admit_live_plan(
    plan_path: Path,
) -> tuple[dict[str, Any], bytes, Path, dict[str, str]]:
    plan, plan_raw = _load_plan(plan_path)
    active = repository_root(Path(plan["active_repository"]))
    host = collect_host()
    if host != plan["host"]:
        raise contract.ABError("live host/power evidence differs from the sealed plan")
    base_env, environment_policy = benchmark_environment(
        os.environ, plan["settings"]["workers"]
    )
    if environment_policy != plan["environment"]:
        raise contract.ABError("live sanitized environment differs from the sealed plan")
    return plan, plan_raw, active, base_env


def _new_artifact(
    artifact_path: Path,
    plan: Mapping[str, Any],
    plan_raw: bytes,
) -> tuple[Path, dict[str, Any]]:
    artifact = artifact_path.resolve()
    artifact.parent.mkdir(parents=True, exist_ok=True)
    try:
        artifact.mkdir()
    except FileExistsError as error:
        raise contract.ABError(f"refusing to reuse artifact directory: {artifact}") from error
    _write_bytes_new(artifact / "plan.json", plan_raw)
    return artifact, {
        "path": "plan.json",
        "sha256": contract.sha256_bytes(plan_raw),
        "bytes": len(plan_raw),
        "seal_sha256": plan["seal_sha256"],
    }


def _build_arms(
    roots: Mapping[str, Path],
    artifact: Path,
    base_env: Mapping[str, str],
    timeout: int,
) -> None:
    for arm in contract.ARM_NAMES:
        print(f"[build] {arm}: isolated ReleaseFast product", flush=True)
        _run_logged(
            build_command(roots[arm]),
            cwd=roots[arm],
            env=_arm_environment(base_env, roots[arm]),
            log_path=artifact / "logs" / f"build-{arm}.log",
            timeout=timeout,
        )
        if worktree_status(roots[arm])["dirty"]:
            raise contract.ABError(f"{arm} source tree changed during build")


def execute_plan(
    plan_path: Path,
    artifact_path: Path,
    *,
    confirmation: str,
) -> Path:
    if confirmation != CONFIRMATION:
        raise contract.ABError(
            f"heavyweight run requires --confirm-heavyweight {CONFIRMATION}"
        )
    plan, plan_raw, active, base_env = _admit_live_plan(plan_path)
    if plan["status"] != "ready_ephemeral_current":
        raise contract.ABError(
            "full A/B is blocked by the plan's quiet-host/power preflight; "
            "only diagnostic smoke is admissible"
        )
    execution_preflight = quiet_host_preflight(plan["host"])
    if not execution_preflight["admissible"]:
        raise contract.ABError(
            "full A/B is blocked by live host interference: "
            + "; ".join(execution_preflight["reasons"])
        )
    artifact, plan_evidence = _new_artifact(artifact_path, plan, plan_raw)

    print(
        f"[native A/B] {len(plan['schedule'])} serial launches; "
        f"{plan['settings']['rounds']} round(s), {plan['settings']['samples']} sample(s)",
        flush=True,
    )
    staging = Path(tempfile.mkdtemp(prefix="source-roots-", dir=artifact))
    try:
        roots = _prepare_run_roots(active, staging, plan)
        snapshot_bundle = _bundle_current(
            roots["current"],
            artifact,
            plan["arms"]["current"]["active_snapshot"]["base_head"],
        )
        _build_arms(
            roots,
            artifact,
            base_env,
            plan["settings"]["timeout_seconds"],
        )
        post_build = bounded_quiet_gate(
            plan["host"],
            label="post-build recovery",
            enforce_load_threshold=True,
            max_attempts=12,
            retry_seconds=10,
        )
        post_build_relative = Path("gates") / "post-build.json"
        contract.write_new_json(artifact / post_build_relative, post_build)
        post_build_evidence = _gate_evidence(
            artifact, post_build_relative, require_admissible=True
        )

        pair_gate_evidence: dict[tuple[int, int], dict[str, Any]] = {}
        for entry in plan["schedule"]:
            arm = entry["arm"]
            relative = _partial_relative(entry)
            report_path = artifact / relative
            pair_key = (entry["round"], entry["case_ordinal"])
            if entry["launch_index"] == 0:
                gate = bounded_quiet_gate(
                    plan["host"],
                    label=(
                        f"round {entry['round'] + 1} "
                        f"{entry['target']}/{entry['input_size']} pair"
                    ),
                    # The one-minute load includes the preceding benchmark pair;
                    # instantaneous idle and thermal state remain enforced.
                    enforce_load_threshold=False,
                    max_attempts=3,
                    retry_seconds=5,
                )
                gate_relative = _pair_gate_relative(entry)
                contract.write_new_json(artifact / gate_relative, gate)
                pair_gate_evidence[pair_key] = _gate_evidence(
                    artifact, gate_relative, require_admissible=True
                )
            if pair_key not in pair_gate_evidence:
                raise contract.ABError("paired launch has no admitted quiet-host gate")
            print(
                f"[launch {entry['ordinal'] + 1}/{len(plan['schedule'])}] "
                f"r{entry['round'] + 1} {entry['target']}/{entry['input_size']} {arm}",
                flush=True,
            )
            started = _now()
            monotonic = time.monotonic()
            load_before = list(os.getloadavg()) if hasattr(os, "getloadavg") else None
            _run_logged(
                benchmark_command(
                    roots[arm], report_path, entry, plan["settings"]
                ),
                cwd=roots[arm],
                env=_arm_environment(base_env, roots[arm]),
                log_path=artifact / "logs" / f"launch-{entry['ordinal']:03d}.log",
                timeout=plan["settings"]["timeout_seconds"]
                * (plan["settings"]["warmups"] + plan["settings"]["samples"] + 5),
            )
            report, raw = contract.load_json(report_path)
            case = _case_for(entry, plan["workload"])
            contract.validate_partial_report(
                report,
                arm=plan["arms"][arm],
                case=case,
                settings=plan["settings"],
                expected_host=plan["host"],
            )
            receipt = contract.attach_seal(
                {
                    "schema": "stwo_riscv_csp_native_ab_launch_receipt_v1",
                    "entry": entry,
                    "started_at": started,
                    "completed_at": _now(),
                    "wall_seconds": time.monotonic() - monotonic,
                    "load_average_before": load_before,
                    "load_average_after": (
                        list(os.getloadavg()) if hasattr(os, "getloadavg") else None
                    ),
                    "report_path": str(relative),
                    "report_sha256": contract.sha256_bytes(raw),
                    "report_bytes": len(raw),
                    "quiet_gate": pair_gate_evidence[pair_key],
                }
            )
            contract.write_new_json(
                artifact / _receipt_relative(entry),
                receipt,
            )
            if worktree_status(roots[arm])["dirty"]:
                raise contract.ABError(f"{arm} source tree changed during measurement")

        report = assemble_report(
            plan,
            artifact,
            plan_evidence=plan_evidence,
            snapshot_bundle=snapshot_bundle,
            execution_preflight=execution_preflight,
            post_build_gate=post_build_evidence,
            pair_gates=[
                pair_gate_evidence[key] for key in sorted(pair_gate_evidence)
            ],
        )
        output = artifact / "report.json"
        contract.write_new_json(output, report)
        return output
    finally:
        # The path is generated by mkdtemp inside the newly-created evidence
        # directory.  Source evidence survives in the sealed plan and bundle.
        shutil.rmtree(staging, ignore_errors=True)


def execute_smoke(
    plan_path: Path,
    artifact_path: Path,
    *,
    confirmation: str,
) -> Path:
    """Exercise both proof paths once without producing comparison statistics."""

    if confirmation != SMOKE_CONFIRMATION:
        raise contract.ABError(
            f"diagnostic smoke requires --confirm-heavyweight {SMOKE_CONFIRMATION}"
        )
    plan, plan_raw, active, base_env = _admit_live_plan(plan_path)
    execution_preflight = quiet_host_preflight(plan["host"])
    artifact, plan_evidence = _new_artifact(artifact_path, plan, plan_raw)
    smoke_settings = {
        **plan["settings"],
        "rounds": 1,
        "warmups": 0,
        "samples": 1,
    }
    entries = [
        entry
        for entry in plan["schedule"]
        if entry["round"] == 0
        and entry["case_ordinal"] == 0
        and entry["target"] == "sha256"
        and entry["input_size"] == 128
    ]
    if [entry["arm"] for entry in entries] != list(contract.ARM_NAMES):
        raise contract.ABError("sealed plan has no canonical sha256/128 smoke pair")

    print(
        "[native A/B smoke] diagnostic_smoke_only: sha256/128, one verified "
        "sample per arm; no performance comparison will be emitted",
        flush=True,
    )
    staging = Path(tempfile.mkdtemp(prefix="source-roots-", dir=artifact))
    try:
        roots = _prepare_run_roots(active, staging, plan)
        snapshot_bundle = _bundle_current(
            roots["current"],
            artifact,
            plan["arms"]["current"]["active_snapshot"]["base_head"],
        )
        _build_arms(
            roots,
            artifact,
            base_env,
            smoke_settings["timeout_seconds"],
        )
        post_build = bounded_quiet_gate(
            plan["host"],
            label="diagnostic smoke post-build observation",
            enforce_load_threshold=False,
            max_attempts=1,
            retry_seconds=0,
        )
        post_build_relative = Path("gates") / "smoke-post-build.json"
        contract.write_new_json(artifact / post_build_relative, post_build)
        post_build_evidence = _gate_evidence(
            artifact, post_build_relative, require_admissible=False
        )
        captures: list[dict[str, Any]] = []
        for launch, entry in enumerate(entries):
            arm = entry["arm"]
            relative = Path("partials") / f"smoke-{launch:02d}-{arm}.json"
            report_path = artifact / relative
            print(f"[smoke {launch + 1}/2] sha256/128 {arm}", flush=True)
            _run_logged(
                benchmark_command(roots[arm], report_path, entry, smoke_settings),
                cwd=roots[arm],
                env=_arm_environment(base_env, roots[arm]),
                log_path=artifact / "logs" / f"smoke-{launch:02d}-{arm}.log",
                timeout=smoke_settings["timeout_seconds"] * 6,
            )
            report, raw = contract.load_json(report_path)
            normalized = contract.validate_partial_report(
                report,
                arm=plan["arms"][arm],
                case=plan["workload"]["cases"][0],
                settings=smoke_settings,
                expected_host=plan["host"],
                require_publishable_power=False,
            )
            captures.append(
                {
                    "arm": arm,
                    "report_path": str(relative),
                    "report_sha256": contract.sha256_bytes(raw),
                    "report_bytes": len(raw),
                    "proof_verified": True,
                    "proof_sha256": normalized["proof_sha256"],
                    "proof_bytes": normalized["proof_bytes"],
                    "peak_rss_available": normalized["peak_rss_bytes"] > 0,
                    "release_fast_identity": True,
                    "native_recursion_disabled": True,
                    "quiet_gate": post_build_evidence,
                }
            )
            if worktree_status(roots[arm])["dirty"]:
                raise contract.ABError(f"{arm} source tree changed during smoke")
        smoke = contract.attach_seal(
            {
                "schema": "stwo_riscv_csp_native_ab_smoke_v1",
                "schema_version": 1,
                "generated_at": _now(),
                "status": "diagnostic_smoke_only",
                "eligible_for_full_ab_report": False,
                "performance_claims_allowed": False,
                "reason": (
                    "one sample exercises source capture, isolated ReleaseFast builds, "
                    "native-only proving, retained verification, and evidence validation; "
                    "it does not estimate performance"
                ),
                "diagnostic_reasons": [
                    "single-sample smoke is non-statistical by contract",
                    *plan["publishable_preflight"]["reasons"],
                    *execution_preflight["reasons"],
                    *post_build["reasons"],
                ],
                "publishable_preflight": {
                    "planning": plan["publishable_preflight"],
                    "execution": execution_preflight,
                },
                "post_build_quiet_observation": post_build_evidence,
                "plan": plan_evidence,
                "source_snapshot_bundle": snapshot_bundle,
                "workload": plan["workload"]["cases"][0],
                "settings": smoke_settings,
                "captures": captures,
            }
        )
        output = artifact / "smoke-report.json"
        contract.write_new_json(output, smoke)
        return output
    finally:
        shutil.rmtree(staging, ignore_errors=True)
