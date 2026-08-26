"""Source isolation, host admission, and installed-binary gates for R-006.

The normative 1/2/4/max-worker plans still accept only an ordinary clean Git
commit.  A dirty development checkout may be copied into the already-audited
deterministic ephemeral snapshot format for build and functional V4 smoke, but
that commit class is explicitly rejected by :func:`contract.source_identity`.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from scripts.riscv_csp_ab_benchmark_lib import contract as ab_contract
from scripts.riscv_csp_ab_benchmark_lib import runner as ab_runner
from scripts.riscv_csp_benchmark_lib.host import collect_host

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .contract import (
    EPHEMERAL_SNAPSHOT_MESSAGE_PREFIX,
    _file_identity,
    _require_binary_markers,
    _validate_generated_input,
)
from .controller import Journal, ProcessResult, default_child_runner, run_attempt
from .model import ENVIRONMENT, GENERATED_WORKLOADS, LANES, UTC_RE, CaptureError
from .preflight import build_host_preflight, validate_host_preflight


SNAPSHOT_SCHEMA = "stwo.typed-air.r006-diagnostic-source-snapshot.v1"
INSTALL_SCHEMA = "stwo.typed-air.r006-diagnostic-install.v1"
SMOKE_SCHEMA = "stwo.typed-air.r006-installed-v4-smoke.v1"
SNAPSHOT_CLASSIFICATION = "diagnostic-content-bound-not-performance-receiptable"
INSTALL_LANES = ("cpu-native", "metal-hybrid")


CommandRunner = Callable[
    [Sequence[str], Path, Mapping[str, str], float], subprocess.CompletedProcess[bytes]
]
SourceProvider = Callable[[Path], dict[str, Any]]
HostProvider = Callable[[], dict[str, Any]]
QuietProvider = Callable[[Mapping[str, Any]], dict[str, Any]]


INSTALL_FIELDS = {
    "schema",
    "schema_version",
    "classification",
    "started_at_utc",
    "completed_at_utc",
    "source",
    "install_prefix",
    "optimization_mode",
    "toolchain",
    "toolchain_binary",
    "build_environment",
    "command",
    "command_sha256",
    "stdout_sha256",
    "stderr_sha256",
    "binaries",
    "required_exact_work_markers_present",
    "normative_performance_receipt",
    "content_sha256",
}
SNAPSHOT_FIELDS = {
    "schema",
    "schema_version",
    "classification",
    "created_at_utc",
    "active_repository",
    "snapshot_repository",
    "source",
    "capture",
    "normative_r006_plan_permitted",
    "allowed_uses",
    "content_sha256",
}
SNAPSHOT_CAPTURE_FIELDS = {
    "active_worktree_dirty",
    "base_head",
    "source_content_sha256",
    "source_file_count",
    "source_payload_bytes",
    "status_sha256",
    "status_entry_count",
    "status_category_counts",
    "tracked_patch_sha256",
    "tracked_patch_bytes",
    "untracked_payload_sha256",
    "untracked_file_count",
    "untracked_payload_bytes",
    "ignored_source_input_count",
    "temporary_tree_git_oid",
    "temporary_tree_listing_sha256",
    "temporary_commit",
    "capture_protocol",
}


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _run(
    command: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CaptureError(f"orchestration command failed to launch: {command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-4096:].decode("utf-8", "replace")
        raise CaptureError(
            f"orchestration command exited {result.returncode}: {' '.join(command)}: {detail}"
        )
    return result


def _git(repository: Path, *arguments: str) -> bytes:
    return _run(
        ("git", *arguments), repository, {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, 600
    ).stdout


def diagnostic_source_identity(repository: Path) -> dict[str, Any]:
    """Identify a clean ordinary or deterministic ephemeral checkout.

    This authority exists only for install/smoke receipts.  Normative planning
    uses ``contract.source_identity`` and rejects the ephemeral commit marker.
    """

    root = repository.resolve()
    commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise CaptureError("R-006 diagnostic source must be an isolated clean snapshot")
    message = _git(root, "log", "-1", "--format=%B").decode("utf-8", "strict")
    listing = _git(root, "ls-tree", "-r", "--full-tree", "HEAD")
    if not listing or not listing.endswith(b"\n"):
        raise CaptureError("diagnostic source closure is empty or malformed")
    ephemeral = message.startswith(EPHEMERAL_SNAPSHOT_MESSAGE_PREFIX)
    return {
        "classification": (
            SNAPSHOT_CLASSIFICATION if ephemeral else "clean-committed-diagnostic-source"
        ),
        "commit": commit,
        "tree": tree,
        "clean": True,
        "ephemeral": ephemeral,
        "source_closure_files": listing.count(b"\n"),
        "source_closure_sha256": sha256_bytes(listing),
    }


def materialize_snapshot(
    active_repository: Path,
    destination: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    active = active_repository.resolve()
    target = destination.resolve()
    receipt = receipt_path.resolve()
    if (
        _inside(target, active)
        or _inside(receipt, active)
        or _inside(receipt, target)
    ):
        raise CaptureError(
            "R-006 snapshot and receipt paths must be outside the active repository"
        )
    try:
        provenance = ab_runner.materialize_ephemeral_current(active, target)
    except ab_contract.ABError as error:
        raise CaptureError(str(error)) from error
    identity = diagnostic_source_identity(target)
    if not identity["ephemeral"]:
        raise CaptureError("isolated dirty-source snapshot lacks its diagnostic commit marker")
    result: dict[str, Any] = {
        "schema": SNAPSHOT_SCHEMA,
        "schema_version": 1,
        "classification": SNAPSHOT_CLASSIFICATION,
        "created_at_utc": _utc_now(),
        "active_repository": str(active),
        "snapshot_repository": str(target),
        "source": identity,
        "capture": provenance,
        "normative_r006_plan_permitted": False,
        "allowed_uses": [
            "ReleaseFast isolated candidate build",
            "installed-binary V4 functional smoke",
        ],
    }
    result["content_sha256"] = content_digest(result)
    write_new(receipt, canonical_bytes(result))
    return result


def validate_snapshot_receipt(
    receipt_path: Path,
    *,
    source_provider: SourceProvider = diagnostic_source_identity,
) -> dict[str, Any]:
    receipt = receipt_path.resolve()
    try:
        raw = receipt.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read the diagnostic snapshot receipt") from error
    value = decode_strict(raw)
    snapshot = exact_object(value, SNAPSHOT_FIELDS, "diagnostic snapshot receipt")
    if raw != canonical_bytes(snapshot):
        raise CaptureError("diagnostic snapshot receipt is not canonical JSON")
    if (
        snapshot["schema"] != SNAPSHOT_SCHEMA
        or snapshot["schema_version"] != 1
        or snapshot["classification"] != SNAPSHOT_CLASSIFICATION
        or snapshot["normative_r006_plan_permitted"] is not False
        or snapshot["allowed_uses"]
        != [
            "ReleaseFast isolated candidate build",
            "installed-binary V4 functional smoke",
        ]
        or snapshot["content_sha256"] != content_digest(snapshot)
    ):
        raise CaptureError("diagnostic snapshot receipt authority changed")
    if type(snapshot["active_repository"]) is not str or type(snapshot["snapshot_repository"]) is not str:
        raise CaptureError("diagnostic snapshot repository paths must be text")
    active = Path(snapshot["active_repository"])
    source = Path(snapshot["snapshot_repository"])
    if (
        not active.is_absolute()
        or not source.is_absolute()
        or _inside(source, active)
        or _inside(receipt, active)
        or _inside(receipt, source)
    ):
        raise CaptureError("diagnostic snapshot receipt path separation changed")
    live_source = source_provider(source)
    if snapshot["source"] != live_source:
        raise CaptureError("diagnostic snapshot source changed after materialization")
    capture = exact_object(
        snapshot["capture"],
        SNAPSHOT_CAPTURE_FIELDS,
        "diagnostic snapshot capture provenance",
    )
    if (
        capture["capture_protocol"]
        != "binary_HEAD_diff_plus_git_ls_files_others_exclude_standard_v1"
        or capture["ignored_source_input_count"] != 0
        or capture["temporary_commit"] != live_source["commit"]
        or capture["temporary_tree_git_oid"] != live_source["tree"]
        or capture["source_file_count"] != live_source["source_closure_files"]
    ):
        raise CaptureError("diagnostic snapshot provenance does not bind its live source")
    return {
        "schema": "stwo.typed-air.r006-diagnostic-source-validation.v1",
        "status": "VALID_DIAGNOSTIC_SOURCE",
        "classification": SNAPSHOT_CLASSIFICATION,
        "snapshot_receipt_sha256": sha256_bytes(raw),
        "source": live_source,
        "normative_r006_plan_permitted": False,
    }


def host_preflight(
    *,
    host_provider: HostProvider = collect_host,
    quiet_provider: QuietProvider = ab_runner.quiet_host_preflight,
) -> dict[str, Any]:
    """Observe and seal the native CSP power/quiet/thermal authority."""

    host = host_provider()
    try:
        quiet = quiet_provider(host)
    except ab_contract.ABError as error:
        raise CaptureError(str(error)) from error
    return build_host_preflight(host, quiet)


def _snapshot_build_environment(
    snapshot: Path,
    inherited: Mapping[str, str] = os.environ,
) -> tuple[dict[str, str], dict[str, Any], Path]:
    local_cache = snapshot / ".zig-cache/r006-install-local"
    global_cache = snapshot / ".zig-cache/r006-install-global"
    path = inherited.get("PATH")
    if not path:
        raise CaptureError("R-006 install requires an explicit PATH")
    zig = shutil.which("zig", path=path)
    if zig is None:
        raise CaptureError("R-006 install cannot resolve zig from the sanitized PATH")
    admitted_names = (
        "PATH",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
    )
    environment = {
        name: inherited[name]
        for name in admitted_names
        if name in inherited and inherited[name]
    }
    environment.update({
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "ZIG_LOCAL_CACHE_DIR": str(local_cache),
        "ZIG_GLOBAL_CACHE_DIR": str(global_cache),
    })
    evidence: dict[str, Any] = {
        "policy": "r006_releasefast_install_sanitized_v1",
        "variables": dict(sorted(environment.items())),
        "admitted_inherited_names": [
            name for name in admitted_names if name in environment
        ],
        "removed_stwo_names": sorted(
            name for name in inherited if name.startswith("STWO_")
        ),
        "cache_isolation": {
            "local": str(local_cache),
            "global": str(global_cache),
        },
        "secret_values_recorded": False,
    }
    return environment, evidence, Path(zig).resolve()


def install_candidate(
    snapshot_repository: Path,
    prefix: Path,
    receipt_path: Path,
    *,
    execute_releasefast_build: bool,
    command_runner: CommandRunner = _run,
    source_provider: SourceProvider = diagnostic_source_identity,
) -> dict[str, Any]:
    if not execute_releasefast_build:
        raise CaptureError("R-006 install requires the explicit ReleaseFast execution token")
    snapshot = snapshot_repository.resolve()
    install_prefix = prefix.resolve()
    receipt = receipt_path.resolve()
    source = source_provider(snapshot)
    if not source["ephemeral"]:
        raise CaptureError("diagnostic install accepts only the isolated ephemeral snapshot")
    if install_prefix.exists():
        raise CaptureError("R-006 install prefix must be create-only")
    if (
        _inside(install_prefix, snapshot)
        or _inside(receipt, snapshot)
        or _inside(receipt, install_prefix)
    ):
        raise CaptureError("R-006 install outputs must be outside the source snapshot")
    environment, environment_evidence, zig = _snapshot_build_environment(snapshot)
    command = (
        str(zig),
        "build",
        LANES["cpu-native"]["build_step"],
        LANES["metal-hybrid"]["build_step"],
        "-Doptimize=ReleaseFast",
        "--prefix",
        str(install_prefix),
    )
    started = _utc_now()
    output = command_runner(command, snapshot, environment, 3600)
    if output.returncode != 0:
        raise CaptureError(
            f"ReleaseFast candidate build exited {output.returncode}"
        )
    version_result = command_runner((str(zig), "version"), snapshot, environment, 30)
    if version_result.returncode != 0 or version_result.stderr:
        raise CaptureError("zig version failed while sealing the diagnostic install")
    toolchain = version_result.stdout.decode("ascii", "strict").strip()
    if not toolchain or len(toolchain) > 256:
        raise CaptureError("zig version returned no bounded toolchain identity")
    if source_provider(snapshot) != source:
        raise CaptureError("R-006 diagnostic source drifted during candidate installation")
    binaries: dict[str, dict[str, object]] = {}
    for lane in INSTALL_LANES:
        path = install_prefix / "bin" / LANES[lane]["executable"]
        before = _file_identity(path, executable=True)
        _require_binary_markers(path)
        after = _file_identity(path, executable=True)
        if after != before:
            raise CaptureError("installed candidate binary changed while it was authenticated")
        binaries[lane] = after
    result: dict[str, Any] = {
        "schema": INSTALL_SCHEMA,
        "schema_version": 1,
        "classification": SNAPSHOT_CLASSIFICATION,
        "started_at_utc": started,
        "completed_at_utc": _utc_now(),
        "source": source,
        "install_prefix": str(install_prefix),
        "optimization_mode": "ReleaseFast",
        "toolchain": f"zig:{toolchain}",
        "toolchain_binary": _file_identity(zig, executable=True),
        "build_environment": environment_evidence,
        "command": list(command),
        "command_sha256": sha256_bytes(canonical_bytes(list(command))),
        "stdout_sha256": sha256_bytes(output.stdout),
        "stderr_sha256": sha256_bytes(output.stderr),
        "binaries": binaries,
        "required_exact_work_markers_present": True,
        "normative_performance_receipt": False,
    }
    result["content_sha256"] = content_digest(result)
    write_new(receipt, canonical_bytes(result))
    return result


@dataclass(frozen=True)
class SmokeSettings:
    repository: Path
    lane: str
    executable: Path
    install_receipt: Path
    elf: Path
    input_path: Path | None
    bundle: Path
    session_id: str
    execute_installed_v4_smoke: bool
    timeout_seconds: float = 86_400.0
    generated_workload_id: str | None = None


def _load_install_receipt(
    receipt_path: Path,
    *,
    repository: Path,
    lane: str,
    executable: Path,
    source_provider: SourceProvider,
) -> tuple[dict[str, Any], dict[str, object]]:
    receipt = receipt_path.resolve()
    try:
        raw = receipt.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read the diagnostic install receipt") from error
    value = decode_strict(raw)
    install = exact_object(value, INSTALL_FIELDS, "diagnostic install receipt")
    if raw != canonical_bytes(install):
        raise CaptureError("diagnostic install receipt is not canonical JSON")
    if (
        install["schema"] != INSTALL_SCHEMA
        or install["schema_version"] != 1
        or install["classification"] != SNAPSHOT_CLASSIFICATION
        or install["optimization_mode"] != "ReleaseFast"
        or install["required_exact_work_markers_present"] is not True
        or install["normative_performance_receipt"] is not False
        or install["content_sha256"] != content_digest(install)
    ):
        raise CaptureError("diagnostic install receipt authority changed")
    if install["source"] != source_provider(repository.resolve()):
        raise CaptureError("diagnostic install receipt source no longer matches the snapshot")
    if type(install["binaries"]) is not dict or set(install["binaries"]) != set(INSTALL_LANES):
        raise CaptureError("diagnostic install receipt binary lane set changed")
    expected = install["binaries"][lane]
    if type(expected) is not dict or _file_identity(executable, executable=True) != expected:
        raise CaptureError("installed executable bytes differ from the install receipt")
    return install, _file_identity(receipt)


def _smoke_workload(settings: SmokeSettings) -> dict[str, Any]:
    selected = settings.generated_workload_id
    if selected is None:
        return {
            "id": "installed_v4_smoke",
            "elf": _file_identity(settings.elf),
            "input": (
                _file_identity(settings.input_path)
                if settings.input_path is not None
                else None
            ),
        }
    if type(selected) is not str or selected not in GENERATED_WORKLOADS:
        raise CaptureError("installed smoke generated workload is not frozen")
    if settings.input_path is None:
        raise CaptureError("generated installed smoke requires its canonical input")
    return {
        "id": selected,
        "elf": _file_identity(settings.elf),
        "input": _file_identity(settings.input_path),
        "generator": dict(GENERATED_WORKLOADS[selected]),
        "parameters": _validate_generated_input(settings.input_path, selected),
    }


def _smoke_plan(
    settings: SmokeSettings,
    *,
    source_provider: SourceProvider,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, object]]:
    if settings.lane not in LANES:
        raise CaptureError("installed V4 smoke lane is invalid")
    source = source_provider(settings.repository)
    install, receipt_identity = _load_install_receipt(
        settings.install_receipt,
        repository=settings.repository,
        lane=settings.lane,
        executable=settings.executable,
        source_provider=source_provider,
    )
    if install["source"] != source:
        raise CaptureError("installed V4 smoke source and install receipt disagree")
    executable = _file_identity(settings.executable, executable=True)
    _require_binary_markers(Path(str(executable["path"])))
    if _file_identity(settings.executable, executable=True) != executable:
        raise CaptureError("installed executable changed while its markers were authenticated")
    workload = _smoke_workload(settings)
    lane = LANES[settings.lane]
    attempt = {
        "ordinal": 0,
        "attempt_id": "r006-installed-v4-smoke-0000",
        "workload_id": workload["id"],
        "worker_count": 1,
        "proof_path": "attempts/0000.proof.json",
        "report_path": "attempts/0000.report.json",
        "stderr_path": "attempts/0000.stderr.bin",
        "verify_stdout_path": "attempts/0000.verify.stdout.bin",
        "verify_stderr_path": "attempts/0000.verify.stderr.bin",
    }
    plan: dict[str, Any] = {
        "schema": SMOKE_SCHEMA,
        "session_id": settings.session_id,
        "source": source,
        "build": {
            "executable_path": executable["path"],
            "executable_bytes": executable["bytes"],
            "executable_sha256": executable["sha256"],
            "install_prefix": install["install_prefix"],
            "install_receipt": receipt_identity,
        },
        "lane": {
            "id": settings.lane,
            "backend": lane["backend"],
            "cli_backend": lane["cli_backend"],
        },
        "environment": dict(ENVIRONMENT),
        "workloads": [workload],
        "attempts": [attempt],
    }
    plan["content_sha256"] = content_digest(plan)
    return plan, attempt, receipt_identity


def installed_v4_smoke(
    settings: SmokeSettings,
    *,
    child_runner: Callable[
        [Sequence[str], Path, float, Mapping[str, str]], ProcessResult
    ] = default_child_runner,
    source_provider: SourceProvider = diagnostic_source_identity,
) -> dict[str, Any]:
    if not settings.execute_installed_v4_smoke:
        raise CaptureError("installed V4 smoke requires its explicit execution token")
    if settings.timeout_seconds <= 0:
        raise CaptureError("installed V4 smoke timeout must be positive")
    plan, attempt, receipt_identity = _smoke_plan(
        settings,
        source_provider=source_provider,
    )
    if (
        _inside(settings.bundle, settings.repository)
        or _inside(settings.bundle, Path(plan["build"]["install_prefix"]))
    ):
        raise CaptureError(
            "installed V4 smoke bundle must be outside the source snapshot and install prefix"
        )
    journal = Journal(settings.bundle, plan, canonical_bytes(plan))
    try:
        record = run_attempt(
            journal=journal,
            plan=plan,
            attempt=attempt,
            timeout_seconds=settings.timeout_seconds,
            child_runner=child_runner,
            monotonic=time.monotonic_ns,
            utc_clock=lambda: dt.datetime.now(dt.timezone.utc),
        )
        sealed_record = journal.append(record)
        if source_provider(settings.repository.resolve()) != plan["source"]:
            raise CaptureError("R-006 diagnostic source drifted during installed V4 smoke")
        if _file_identity(settings.executable, executable=True) != {
            "path": plan["build"]["executable_path"],
            "bytes": plan["build"]["executable_bytes"],
            "sha256": plan["build"]["executable_sha256"],
        }:
            raise CaptureError("installed executable drifted during V4 smoke")
        if _file_identity(settings.install_receipt) != receipt_identity:
            raise CaptureError("diagnostic install receipt drifted during V4 smoke")
        workload = plan["workloads"][0]
        if _file_identity(settings.elf) != workload["elf"]:
            raise CaptureError("installed V4 smoke ELF drifted during execution")
        if settings.input_path is not None and _file_identity(settings.input_path) != workload["input"]:
            raise CaptureError("installed V4 smoke input drifted during execution")
        journal_identity = journal.close()
    except BaseException:
        journal.abandon()
        raise
    verified = record["status"] == "verified" and record["metrics"] is not None
    exact_work = verified and "work_disclosure" in record["metrics"]
    result: dict[str, Any] = {
        "schema": SMOKE_SCHEMA,
        "schema_version": 1,
        "classification": "installed-v4-functional-smoke-not-performance-evidence",
        "status": "PASS" if verified and exact_work else "FAIL",
        "session_id": settings.session_id,
        "source": plan["source"],
        "build": plan["build"],
        "install_receipt": receipt_identity,
        "lane": plan["lane"],
        "workload": plan["workloads"][0],
        "record_sha256": sealed_record["content_sha256"],
        "journal": journal_identity,
        "independent_verification": record["independent_verification"]["status"],
        "work_disclosure": (
            record["metrics"].get("work_disclosure") if verified else None
        ),
        "normative_performance_receipt": False,
    }
    result["content_sha256"] = content_digest(result)
    write_new(journal.bundle / "smoke.json", canonical_bytes(result))
    if result["status"] != "PASS":
        raise CaptureError(
            f"installed V4 smoke failed: {record['failure_code'] or 'missing exact work'}"
        )
    return result
