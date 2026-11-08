#!/usr/bin/env python3
"""Fail-closed development cache and retained evidence for Zig gate runs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Mapping, Sequence

try:
    from scripts import typed_air_zig_gate_execution as gate_execution
except ModuleNotFoundError:  # Direct sibling import from scripts/.
    import typed_air_zig_gate_execution as gate_execution


AUTHORITY_SCHEMA = "stwo.typed-air.zig-gate-authority.v1"
RECEIPT_SCHEMA = "stwo.typed-air.zig-gate-run-receipt.v1"
STORE_DIRECTORY_NAME = "typed-air-zig-gates"
MAX_RECEIPT_BYTES = 1024 * 1024
TIMEOUT_EXIT = gate_execution.TIMEOUT_EXIT
AUTHORITY_CHANGED_EXIT = 74
DEFAULT_REUSABLE_TIMEOUT_SECONDS = 20 * 60.0
ExecutionResult = gate_execution.ExecutionResult
execute_with_logs = gate_execution.execute_with_logs
HeldLock = gate_execution.HeldLock
try_lock = gate_execution.try_lock
read_lock_owner = gate_execution.read_lock_owner
zig_command_index = gate_execution.zig_command_index
caller_global_cache_affinity = gate_execution.caller_global_cache_affinity
semantic_external_environment = gate_execution.semantic_external_environment
DENIED_TARGET_TERMS = (
    "bench",
    "capture",
    "evidence",
    "perf",
    "profile",
    "prove",
    "prover",
    "proof",
    "receipt",
)
DENIED_ARGUMENT_PREFIXES = (
    "--artifact-out",
    "--capture-out",
    "--evidence-out",
    "-femit-asm",
    "-femit-bin",
    "-femit-docs",
    "-femit-implib",
    "-femit-llvm-bc",
    "-femit-llvm-ir",
    "-femit-h",
    "--output",
    "--perf-out",
    "--proof-out",
    "--receipt-out",
    "--report-out",
)

_CACHE_PATH_OPTIONS = frozenset(("--cache-dir", "--global-cache-dir"))
_PATH_VALUE_OPTIONS = frozenset(
    (
        "--build-file",
        "--build-runner",
        "--cache-dir",
        "--color",
        "--global-cache-dir",
        "--jobs",
        "--prefix",
        "--system",
        "--zig-lib-dir",
        "-p",
        "-j",
    )
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _git(repository: Path, arguments: Sequence[str]) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def _untracked_manifest(
    repository: Path, paths: Sequence[bytes]
) -> tuple[int, str, int]:
    digest = hashlib.sha256()
    count = 0
    symlink_count = 0
    root = repository.resolve()
    for raw_path in sorted(paths):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("git returned an unsafe untracked path")
        path = repository / relative
        metadata = path.lstat()
        resolved_parent = path.parent.resolve()
        if resolved_parent != root and root not in resolved_parent.parents:
            raise RuntimeError("untracked path escapes repository closure")
        digest.update(len(raw_path).to_bytes(8, "little"))
        digest.update(raw_path)
        digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "little"))
        if stat.S_ISREG(metadata.st_mode):
            kind = b"file"
            size, content = sha256_file(path)
            digest.update(kind)
            digest.update(size.to_bytes(8, "little"))
            digest.update(bytes.fromhex(content))
        elif stat.S_ISLNK(metadata.st_mode):
            symlink_count += 1
            kind = b"symlink"
            target = os.fsencode(os.readlink(path))
            digest.update(kind)
            digest.update(len(target).to_bytes(8, "little"))
            digest.update(target)
        else:
            raise RuntimeError(
                f"unsupported untracked path type prevents gate reuse: {path}"
            )
        count += 1
    return count, digest.hexdigest(), symlink_count


def _tracked_special_paths(repository: Path) -> tuple[int, int]:
    raw = _git(repository, ("ls-files", "--stage", "-z"))
    symlinks = 0
    gitlinks = 0
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            header, _ = entry.split(b"\t", 1)
            mode = header.split(b" ", 1)[0]
        except ValueError as error:
            raise RuntimeError("git returned an invalid index entry") from error
        symlinks += mode == b"120000"
        gitlinks += mode == b"160000"
    return symlinks, gitlinks


def source_authority(repository: Path) -> dict[str, object]:
    head = _git(repository, ("rev-parse", "HEAD")).decode("ascii").strip()
    tree = _git(repository, ("rev-parse", "HEAD^{tree}")).decode("ascii").strip()
    tracked_diff = _git(
        repository,
        ("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--"),
    )
    status = _git(
        repository,
        ("status", "--porcelain=v2", "-z", "--untracked-files=all"),
    )
    untracked_raw = _git(
        repository,
        ("ls-files", "--others", "--exclude-standard", "-z"),
    )
    untracked = [item for item in untracked_raw.split(b"\0") if item]
    untracked_count, untracked_sha, untracked_symlinks = _untracked_manifest(repository, untracked)
    tracked_symlinks, gitlinks = _tracked_special_paths(repository)
    closure_complete = not (tracked_symlinks or gitlinks or untracked_symlinks)
    return {
        "head": head,
        "tree": tree,
        "tracked_diff_bytes": len(tracked_diff),
        "tracked_diff_sha256": sha256_bytes(tracked_diff),
        "status_sha256": sha256_bytes(status),
        "untracked_files": untracked_count,
        "untracked_manifest_sha256": untracked_sha,
        "tracked_symlinks": tracked_symlinks,
        "tracked_gitlinks": gitlinks,
        "untracked_symlinks": untracked_symlinks,
        "closure_complete": closure_complete,
    }


def environment_authority(environment: Mapping[str, str]) -> dict[str, object]:
    digest = hashlib.sha256()
    for name, value in sorted(environment.items()):
        encoded_name = os.fsencode(name)
        encoded_value = os.fsencode(value)
        digest.update(len(encoded_name).to_bytes(8, "little"))
        digest.update(encoded_name)
        digest.update(len(encoded_value).to_bytes(8, "little"))
        digest.update(encoded_value)
    return {
        "variable_count": len(environment),
        "sha256": digest.hexdigest(),
    }


def host_authority() -> dict[str, str]:
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "macos_version": platform.mac_ver()[0],
    }


def _resolved_executable(
    token: str, repository: Path, environment: Mapping[str, str]
) -> Path:
    candidate = Path(token)
    if candidate.parent != Path("."):
        path = candidate if candidate.is_absolute() else repository / candidate
        resolved = path.resolve()
    else:
        located = shutil.which(token, path=environment.get("PATH"))
        if located is None:
            raise RuntimeError(f"cannot resolve executable {token!r}")
        resolved = Path(located).resolve()
    if not resolved.is_file():
        raise RuntimeError(f"resolved executable is not a regular file: {resolved}")
    return resolved


def _executable_identity(path: Path) -> dict[str, object]:
    size, digest = sha256_file(path)
    return {"path": str(path), "bytes": size, "sha256": digest}


def toolchain_authority(
    repository: Path,
    command: Sequence[str],
    environment: Mapping[str, str],
) -> dict[str, object]:
    launcher = _resolved_executable(command[0], repository, environment)
    zig_index = zig_command_index(command)
    zig_identity: dict[str, object] | None = None
    zig_version: str | None = None
    if zig_index is not None:
        zig = _resolved_executable(command[zig_index], repository, environment)
        version = subprocess.run(
            [str(zig), "version"],
            cwd=repository,
            env=dict(environment),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if version.returncode != 0 or not version.stdout.strip() or version.stderr:
            raise RuntimeError("cannot establish exact Zig toolchain version")
        zig_identity = _executable_identity(zig)
        zig_version = version.stdout.strip()
    command_executables: list[dict[str, object]] = []
    seen: set[Path] = set()
    for token in command:
        if "/" not in token and os.sep not in token:
            continue
        candidate = Path(token)
        path = candidate if candidate.is_absolute() else repository / candidate
        try:
            resolved = path.resolve()
            executable = resolved.is_file() and os.access(resolved, os.X_OK)
        except OSError:
            executable = False
        if executable and resolved not in seen:
            seen.add(resolved)
            command_executables.append(_executable_identity(resolved))
    return {
        "launcher": _executable_identity(launcher),
        "controller_python": {
            **_executable_identity(Path(sys.executable).resolve()),
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "zig": zig_identity,
        "zig_version": zig_version,
        "command_executables": command_executables,
    }


def _build_steps(arguments: Sequence[str]) -> list[str]:
    options_with_values = {
        "--build-file",
        "--build-runner",
        "--cache-dir",
        "--color",
        "--global-cache-dir",
        "--jobs",
        "--maxrss",
        "--prefix",
        "--seed",
        "--summary",
        "--system",
        "--zig-lib-dir",
        "-j",
        "-p",
    }
    result: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in options_with_values:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        result.append(argument)
        index += 1
    return result


def _target_may_publish_evidence(target: str) -> bool:
    lowered = target.lower()
    basename = Path(lowered).name
    return (
        any(term in lowered for term in DENIED_TARGET_TERMS)
        or basename == "run"
        or basename.startswith("run-")
        or basename.startswith("run_")
    )


def _has_external_path(
    repository: Path,
    command: Sequence[str],
    executable_indices: set[int],
) -> bool:
    root = repository.resolve()

    def is_external(value: str) -> bool:
        if not value or ("/" not in value and os.sep not in value):
            return False
        candidate = Path(value)
        path = candidate if candidate.is_absolute() else repository / candidate
        resolved = path.resolve()
        return resolved != root and root not in resolved.parents

    index = 0
    while index < len(command):
        argument = command[index]
        if index in executable_indices:
            index += 1
            continue
        if "=" in argument and argument.startswith("-"):
            option, value = argument.split("=", 1)
            if option not in _CACHE_PATH_OPTIONS and is_external(value):
                return True
            index += 1
            continue
        if argument in _PATH_VALUE_OPTIONS:
            if index + 1 >= len(command):
                return True
            if argument not in _CACHE_PATH_OPTIONS and is_external(command[index + 1]):
                return True
            index += 2
            continue
        if is_external(argument):
            return True
        index += 1
    return False


def reuse_policy(
    repository: Path,
    command: Sequence[str],
    *,
    evidence: bool,
) -> tuple[bool, str]:
    if evidence:
        return False, "explicit normative evidence run"
    zig_index = zig_command_index(command)
    if zig_index is None or zig_index + 1 >= len(command):
        return False, "not a recognized Zig diagnostic gate"
    executable_indices = {0, zig_index}
    if _has_external_path(repository, command, executable_indices):
        return False, "command references an unhashed external path or bundle"
    lowered = [argument.lower() for argument in command]
    if any(
        argument.startswith(prefix)
        for argument in lowered
        for prefix in DENIED_ARGUMENT_PREFIXES
    ):
        return False, "command publishes an output artifact"
    operation = lowered[zig_index + 1]
    if operation in {"bench", "build-exe", "build-lib", "build-obj", "run"}:
        return False, f"{operation} is not a reusable development gate"
    if operation in {"ast-check", "test"}:
        targets = [
            argument
            for argument in lowered[zig_index + 2 :]
            if not argument.startswith("-")
        ]
        if any(_target_may_publish_evidence(target) for target in targets):
            return False, "source/test target may produce normative evidence"
        return True, "recognized source/test diagnostic"
    if operation == "fmt":
        return ("--check" in lowered, "format check" if "--check" in lowered else "format mutation")
    if operation != "build":
        return False, "unrecognized Zig operation"
    steps = _build_steps(command[zig_index + 2 :])
    if not steps:
        return False, "default/product build has no explicit diagnostic step"
    for step in steps:
        lowered_step = step.lower()
        if _target_may_publish_evidence(lowered_step):
            return False, f"target {step!r} may produce normative evidence"
        if not (lowered_step.startswith("test") or lowered_step.startswith("check")):
            return False, f"target {step!r} is not a test/check gate"
    return True, "recognized development-only build gate"


def requires_heavy_lock(command: Sequence[str], *, evidence: bool) -> bool:
    if evidence:
        return True
    lowered = [argument.lower() for argument in command]
    if any(_target_may_publish_evidence(argument) for argument in lowered):
        return True
    if any(
        argument.startswith(prefix)
        for argument in lowered
        for prefix in DENIED_ARGUMENT_PREFIXES
    ):
        return True
    zig_index = zig_command_index(command)
    if zig_index is None or zig_index + 1 >= len(command):
        return True
    operation = lowered[zig_index + 1]
    if operation in {"bench", "build-exe", "build-lib", "build-obj", "run"}:
        return True
    if operation != "build":
        return operation not in {"ast-check", "fmt", "test", "version"}
    steps = _build_steps(command[zig_index + 2 :])
    if not steps:
        return True
    return any(
        not (step.lower().startswith("test") or step.lower().startswith("check"))
        for step in steps
    )


@dataclass(frozen=True)
class GateAuthority:
    key: str
    cache_affinity: str
    reusable: bool
    policy_reason: str
    heavy: bool
    global_cache_affinity: str | None
    timeout_seconds: float | None
    payload: dict[str, object]


def build_authority(
    repository: Path,
    command: Sequence[str],
    *,
    stage: str,
    cache_group: str | None,
    evidence: bool,
    timeout_seconds: float | None = None,
    environment: Mapping[str, str] | None = None,
    controller_files: Sequence[Path] = (),
) -> GateAuthority:
    selected_environment = dict(os.environ if environment is None else environment)
    reusable, reason = reuse_policy(repository, command, evidence=evidence)
    heavy = requires_heavy_lock(command, evidence=evidence)
    global_cache_affinity = caller_global_cache_affinity(
        repository, command, selected_environment
    )
    source = source_authority(repository)
    external_environment = semantic_external_environment(repository, selected_environment)
    if reusable and source.get("closure_complete") is False:
        reusable = False
        reason = "checkout contains symlink or submodule inputs outside the hashed closure"
    if reusable and external_environment:
        reusable = False
        reason = "environment references an unhashed external semantic path or bundle"
    effective_timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else DEFAULT_REUSABLE_TIMEOUT_SECONDS
        if reusable
        else None
    )
    toolchain = toolchain_authority(repository, command, selected_environment)
    environment_identity = environment_authority(selected_environment)
    host_identity = host_authority()
    controllers = []
    for path in controller_files:
        size, digest = sha256_file(path)
        controllers.append({"path": str(path.resolve()), "bytes": size, "sha256": digest})
    payload: dict[str, object] = {
        "schema": AUTHORITY_SCHEMA,
        "repository": str(repository.resolve()),
        "source": source,
        "command": list(command),
        "command_sha256": sha256_bytes(canonical_bytes(list(command))),
        "toolchain": toolchain,
        "host": host_identity,
        "environment": environment_identity,
        "external_semantic_environment_names": external_environment,
        "controllers": controllers,
        "stage": stage,
        "cache_group": cache_group,
        "reuse_policy": {"reusable": reusable, "reason": reason},
        "execution_policy": {
            "heavy_serialization": heavy,
            "caller_global_cache_affinity": global_cache_affinity,
            "timeout_seconds": effective_timeout,
        },
    }
    key = sha256_bytes(canonical_bytes(payload))
    affinity_input = {
        "repository": str(repository.resolve()),
        "toolchain": toolchain,
        "host": host_identity,
        "environment": environment_identity,
        "cache_group": cache_group,
        "command": None if cache_group is not None else list(command),
    }
    affinity = sha256_bytes(canonical_bytes(affinity_input))
    return GateAuthority(
        key,
        affinity,
        reusable,
        reason,
        heavy,
        global_cache_affinity,
        effective_timeout,
        payload,
    )


class GateStore:
    def __init__(self, private_directory: Path):
        self.root = private_directory / STORE_DIRECTORY_NAME
        self.receipts = self.root / "green"
        self.runs = self.root / "runs"
        self.logs = self.root / "logs"
        self.locks = self.root / "locks"
        self._ensure_directory(self.root, parents=True)
        for path in (self.receipts, self.runs, self.logs, self.locks):
            self._ensure_directory(path)

    @staticmethod
    def _ensure_directory(path: Path, *, parents: bool = False) -> None:
        path.mkdir(parents=parents, exist_ok=True)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"gate-store path is not a private directory: {path}")

    def _regular_path(self, relative: Path) -> Path:
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("gate-store path escapes its root")
        current = self.root
        for index, part in enumerate(relative.parts):
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("gate-store path contains a symlink")
            final = index == len(relative.parts) - 1
            if final:
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("gate-store leaf is not a regular file")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("gate-store path component is not a directory")
        return current

    def key_lock_path(self, key: str) -> Path:
        return self.locks / f"key-{key}.lock"

    def group_lock_path(self, affinity: str) -> Path:
        return self.locks / f"cache-{affinity}.lock"

    def heavy_lock_path(self) -> Path:
        return self.locks / "heavy-evidence.lock"

    def global_cache_lock_path(self, affinity: str) -> Path:
        return self.locks / f"caller-global-cache-{affinity}.lock"

    def green_path(self, key: str) -> Path:
        return self.receipts / f"{key}.json"

    def invalidate_green(self, key: str) -> None:
        path = self.green_path(key)
        self._ensure_directory(self.receipts)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        directory = os.open(self.receipts, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def create_logs(self, affinity: str) -> tuple[str, Path, Path]:
        run_id = f"{time.time_ns()}-{os.getpid()}"
        directory = self.logs / affinity
        self._ensure_directory(directory)
        stdout_path = directory / f"{run_id}.stdout.log"
        stderr_path = directory / f"{run_id}.stderr.log"
        for path in (stdout_path, stderr_path):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        return run_id, stdout_path, stderr_path

    def _identity(self, path: Path) -> dict[str, object]:
        relative = path.relative_to(self.root)
        checked = self._regular_path(relative)
        size, digest = sha256_file(checked)
        return {
            "path": str(relative),
            "bytes": size,
            "sha256": digest,
        }

    def _validate_log(self, value: object) -> None:
        if not isinstance(value, dict) or set(value) != {"path", "bytes", "sha256"}:
            raise ValueError("invalid retained log identity")
        if not isinstance(value["path"], str):
            raise ValueError("invalid retained log path")
        relative = Path(value["path"])
        path = self._regular_path(relative)
        size, digest = sha256_file(path)
        if size != value["bytes"] or digest != value["sha256"]:
            raise ValueError("retained log identity changed")

    def read_green(self, authority: GateAuthority) -> tuple[Path, dict[str, object]] | None:
        if not authority.reusable:
            return None
        path = self.green_path(authority.key)
        try:
            checked = self._regular_path(path.relative_to(self.root))
            metadata = checked.lstat()
        except (FileNotFoundError, ValueError):
            return None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RECEIPT_BYTES:
            return None
        try:
            raw = checked.read_bytes()
            receipt = json.loads(raw)
            if not isinstance(receipt, dict):
                return None
            expected_fields = {
                "schema", "key", "status", "reusable", "policy_reason",
                "authority", "label", "stage", "run_id", "started_unix_ns",
                "elapsed_ns", "exit_code", "timed_out", "cache_directory", "logs",
                "authority_drift",
            }
            if set(receipt) != expected_fields:
                return None
            if (
                receipt["schema"] != RECEIPT_SCHEMA
                or receipt["key"] != authority.key
                or receipt["status"] != "GREEN"
                or receipt["reusable"] is not True
                or receipt["exit_code"] != 0
                or receipt["timed_out"] is not False
                or receipt["authority_drift"] is not False
                or receipt["authority"] != authority.payload
                or canonical_bytes(receipt) != raw
            ):
                return None
            logs = receipt["logs"]
            if not isinstance(logs, dict) or set(logs) != {"stdout", "stderr"}:
                return None
            self._validate_log(logs["stdout"])
            self._validate_log(logs["stderr"])
            return path, receipt
        except (
            OSError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return None

    def _write_atomic(self, path: Path, raw: bytes) -> None:
        parent_relative = path.parent.relative_to(self.root)
        current = self.root
        for part in parent_relative.parts:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError("gate-store receipt parent is not a private directory")
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _write_create_only(self, path: Path, raw: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def publish(
        self,
        authority: GateAuthority,
        *,
        label: str,
        stage: str,
        run_id: str,
        started_unix_ns: int,
        elapsed_ns: int,
        exit_code: int,
        timed_out: bool,
        cache_directory: Path,
        stdout_path: Path,
        stderr_path: Path,
        authority_drift: bool = False,
    ) -> tuple[Path, dict[str, object]]:
        status = (
            "TIMEOUT"
            if timed_out
            else "DRIFT"
            if authority_drift
            else "GREEN"
            if exit_code == 0
            else "RED"
        )
        receipt: dict[str, object] = {
            "schema": RECEIPT_SCHEMA,
            "key": authority.key,
            "status": status,
            "reusable": authority.reusable and status == "GREEN",
            "policy_reason": authority.policy_reason,
            "authority": authority.payload,
            "label": label,
            "stage": stage,
            "run_id": run_id,
            "started_unix_ns": started_unix_ns,
            "elapsed_ns": elapsed_ns,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "authority_drift": authority_drift,
            "cache_directory": str(cache_directory),
            "logs": {
                "stdout": self._identity(stdout_path),
                "stderr": self._identity(stderr_path),
            },
        }
        raw = canonical_bytes(receipt)
        run_path = self.runs / f"{run_id}.json"
        self._write_create_only(run_path, raw)
        if receipt["reusable"]:
            self._write_atomic(self.green_path(authority.key), raw)
        else:
            self.invalidate_green(authority.key)
        return run_path, receipt
