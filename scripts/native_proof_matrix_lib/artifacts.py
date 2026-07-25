"""Atomic artifact and subprocess boundaries for Native proof matrices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .model import (
    AIR_PROTOCOLS,
    INTEROP_UPSTREAM_COMMIT,
    RUST_ORACLE_CAPABILITY_PROTOCOL,
    RUST_ORACLE_SHA256,
    RUST_ORACLE_TOOLCHAIN,
    MatrixError,
    Workload,
)

try:
    from process_resources_lib import (
        ResourceMeasurementError,
        measurement_command as shared_measurement_command,
        parse_process_resources as shared_parse_process_resources,
    )
except ModuleNotFoundError:
    from scripts.process_resources_lib import (
        ResourceMeasurementError,
        measurement_command as shared_measurement_command,
        parse_process_resources as shared_parse_process_resources,
    )


ROOT = Path(
    os.environ.get("STWO_ZIG_EXECUTION_ROOT", Path(__file__).resolve().parents[2])
).resolve()
PROFILE_ENV_VARS = (
    "STWO_ZIG_METAL_PROFILE_OUT",
    "STWO_ZIG_METAL_PROFILE_ENCODER_COUNTERS",
    "STWO_ZIG_METAL_PROFILE_MAX_ENCODERS",
)
MAX_STDOUT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024 * 1024
MAX_PROOF_ARTIFACT_BYTES = 64 * 1024 * 1024
HOST_MEASUREMENT_LOCK = Path("/tmp/stwo-perf-judge.lock")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_bytes(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, document: dict[str, Any]) -> bytes:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    atomic_write_bytes(path, encoded)
    return encoded


def prepare_output_dir(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise MatrixError(f"output path is not a directory: {path}")
        if any(path.iterdir()):
            raise MatrixError(f"output directory is not empty: {path}")
    else:
        path.mkdir(parents=True)


@contextmanager
def output_dir_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise MatrixError(f"output directory is locked: {path}") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode())
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


@contextmanager
def host_measurement_lock(repo_root: Path) -> Iterator[None]:
    """Exclude judged matrices from every cooperating host benchmark."""
    payload = f"{os.getpid()} {repo_root.resolve()}\n".encode()
    descriptor: int | None = None
    for _ in range(2):
        try:
            descriptor = os.open(
                HOST_MEASUREMENT_LOCK,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o644,
            )
            break
        except FileExistsError as error:
            try:
                pid = int(HOST_MEASUREMENT_LOCK.read_text().split()[0])
                os.kill(pid, 0)
            except PermissionError as live_error:
                raise MatrixError(
                    f"host measurement lock held by another user: "
                    f"{HOST_MEASUREMENT_LOCK}"
                ) from live_error
            except (ValueError, IndexError, ProcessLookupError, OSError):
                HOST_MEASUREMENT_LOCK.unlink(missing_ok=True)
                continue
            raise MatrixError(
                f"host measurement lock held by pid {pid}: {HOST_MEASUREMENT_LOCK}"
            ) from error
    if descriptor is None:
        raise MatrixError(
            f"could not acquire host measurement lock: {HOST_MEASUREMENT_LOCK}"
        )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        HOST_MEASUREMENT_LOCK.unlink(missing_ok=True)


def require_unprofiled_environment(environment: dict[str, str]) -> None:
    inherited = sorted(name for name in PROFILE_ENV_VARS if name in environment)
    if inherited:
        raise MatrixError(
            "formal matrix refuses inherited Metal profiler environment: "
            + ", ".join(inherited)
        )


def require_binary(path: Path, lane: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise MatrixError(f"{lane} benchmark binary does not exist: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise MatrixError(f"{lane} benchmark binary is not executable: {resolved}")
    return resolved


def resource_measurement_command(command: list[str]) -> tuple[list[str], str]:
    try:
        return shared_measurement_command(command, required=True)
    except ResourceMeasurementError as error:
        raise MatrixError(str(error)) from error


def parse_process_resources(stderr: bytes, measurement: str) -> dict[str, Any]:
    try:
        resources = shared_parse_process_resources(stderr, measurement)
    except ResourceMeasurementError as error:
        raise MatrixError(str(error)) from error
    return {
        key: resources[key]
        for key in ("measurement", "measurement_locale", "normalized_unit", "peak_rss_kib")
    }


def as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode()


def publish_capture(
    temporary: Any,
    destination: Path,
    supplemental: bytes | str | None,
) -> int:
    extra = as_bytes(supplemental)
    if extra:
        temporary.write(extra)
    temporary.flush()
    os.fsync(temporary.fileno())
    size = os.fstat(temporary.fileno()).st_size
    temporary_path = Path(temporary.name)
    temporary.close()
    os.replace(temporary_path, destination)
    return size


def publish_captures(
    captures: tuple[tuple[Any, Path, bytes | str | None, int], ...],
) -> None:
    oversized: list[str] = []
    failures: list[str] = []
    for temporary, destination, supplemental, maximum_bytes in captures:
        try:
            size = publish_capture(temporary, destination, supplemental)
        except BaseException as error:
            temporary.close()
            Path(temporary.name).unlink(missing_ok=True)
            failures.append(f"{destination}: {error}")
            continue
        if size > maximum_bytes:
            oversized.append(f"{destination} ({size} > {maximum_bytes})")
    if failures:
        raise MatrixError("failed to publish captured streams: " + "; ".join(failures))
    if oversized:
        raise MatrixError("captured stream limit exceeded: " + "; ".join(oversized))


def decode_report(stdout: bytes, lane: str) -> dict[str, Any]:
    try:
        document = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"{lane} stdout is not one valid UTF-8 JSON document") from error
    if not isinstance(document, dict):
        raise MatrixError(f"{lane} report root must be an object")
    return document


def load_proof_artifact(path: Path, lane: str) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_PROOF_ARTIFACT_BYTES + 1)
    except FileNotFoundError as error:
        raise MatrixError(f"{lane} proof artifact was not produced: {path}") from error
    if len(raw) > MAX_PROOF_ARTIFACT_BYTES:
        raise MatrixError(
            f"{lane} proof artifact exceeds {MAX_PROOF_ARTIFACT_BYTES} byte limit"
        )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"{lane} proof artifact is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise MatrixError(f"{lane} proof artifact root must be an object")

    proof_hex = document.get("proof_bytes_hex")
    if (
        not isinstance(proof_hex, str)
        or len(proof_hex) == 0
        or len(proof_hex) % 2 != 0
        or any(character not in "0123456789abcdef" for character in proof_hex)
    ):
        raise MatrixError(f"{lane} proof artifact has noncanonical proof_bytes_hex")
    proof_bytes = bytes.fromhex(proof_hex)
    try:
        proof_wire = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"{lane} artifact proof bytes are not JSON wire data") from error
    if not isinstance(proof_wire, dict):
        raise MatrixError(f"{lane} artifact proof wire root must be an object")

    return {
        "path": path,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "document": document,
        "proof_bytes": len(proof_bytes),
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
    }


def lane_command(
    binary: Path,
    workload: Workload,
    warmups: int,
    samples: int,
    protocol: str,
    proof_artifact_path: Path,
    *,
    resource_profile: str = "standard",
    blake2_backend: str | None = None,
    metal_runtime: str | None = None,
    metal_aot_bundle: Path | None = None,
    metal_aot_manifest_sha256: str | None = None,
) -> list[str]:
    command = [
        str(binary),
        *workload.native_flags(),
        "--warmups",
        str(warmups),
        "--samples",
        str(samples),
        "--protocol",
        protocol,
        "--resource-profile",
        resource_profile,
    ]
    if blake2_backend is not None:
        command.extend(("--blake2-backend", blake2_backend))
    if metal_runtime is not None:
        command.extend(("--metal-runtime", metal_runtime))
        if metal_runtime == "authenticated-aot":
            if metal_aot_bundle is None or metal_aot_manifest_sha256 is None:
                raise MatrixError("authenticated AOT lane command is incomplete")
            command.extend((
                "--metal-aot-bundle",
                str(metal_aot_bundle),
                "--metal-aot-manifest-sha256",
                metal_aot_manifest_sha256,
            ))
    command.extend(("--proof-artifact-out", str(proof_artifact_path)))
    return command


def run_rust_oracle(
    binary: Path,
    artifact_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    resolved = require_binary(binary, "Rust oracle")
    binary_sha256 = sha256_file(resolved)
    if binary_sha256 != RUST_ORACLE_SHA256:
        raise MatrixError(
            "Rust oracle binary digest does not match the pinned verifier "
            f"({binary_sha256} != {RUST_ORACLE_SHA256})"
        )
    artifact_sha256 = sha256_file(artifact_path)
    command = [str(resolved), "--mode", "verify", "--artifact", str(artifact_path)]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixError(
            f"Rust oracle timed out after {timeout_seconds} seconds"
        ) from error
    elapsed_seconds = time.perf_counter() - started
    if len(completed.stdout) > MAX_STDOUT_BYTES or len(completed.stderr) > MAX_STDERR_BYTES:
        raise MatrixError("Rust oracle output exceeded capture limits")
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise MatrixError(
            f"Rust oracle rejected canonical artifact; stderr tail:\n{tail}"
        )
    if completed.stdout.strip() or completed.stderr.strip():
        raise MatrixError("Rust oracle verify mode produced unexpected output")
    if sha256_file(resolved) != RUST_ORACLE_SHA256:
        raise MatrixError("Rust oracle binary changed during verification")
    if sha256_file(artifact_path) != artifact_sha256:
        raise MatrixError("canonical artifact changed during Rust verification")
    return {
        "status": "passed",
        "verified": True,
        "upstream_commit": INTEROP_UPSTREAM_COMMIT,
        "toolchain": RUST_ORACLE_TOOLCHAIN,
        "binary_path": str(resolved),
        "binary_sha256": binary_sha256,
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha256,
        "command": command,
        "elapsed_seconds": elapsed_seconds,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def preflight_rust_oracle_adapter(
    binary: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    resolved = require_binary(binary, "Rust oracle")
    binary_sha256 = sha256_file(resolved)
    if binary_sha256 != RUST_ORACLE_SHA256:
        raise MatrixError(
            "Rust oracle binary digest does not match the pinned verifier "
            f"({binary_sha256} != {RUST_ORACLE_SHA256})"
        )
    command = [str(resolved), "--mode", "capabilities"]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixError(
            f"Rust oracle capability preflight timed out after {timeout_seconds} seconds"
        ) from error
    if len(completed.stdout) > MAX_STDOUT_BYTES or len(completed.stderr) > MAX_STDERR_BYTES:
        raise MatrixError("Rust oracle capability output exceeded capture limits")
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise MatrixError(
            "Rust oracle does not expose the required exact AIR adapter "
            f"capabilities; stderr tail:\n{tail}"
        )
    if completed.stderr.strip():
        raise MatrixError("Rust oracle capability preflight produced unexpected stderr")
    try:
        manifest = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError("Rust oracle capability manifest is invalid JSON") from error
    expected = {
        "schema_version": 1,
        "protocol": RUST_ORACLE_CAPABILITY_PROTOCOL,
        "upstream_commit": INTEROP_UPSTREAM_COMMIT,
        "exact_air_protocols": {
            "poseidon": AIR_PROTOCOLS["poseidon"],
            "state_machine": AIR_PROTOCOLS["state_machine"],
            "xor": AIR_PROTOCOLS["xor"],
        },
    }
    if manifest != expected:
        raise MatrixError("Rust oracle exact AIR adapter capabilities are stale")
    if sha256_file(resolved) != RUST_ORACLE_SHA256:
        raise MatrixError("Rust oracle binary changed during capability preflight")
    return manifest


def run_lane(
    lane: str,
    binary: Path,
    workload: Workload,
    args: argparse.Namespace,
    artifact_dir: Path,
) -> dict[str, Any]:
    stdout_path = artifact_dir / f"{lane}.stdout.json"
    stderr_path = artifact_dir / f"{lane}.stderr.txt"
    proof_artifact_path = artifact_dir / f"{lane}.proof-artifact.json"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if proof_artifact_path.exists():
        raise MatrixError(f"refusing to overwrite proof artifact: {proof_artifact_path}")
    command = lane_command(
        binary,
        workload,
        args.warmups,
        args.samples,
        args.protocol,
        proof_artifact_path,
        resource_profile=getattr(args, "resource_profile", "standard"),
        blake2_backend=getattr(args, "blake2_backend", "auto"),
        metal_runtime=getattr(args, "metal_runtime", "source-jit") if lane == "metal" else None,
        metal_aot_bundle=getattr(args, "metal_aot_bundle", None),
        metal_aot_manifest_sha256=getattr(args, "metal_aot_manifest_sha256", None),
    )
    measured_command, resource_measurement = resource_measurement_command(command)
    stdout_capture = tempfile.NamedTemporaryFile(
        dir=artifact_dir,
        prefix=f".{lane}.stdout.",
        delete=False,
    )
    stderr_capture = tempfile.NamedTemporaryFile(
        dir=artifact_dir,
        prefix=f".{lane}.stderr.",
        delete=False,
    )
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            measured_command,
            cwd=ROOT,
            stdout=stdout_capture,
            stderr=stderr_capture,
            timeout=args.timeout_seconds,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        publish_captures(
            (
                (stdout_capture, stdout_path, error.stdout, MAX_STDOUT_BYTES),
                (stderr_capture, stderr_path, error.stderr, MAX_STDERR_BYTES),
            )
        )
        raise MatrixError(
            f"{lane} benchmark timed out after {args.timeout_seconds} seconds"
        ) from error
    except BaseException:
        stdout_capture.close()
        stderr_capture.close()
        Path(stdout_capture.name).unlink(missing_ok=True)
        Path(stderr_capture.name).unlink(missing_ok=True)
        raise
    process_wall_seconds = time.perf_counter() - started
    publish_captures(
        (
            (stdout_capture, stdout_path, completed.stdout, MAX_STDOUT_BYTES),
            (stderr_capture, stderr_path, completed.stderr, MAX_STDERR_BYTES),
        )
    )
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    if completed.returncode != 0:
        tail = stderr[-4000:].decode("utf-8", errors="replace")
        raise MatrixError(
            f"{lane} benchmark exited {completed.returncode}; stderr tail:\n{tail}"
        )
    resources = parse_process_resources(stderr, resource_measurement)
    return {
        "lane": lane,
        "command": command,
        "process_wall_seconds": process_wall_seconds,
        "resources": resources,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "report": decode_report(stdout, lane),
        "proof_artifact": load_proof_artifact(proof_artifact_path, lane),
    }
