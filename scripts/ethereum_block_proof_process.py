"""Bounded subprocess transport and typed one-shot parent production."""

from __future__ import annotations

import fcntl
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


PARENT_REQUEST_SCHEMA = "stwo.ethereum.block-proof-parent-process-request.v1"
PARENT_RESULT_SCHEMA = "stwo.ethereum.block-proof-parent-result.v1"
MAX_TRANSPORT_BYTES = 64 * 1024
POLL_SECONDS = 0.02


def identity_without_path(value: dict[str, Any]) -> dict[str, Any]:
    return {"bytes": value["bytes"], "sha256": value["sha256"]}


def write_exclusive(path: Path, payload: bytes) -> None:
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        store._fsync_directory(path.parent)
    except OSError as error:
        raise protocol.ProofProtocolError("cannot publish subprocess request") from error


def canonical_result(path: Path, where: str) -> dict[str, Any]:
    value = store.read_canonical_json(path, where)
    protocol.require(value.get("content_sha256") == protocol.content_sha256(value),
                     f"{where} digest differs")
    return value


def regular_size(path: Path, where: str) -> int:
    descriptor = store._open_regular(path, os.O_RDONLY, where)
    try:
        return os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)


def open_empty_output(path: Path, where: str) -> Any:
    """Create an output or reopen a durable pre-launch empty output."""
    if os.path.lexists(path):
        protocol.require(regular_size(path, where) == 0, f"{where} is not empty")
        descriptor = store._open_regular(path, os.O_WRONLY, where)
        return os.fdopen(descriptor, "wb", buffering=0)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags, 0o600)
        store._fsync_directory(path.parent)
        return os.fdopen(descriptor, "wb", buffering=0)
    except OSError as error:
        raise protocol.ProofProtocolError(
            "cannot create proof subprocess transport file"
        ) from error


def lock_is_held(path: Path, where: str) -> bool:
    descriptor = store._open_regular(path, os.O_RDWR, where)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def acquire_lock(path: Path, where: str) -> int:
    descriptor = store._open_regular(path, os.O_RDWR, where)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        os.close(descriptor)
        raise protocol.ProofProtocolError(
            "another proof subprocess still owns its spool"
        ) from error


def leaf_producer_observation(
    plan: dict[str, Any], start: dict[str, Any], progress: dict[str, Any],
    leaf: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": protocol.LEAF_PRODUCER_OBSERVATION_SCHEMA,
        "role": "leaf_stream_producer",
        "executable": plan["prover"],
        "argv": start["argv"],
        "stream_session_sha256": start["stream_session_sha256"],
        "segment_index": progress["segment_index"],
        "progress_record_sha256": progress["content_sha256"],
        "prove_timing": leaf["prove_timing"],
    }


def timing(value: Any, where: str) -> dict[str, int]:
    value = protocol.exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    protocol.require(all(type(item) is int and item >= 0 for item in value.values()),
                     f"{where} differs")
    return value


def run_process(
    argv: list[str], executable: dict[str, Any], role: str, timeout_seconds: int,
    *, cwd: Path,
) -> dict[str, Any]:
    started = time.monotonic_ns()
    stdout = tempfile.TemporaryFile(prefix="proof-stdout.", dir=cwd)
    stderr = tempfile.TemporaryFile(prefix="proof-stderr.", dir=cwd)
    try:
        child = subprocess.Popen(
            argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=True,
        )
    except OSError as error:
        stdout.close()
        stderr.close()
        raise protocol.ProofProtocolError(f"{role} subprocess failed to launch") from error
    deadline = time.monotonic() + timeout_seconds
    failure = None
    outcome = None
    while outcome is None:
        outcome = _wait4_nohang(child)
        if outcome is not None:
            break
        sizes = (os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size)
        if max(sizes) > MAX_TRANSPORT_BYTES:
            failure = f"{role} subprocess exceeded its transport bound"
            break
        if time.monotonic() >= deadline:
            failure = f"{role} subprocess timed out"
            break
        time.sleep(POLL_SECONDS)
    if failure is not None:
        try:
            _terminate_group(child)
        finally:
            stdout.close()
            stderr.close()
        raise protocol.ProofProtocolError(failure)
    protocol.require(outcome is not None, f"{role} subprocess wait differs")
    return_code, usage = outcome
    if _group_alive(child.pid):
        try:
            _terminate_group(child)
        finally:
            stdout.close()
            stderr.close()
        raise protocol.ProofProtocolError(f"{role} subprocess left a live descendant")
    ended = time.monotonic_ns()
    stdout_bytes = os.fstat(stdout.fileno()).st_size
    stderr_bytes = os.fstat(stderr.fileno()).st_size
    stdout.close()
    stderr.close()
    protocol.require(return_code == 0, f"{role} subprocess failed")
    protocol.require(max(stdout_bytes, stderr_bytes) <= MAX_TRANSPORT_BYTES,
                     f"{role} subprocess exceeded its transport bound")
    protocol.require(stdout_bytes == 0 and stderr_bytes == 0,
                     f"{role} subprocess emitted forbidden output")
    receipt = {
        "schema": protocol.PROCESS_RECEIPT_SCHEMA,
        "role": role,
        "executable": executable,
        "argv": argv,
        "exit_code": return_code,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "timing": {
            "wall_ns": ended - started,
            "user_ns": max(0, round(usage.ru_utime * 1e9)),
            "system_ns": max(0, round(usage.ru_stime * 1e9)),
        },
    }
    protocol.validate_process_receipt(receipt, executable, role)
    return receipt


def _wait4_nohang(
    child: subprocess.Popen[bytes],
) -> tuple[int, Any] | None:
    try:
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
    except ChildProcessError as error:
        raise protocol.ProofProtocolError("subprocess custody was lost") from error
    if pid == 0:
        return None
    protocol.require(pid == child.pid, "subprocess wait identity differs")
    return_code = os.waitstatus_to_exitcode(status)
    child.returncode = return_code
    return return_code, usage


def _group_alive(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return _ps_group_alive(group_id)


def drain_process_group(child: subprocess.Popen[bytes], where: str) -> bool:
    """Drain any surviving descendant and report whether the exit was already clean."""
    clean = not _group_alive(child.pid)
    if not clean:
        _terminate_group(child)
    protocol.require(not _group_alive(child.pid), f"{where} process group did not drain")
    return clean


def _ps_group_alive(group_id: int) -> bool:
    try:
        completed = subprocess.run(
            ["/bin/ps", "-axo", "pgid=,stat="], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise protocol.ProofProtocolError("cannot audit subprocess group") from error
    protocol.require(completed.returncode == 0
                     and len(completed.stdout) <= 1024 * 1024,
                     "cannot audit subprocess group")
    for line in completed.stdout.decode("ascii", errors="strict").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and int(fields[0]) == group_id:
            if not fields[1].startswith("Z"):
                return True
    return False


def _terminate_group(child: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(child.pid, 15)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    if _group_alive(child.pid):
        try:
            os.killpg(child.pid, 9)
        except ProcessLookupError:
            pass
        except PermissionError:
            protocol.require(not _ps_group_alive(child.pid),
                             "subprocess group could not be killed")
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise protocol.ProofProtocolError("subprocess group did not drain") from error
    deadline = time.monotonic() + 2
    while _group_alive(child.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    protocol.require(not _group_alive(child.pid), "subprocess group did not drain")


def _typed_child(
    semantic: dict[str, Any], runtime: dict[str, Any], position: int,
) -> dict[str, Any]:
    protocol.require(runtime["kind"] == semantic["kind"]
                     and runtime["record_sha256"] == semantic["record_sha256"],
                     f"parent child {position} runtime identity differs")
    if semantic["kind"] == "canonical_empty":
        path = Path(runtime["authority_path"])
        authority = store.read_canonical_json(path, f"parent child {position} authority")
        protocol.require(authority.get("authority_sha256")
                         == semantic["authority_sha256"],
                         f"parent child {position} empty authority differs")
        return {
            "kind": "canonical_empty",
            "record_sha256": semantic["record_sha256"],
            "statement_sha256": semantic["statement_sha256"],
            "authority": {"path": str(path),
                          **store.file_identity(path, "parent empty authority")},
            "proof": None,
            "verification_receipt": None,
        }
    proof_path = Path(runtime["proof_path"])
    receipt_path = Path(runtime["verification_receipt_path"])
    proof = store.file_identity(proof_path, f"parent child {position} proof")
    receipt = store.file_identity(receipt_path, f"parent child {position} receipt")
    protocol.require(proof["sha256"] == semantic["proof_sha256"]
                     and receipt["sha256"]
                     == semantic["verification_receipt_sha256"],
                     f"parent child {position} proof custody differs")
    return {
        "kind": semantic["kind"],
        "record_sha256": semantic["record_sha256"],
        "statement_sha256": semantic["statement_sha256"],
        "authority": None,
        "proof": {"path": str(proof_path), **proof},
        "verification_receipt": {"path": str(receipt_path), **receipt},
    }


def parent_request(request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    runtime = context["child_inputs"]
    protocol.require(len(request["children"]) == 2 and len(runtime) == 2,
                     "parent process requires exactly two ordered children")
    return protocol.seal({
        "schema": PARENT_REQUEST_SCHEMA,
        "task_request": request,
        "children": [
            _typed_child(semantic, child, position)
            for position, (semantic, child) in enumerate(
                zip(request["children"], runtime, strict=True)
            )
        ],
    })


def run_parent(
    plan: dict[str, Any], timeout_seconds: int, request: dict[str, Any],
    context: dict[str, Any], fresh_verify: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="ethereum-parent.", dir=context["scratch_root"],
    ) as raw:
        workspace = Path(raw)
        request_path = workspace / "request.json"
        proof_path = workspace / "proof.stw"
        result_path = workspace / "producer-result.json"
        process_request = parent_request(request, context)
        write_exclusive(request_path, protocol.canonical_bytes(process_request))
        argv = [
            str(context["prover_path"]), "ethereum-block-parent-producer",
            "--request", str(request_path), "--proof-out", str(proof_path),
            "--result", str(result_path),
        ]
        producer = run_process(
            argv, plan["prover"], "proof_producer", timeout_seconds, cwd=workspace,
        )
        output = _validate_parent_result(
            plan, result_path, proof_path, request, process_request,
        )
        proof_bytes = store.read_regular(
            proof_path, "parent proof", maximum=512 * 1024 * 1024,
        )
        verify = fresh_verify(
            request, context, proof_path, output["root_sha256"],
            process_request=process_request,
        )
        return {
            "schema": protocol.CHILD_RESULT_SCHEMA,
            "statement_sha256": output["statement_sha256"],
            "root_sha256": output["root_sha256"],
            "proof_bytes": proof_bytes,
            "verification_receipt": verify["verification_receipt"],
            "prove_timing": output["prove_timing"],
            "fresh_verify_timing": verify["process"]["timing"],
            "producer_process": producer,
            "verifier_process": verify["process"],
        }


def _validate_parent_result(
    plan: dict[str, Any], result_path: Path, proof_path: Path,
    request: dict[str, Any], process_request: dict[str, Any],
) -> dict[str, Any]:
    value = protocol.exact(canonical_result(result_path, "parent producer result"), {
        "schema", "status", "request_sha256", "producer_sha256",
        "statement_sha256", "root_sha256", "proof_bytes", "proof_sha256",
        "prove_timing", "content_sha256",
    }, "parent producer result")
    proof = store.file_identity(proof_path, "parent proof")
    protocol.require(value["schema"] == PARENT_RESULT_SCHEMA
                     and value["status"] == "proved"
                     and value["request_sha256"] == process_request["content_sha256"]
                     and value["producer_sha256"] == plan["prover"]["sha256"]
                     and value["statement_sha256"]
                     == request["expected_statement_sha256"]
                     and {"bytes": value["proof_bytes"],
                          "sha256": value["proof_sha256"]} == proof,
                     "parent producer result differs")
    protocol._sha(value["root_sha256"], "parent producer root")
    timing(value["prove_timing"], "parent producer timing")
    return value
