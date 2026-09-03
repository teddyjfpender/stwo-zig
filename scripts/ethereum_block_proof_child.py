"""Production subprocess adapter for streamed leaves and one-shot parents."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_process as process
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store
from scripts import ethereum_block_proof_stream_request as stream_request


LEAF_STREAM_REQUEST_SCHEMA = stream_request.REQUEST_SCHEMA
LEAF_RESULT_SCHEMA = "stwo.ethereum.block-proof-leaf-result.v1"
LEAF_PROGRESS_HEADER_SCHEMA = "stwo.ethereum.block-proof-leaf-progress-header.v1"
LEAF_PROGRESS_RECORD_SCHEMA = stream_request.PROGRESS_RECORD_SCHEMA
LEAF_SESSION_START_SCHEMA = "stwo.ethereum.block-proof-leaf-session-start.v1"
LEAF_SESSION_RECEIPT_SCHEMA = "stwo.ethereum.block-proof-leaf-session-receipt.v1"
LEAF_STREAM_RESULT_SCHEMA = "stwo.ethereum.block-proof-leaf-stream-result.v1"
VERIFIER_RESULT_SCHEMA = "stwo.ethereum.block-proof-verifier-result.v1"
MAX_TIMEOUT_SECONDS = 24 * 60 * 60


_identity_without_path = process.identity_without_path


_write_exclusive = process.write_exclusive
_result = process.canonical_result
_timing = process.timing
_run_process = process.run_process


class SubprocessChildAdapter:
    """One leaf stream per controller lifetime; one process per binary parent."""

    def __init__(
        self, plan: dict[str, Any], *, run_root: Path, timeout_seconds: int = 3600,
        replay_only: bool = False,
    ) -> None:
        self.plan = protocol.validate_plan(plan)
        protocol.require(type(timeout_seconds) is int
                         and 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS,
                         "subprocess timeout differs")
        self.timeout_seconds = timeout_seconds
        self.replay_only = replay_only
        self.run_root = run_root
        self.stream_root = run_root / "leaf-stream"
        self.proof_root = self.stream_root / "proofs"
        self.sessions_root = self.stream_root / "sessions"
        self.progress_path = self.proof_root / "progress.ndjson"
        self.lock_path = self.stream_root / "producer.lock"
        self._process: subprocess.Popen[bytes] | None = None
        self._process_started_ns: int | None = None
        self._session_start: dict[str, Any] | None = None
        self._session_directory: Path | None = None
        self._stdout: Any = None
        self._stderr: Any = None
        self._initialized = False
        self._foreign_session: dict[str, Any] | None = None
        self._incomplete_session_index: int | None = None
        self._last_context: dict[str, Any] | None = None

    def __enter__(self) -> SubprocessChildAdapter:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._process is not None:
            self._terminate_process("terminated_by_controller")

    def __call__(self, request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        protocol.require(not self.replay_only,
                         "proof replay encountered an uncommitted proof task")
        if request["task_kind"] == "real_leaf_proof":
            return self._leaf(request, context)
        protocol.require(request["task_kind"] == "recursive_parent_proof",
                         "subprocess adapter received a non-proof task")
        return self._parent(request, context)

    def _leaf(self, request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        index = request["node_index"]
        self._last_context = context
        self._ensure_spool(context)
        progress = self._progress_records()
        if index not in progress:
            if self._process is None:
                self._start_leaf_stream(index, context)
            progress = self._wait_for_progress(index)
        record = progress[index]
        result_path = self.stream_root / record["result"]["path"]
        leaf = self._validate_leaf_result(
            result_path, result_path.parent,
            self._session_request(record["stream_session_sha256"]), index,
        )
        proof_path = Path(leaf["proof_path"])
        proof_bytes = store.read_regular(
            proof_path, f"leaf {index} proof", maximum=512 * 1024 * 1024,
        )
        verify = self._fresh_verify(request, context, proof_path, leaf["root_sha256"])
        return {
            "schema": protocol.CHILD_RESULT_SCHEMA,
            "statement_sha256": leaf["statement_sha256"],
            "root_sha256": leaf["root_sha256"],
            "proof_bytes": proof_bytes,
            "verification_receipt": verify["verification_receipt"],
            "prove_timing": leaf["prove_timing"],
            "fresh_verify_timing": verify["process"]["timing"],
            "producer_process": process.leaf_producer_observation(
                self.plan, self._session_start_for(record["stream_session_sha256"]),
                record, leaf,
            ),
            "verifier_process": verify["process"],
        }

    def _start_leaf_stream(
        self, first_segment: int, context: dict[str, Any],
    ) -> None:
        protocol.require(not self.replay_only,
                         "proof replay cannot start a leaf producer")
        committed = context["committed_leaf_records"]
        protocol.require(len(committed) == first_segment,
                         "leaf stream committed prefix differs")
        session_index = self._next_session_index()
        workspace = self.sessions_root / f"session-{session_index:06d}"
        store.require_directory(workspace, "leaf stream session", create=True)
        store.require_allowed_entries(
            workspace, {"proofs", "stream-request.json", "stdout.bin", "stderr.bin"},
            "pre-launch leaf stream session",
        )
        session_proof_root = workspace / "proofs"
        store.require_directory(
            session_proof_root, "leaf stream session proof spool", create=True,
        )
        store.require_allowed_entries(
            session_proof_root, set(), "pre-launch leaf stream proof spool",
        )
        result_path = workspace / "stream-result.json"
        request_path = workspace / "stream-request.json"
        session_sha256 = protocol.sha256_bytes(protocol.canonical_bytes({
            "domain": LEAF_SESSION_START_SCHEMA,
            "plan_sha256": self.plan["content_sha256"],
            "session_index": session_index,
            "first_segment_index": first_segment,
        }))
        stream_request_value = stream_request.build(
            self.plan, context, committed, session_sha256, session_index,
            self.progress_path,
        )
        store.publish_new_or_identical(
            request_path, protocol.canonical_bytes(stream_request_value),
            staging_directory=Path(context["scratch_root"]),
        )
        argv = [
            str(context["prover_path"]), "ethereum-block-leaf-producer",
            "--request", str(request_path), "--proof-root", str(session_proof_root),
            "--result", str(result_path),
        ]
        start = protocol.seal({
            "schema": LEAF_SESSION_START_SCHEMA,
            "session_index": session_index,
            "plan_sha256": self.plan["content_sha256"],
            "request": {"path": request_path.name,
                        **store.file_identity(request_path, "leaf stream request")},
            "stream_session_sha256": session_sha256,
            "executable": self.plan["prover"],
            "argv": argv,
            "first_segment_index": first_segment,
            "started_unix_ns": time.time_ns(),
        })
        stdout_path = workspace / "stdout.bin"
        stderr_path = workspace / "stderr.bin"
        self._stdout = process.open_empty_output(stdout_path, "leaf stdout")
        self._stderr = process.open_empty_output(stderr_path, "leaf stderr")
        store.publish_new_or_identical(
            workspace / "session-start.json", protocol.canonical_bytes(start),
            staging_directory=Path(context["scratch_root"]),
        )
        self._incomplete_session_index = None
        lock_descriptor = self._acquire_lock()
        try:
            self._process_started_ns = time.monotonic_ns()
            self._process = subprocess.Popen(
                argv, cwd=workspace, stdin=subprocess.DEVNULL,
                stdout=self._stdout, stderr=self._stderr, start_new_session=True,
                pass_fds=(lock_descriptor,),
            )
        except OSError as error:
            os.close(lock_descriptor)
            self._close_transport_files()
            raise protocol.ProofProtocolError(
                "leaf stream producer failed to launch"
            ) from error
        os.close(lock_descriptor)
        self._session_start = start
        self._session_directory = workspace

    def _ensure_spool(self, context: dict[str, Any]) -> None:
        if self._initialized:
            return
        store.require_directory(self.stream_root, "leaf stream root", create=True)
        store.require_allowed_entries(
            self.stream_root, {"proofs", "producer.lock", "sessions"},
            "leaf stream root",
        )
        store.require_directory(self.proof_root, "leaf stream proof spool", create=True)
        store.require_directory(self.sessions_root, "leaf stream sessions", create=True)
        if not os.path.lexists(self.lock_path):
            descriptor = os.open(
                self.lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
            store._fsync_directory(self.stream_root)
        else:
            descriptor = store._open_regular(
                self.lock_path, os.O_RDONLY, "leaf stream producer lock",
            )
            os.close(descriptor)
        header = protocol.seal({
            "schema": LEAF_PROGRESS_HEADER_SCHEMA,
            "plan_sha256": self.plan["content_sha256"],
            "source_request_sha256": self.plan["leaf_stream_request"]["sha256"],
            "real_segment_count": self.plan["real_segment_count"],
        })
        if not os.path.lexists(self.progress_path):
            store.publish_new_or_identical(
                self.progress_path, protocol.canonical_bytes(header),
                staging_directory=Path(context["scratch_root"]),
            )
        records = store._read_journal(self.progress_path)
        protocol.require(records and records[0] == header,
                         "leaf stream progress header differs")
        self._recover_sessions(Path(context["scratch_root"]))
        self._progress_records()
        self._initialized = True

    def _recover_sessions(self, staging: Path) -> None:
        directories = sorted(self.sessions_root.iterdir(), key=lambda path: path.name)
        for index, directory in enumerate(directories):
            protocol.require(directory.name == f"session-{index:06d}",
                             "leaf stream session order differs")
            store.require_directory(directory, f"leaf stream session {index}")
            start_path = directory / "session-start.json"
            if not os.path.lexists(start_path):
                protocol.require(not self.replay_only and index == len(directories) - 1
                                 and not self._lock_is_held(),
                                 "unterminated pre-launch leaf session differs")
                store.require_allowed_entries(
                    directory,
                    {"proofs", "stream-request.json", "stdout.bin", "stderr.bin"},
                    "pre-launch leaf stream session",
                )
                proof_root = directory / "proofs"
                if os.path.lexists(proof_root):
                    store.require_directory(proof_root, "pre-launch leaf proof spool")
                    store.require_allowed_entries(
                        proof_root, set(), "pre-launch leaf proof spool",
                    )
                for name in ("stdout.bin", "stderr.bin"):
                    path = directory / name
                    if os.path.lexists(path):
                        protocol.require(process.regular_size(path, name) == 0,
                                         "pre-launch transport is not empty")
                self._incomplete_session_index = index
                continue
            start = self._validate_session_start(start_path, index)
            receipt_path = directory / "session-receipt.json"
            if os.path.lexists(receipt_path):
                self._validate_session_receipt(receipt_path, start)
                continue
            protocol.require(not self.replay_only,
                             "proof replay found an unterminated leaf session")
            if self._lock_is_held():
                protocol.require(index == len(directories) - 1,
                                 "nonterminal leaf stream session remains active")
                self._foreign_session = start
                continue
            receipt = self._session_receipt(
                start, "indeterminate_after_controller_loss", None, None,
            )
            store.publish_new_or_identical(
                receipt_path, protocol.canonical_bytes(receipt),
                staging_directory=staging,
            )

    def _next_session_index(self) -> int:
        return (self._incomplete_session_index if self._incomplete_session_index is not None
                else len(list(self.sessions_root.iterdir())))

    def _lock_is_held(self) -> bool:
        return process.lock_is_held(self.lock_path, "leaf stream producer lock")

    def _acquire_lock(self) -> int:
        return process.acquire_lock(self.lock_path, "leaf stream producer lock")

    def _progress_records(self) -> dict[int, dict[str, Any]]:
        raw = store._read_journal(self.progress_path)
        protocol.require(raw and raw[0]["schema"] == LEAF_PROGRESS_HEADER_SCHEMA,
                         "leaf stream progress header differs")
        result: dict[int, dict[str, Any]] = {}
        for expected_index, record in enumerate(raw[1:]):
            record = protocol.exact(record, {
                "schema", "segment_index", "stream_session_sha256",
                "request_sha256", "proof", "result", "content_sha256",
            }, f"leaf stream progress record {expected_index}")
            protocol.require(record["schema"] == LEAF_PROGRESS_RECORD_SCHEMA
                             and record["segment_index"] == expected_index,
                             "leaf stream progress order differs")
            protocol._sha(record["stream_session_sha256"],
                          "leaf stream progress session")
            protocol._sha(record["request_sha256"], "leaf stream progress request")
            proof = protocol._identity(
                record["proof"], "leaf stream progress proof", path=True,
            )
            leaf_result = protocol._identity(
                record["result"], "leaf stream progress result", path=True,
            )
            start = self._session_start_for(record["stream_session_sha256"])
            session_prefix = f"sessions/session-{start['session_index']:06d}/proofs"
            protocol.require(
                proof["path"] == f"{session_prefix}/segment-{expected_index:06d}.stw"
                and leaf_result["path"]
                == f"{session_prefix}/segment-{expected_index:06d}.result.json",
                "leaf stream progress paths differ",
            )
            store.validate_file_identity(
                self.stream_root / proof["path"], _identity_without_path(proof),
                f"spooled leaf {expected_index} proof",
            )
            store.validate_file_identity(
                self.stream_root / leaf_result["path"],
                _identity_without_path(leaf_result),
                f"spooled leaf {expected_index} result",
            )
            session_request = self._session_request(record["stream_session_sha256"])
            protocol.require(record["request_sha256"]
                             == session_request["content_sha256"],
                             "leaf stream progress request differs")
            result[expected_index] = record
        protocol.require(len(result) <= self.plan["real_segment_count"],
                         "leaf stream progress exceeds the plan")
        return result

    def _wait_for_progress(self, index: int) -> dict[int, dict[str, Any]]:
        deadline = time.monotonic() + self.timeout_seconds
        last_error: protocol.ProofProtocolError | None = None
        while time.monotonic() < deadline:
            try:
                records = self._progress_records()
                last_error = None
            except protocol.ProofProtocolError as error:
                last_error = error
                records = {}
            if index in records:
                return records
            if self._process is not None and self._process.poll() is not None:
                self._finish_current_process(require_complete=False)
                records = self._progress_records()
                if index in records:
                    return records
                raise protocol.ProofProtocolError(
                    "leaf stream producer exited before publishing the requested leaf"
                )
            if self._process is None and self._foreign_session is not None:
                if not self._lock_is_held():
                    self._seal_foreign_session()
                    self._start_leaf_stream(index, self._last_context)
            time.sleep(0.02)
        if last_error is not None:
            raise last_error
        if self._process is not None:
            self._terminate_process("timed_out")
        raise protocol.ProofProtocolError("leaf stream publication timed out")

    def _validate_session_start(self, path: Path, index: int) -> dict[str, Any]:
        value = protocol.exact(_result(path, f"leaf stream session {index} start"), {
            "schema", "session_index", "plan_sha256", "request",
            "stream_session_sha256", "executable", "argv",
            "first_segment_index", "started_unix_ns", "content_sha256",
        }, f"leaf stream session {index} start")
        protocol.require(value["schema"] == LEAF_SESSION_START_SCHEMA
                         and value["session_index"] == index
                         and value["plan_sha256"] == self.plan["content_sha256"]
                         and value["executable"] == self.plan["prover"],
                         "leaf stream session start differs")
        protocol._identity(value["request"], "leaf stream session request", path=True)
        protocol._sha(value["stream_session_sha256"], "leaf stream session identity")
        protocol.require(type(value["argv"]) is list and len(value["argv"]) >= 2
                         and type(value["first_segment_index"]) is int
                         and 0 <= value["first_segment_index"]
                         < self.plan["real_segment_count"]
                         and type(value["started_unix_ns"]) is int
                         and value["started_unix_ns"] > 0,
                         "leaf stream session start fields differ")
        store.validate_file_identity(
            path.parent / value["request"]["path"],
            _identity_without_path(value["request"]),
            "leaf stream session request",
        )
        return value

    def _session_start_for(self, stream_session_sha256: str) -> dict[str, Any]:
        for index, directory in enumerate(sorted(
            self.sessions_root.iterdir(), key=lambda path: path.name,
        )):
            start = self._validate_session_start(
                directory / "session-start.json", index,
            )
            if start["stream_session_sha256"] == stream_session_sha256:
                return start
        raise protocol.ProofProtocolError("leaf stream progress names an unknown session")

    def _session_request(self, stream_session_sha256: str) -> dict[str, Any]:
        start = self._session_start_for(stream_session_sha256)
        directory = self.sessions_root / f"session-{start['session_index']:06d}"
        value = _result(
            directory / start["request"]["path"], "leaf stream session request",
        )
        protocol.exact(value, {
            "schema", "plan_sha256", "session_id", "stream_session_sha256",
            "source_request", "producer_sha256", "verifier_sha256",
            "real_segment_count", "first_uncommitted_segment", "durable_progress",
            "segments", "content_sha256",
        }, "leaf stream session request")
        protocol.require(value["schema"] == LEAF_STREAM_REQUEST_SCHEMA
                         and value["stream_session_sha256"]
                         == stream_session_sha256
                         and value["producer_sha256"] == self.plan["prover"]["sha256"]
                         and value["verifier_sha256"]
                         == self.plan["verifier"]["sha256"],
                         "leaf stream session request differs")
        return value

    def _close_transport_files(self) -> None:
        for name in ("_stdout", "_stderr"):
            output = getattr(self, name)
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
                output.close()
                setattr(self, name, None)

    def _session_receipt(
        self, start: dict[str, Any], classification: str,
        exit_code: int | None, timing: dict[str, Any] | None,
    ) -> dict[str, Any]:
        directory = self.sessions_root / f"session-{start['session_index']:06d}"
        stdout_bytes = process.regular_size(directory / "stdout.bin", "leaf stdout")
        stderr_bytes = process.regular_size(directory / "stderr.bin", "leaf stderr")
        result_path = directory / "stream-result.json"
        stream_result = None
        if os.path.lexists(result_path):
            stream_result = {"path": result_path.name,
                             **store.file_identity(result_path, "leaf stream result")}
        published = [
            index for index, record in self._progress_records().items()
            if record["stream_session_sha256"] == start["stream_session_sha256"]
        ]
        return protocol.seal({
            "schema": LEAF_SESSION_RECEIPT_SCHEMA,
            "classification": classification,
            "session_index": start["session_index"],
            "stream_session_sha256": start["stream_session_sha256"],
            "executable": start["executable"],
            "argv": start["argv"],
            "request": start["request"],
            "first_segment_index": start["first_segment_index"],
            "published_segment_indices": published,
            "exit_code": exit_code,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "timing": timing,
            "stream_result": stream_result,
        })

    def _validate_stream_result(
        self, path: Path, start: dict[str, Any],
    ) -> dict[str, Any]:
        value = protocol.exact(_result(path, "leaf stream terminal result"), {
            "schema", "status", "request_sha256", "producer_sha256",
            "stream_session_sha256", "first_segment_index", "publications",
            "content_sha256",
        }, "leaf stream terminal result")
        request = self._session_request(start["stream_session_sha256"])
        records = [
            record for record in self._progress_records().values()
            if record["stream_session_sha256"] == start["stream_session_sha256"]
        ]
        publications = [{
            "segment_index": record["segment_index"],
            "progress_record_sha256": record["content_sha256"],
            "proof": record["proof"],
            "result": record["result"],
        } for record in records]
        protocol.require(value["schema"] == LEAF_STREAM_RESULT_SCHEMA
                         and value["status"] == "complete"
                         and value["request_sha256"] == request["content_sha256"]
                         and value["producer_sha256"] == self.plan["prover"]["sha256"]
                         and value["stream_session_sha256"]
                         == start["stream_session_sha256"]
                         and value["first_segment_index"]
                         == start["first_segment_index"]
                         and value["publications"] == publications,
                         "leaf stream terminal result differs")
        return value

    def _validate_session_receipt(
        self, path: Path, start: dict[str, Any],
    ) -> dict[str, Any]:
        value = protocol.exact(_result(path, "leaf stream session receipt"), {
            "schema", "classification", "session_index", "stream_session_sha256",
            "executable", "argv", "request", "first_segment_index",
            "published_segment_indices", "exit_code", "stdout_bytes",
            "stderr_bytes", "timing", "stream_result", "content_sha256",
        }, "leaf stream session receipt")
        protocol.require(value["schema"] == LEAF_SESSION_RECEIPT_SCHEMA
                         and value["session_index"] == start["session_index"]
                         and value["stream_session_sha256"]
                         == start["stream_session_sha256"]
                         and value["executable"] == start["executable"]
                         and value["argv"] == start["argv"]
                         and value["request"] == start["request"]
                         and value["first_segment_index"]
                         == start["first_segment_index"],
                         "leaf stream session receipt authority differs")
        classification = value["classification"]
        protocol.require(classification in {
            "complete", "failed", "indeterminate_after_controller_loss",
            "terminated_by_controller", "timed_out",
        }, "leaf stream session classification differs")
        protocol.require(type(value["published_segment_indices"]) is list
                         and value["published_segment_indices"]
                         == sorted(set(value["published_segment_indices"])),
                         "leaf stream session publication indices differ")
        if classification == "complete":
            protocol.require(value["exit_code"] == 0
                             and value["stdout_bytes"] == 0
                             and value["stderr_bytes"] == 0
                             and type(value["timing"]) is dict
                             and value["stream_result"] is not None,
                             "complete leaf stream session differs")
        elif classification == "indeterminate_after_controller_loss":
            protocol.require(value["exit_code"] is None and value["timing"] is None,
                             "indeterminate leaf stream session differs")
        else:
            protocol.require(type(value["exit_code"]) is int
                             and type(value["timing"]) is dict,
                             "terminal leaf stream session differs")
        if value["timing"] is not None:
            timing = protocol.exact(
                value["timing"], {"wall_ns", "user_ns", "system_ns"},
                "leaf stream session timing",
            )
            protocol.require(type(timing["wall_ns"]) is int and timing["wall_ns"] >= 0
                             and timing["user_ns"] is None
                             and timing["system_ns"] is None,
                             "leaf stream session timing differs")
        if value["stream_result"] is not None:
            identity = protocol._identity(
                value["stream_result"], "leaf stream terminal result", path=True,
            )
            protocol.require(identity["path"] == "stream-result.json",
                             "leaf stream terminal result path differs")
            store.validate_file_identity(
                path.parent / identity["path"], _identity_without_path(identity),
                "leaf stream terminal result",
            )
            if classification == "complete":
                self._validate_stream_result(path.parent / identity["path"], start)
        return value

    def _finish_current_process(self, *, require_complete: bool) -> dict[str, Any]:
        protocol.require(self._process is not None and self._session_start is not None
                         and self._session_directory is not None
                         and self._process_started_ns is not None,
                         "leaf stream process state differs")
        try:
            exit_code = self._process.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            self._terminate_process("timed_out")
            raise protocol.ProofProtocolError("leaf stream producer timed out")
        descendant_clean = self._drain_process_group()
        wall_ns = time.monotonic_ns() - self._process_started_ns
        self._close_transport_files()
        progress = self._progress_records()
        transport_clean = (
            process.regular_size(self._session_directory / "stdout.bin", "leaf stdout") == 0
            and process.regular_size(
                self._session_directory / "stderr.bin", "leaf stderr",
            ) == 0
        )
        complete = (
            exit_code == 0 and transport_clean and descendant_clean
            and len(progress) == self.plan["real_segment_count"]
        )
        result_path = self._session_directory / "stream-result.json"
        if complete:
            try:
                self._validate_stream_result(result_path, self._session_start)
            except protocol.ProofProtocolError:
                complete = False
        classification = "complete" if complete else "failed"
        receipt = self._session_receipt(
            self._session_start, classification, exit_code,
            {"wall_ns": wall_ns, "user_ns": None, "system_ns": None},
        )
        receipt_path = self._session_directory / "session-receipt.json"
        store.publish_new_or_identical(
            receipt_path, protocol.canonical_bytes(receipt),
            staging_directory=self.run_root / ".staging",
        )
        self._validate_session_receipt(receipt_path, self._session_start)
        self._process = None
        self._process_started_ns = None
        self._session_start = None
        self._session_directory = None
        if require_complete:
            protocol.require(complete, "leaf stream producer did not complete cleanly")
        return receipt

    def _terminate_process(self, classification: str) -> None:
        if self._process is None:
            return
        try:
            os.killpg(self._process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            exit_code = self._process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self._process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            exit_code = self._process.wait(timeout=2)
        self._drain_process_group()
        wall_ns = time.monotonic_ns() - (self._process_started_ns or time.monotonic_ns())
        self._close_transport_files()
        start = self._session_start
        directory = self._session_directory
        protocol.require(start is not None and directory is not None,
                         "leaf stream termination state differs")
        receipt = self._session_receipt(
            start, classification, exit_code,
            {"wall_ns": wall_ns, "user_ns": None, "system_ns": None},
        )
        store.publish_new_or_identical(
            directory / "session-receipt.json", protocol.canonical_bytes(receipt),
            staging_directory=self.run_root / ".staging",
        )
        self._process = None
        self._process_started_ns = None
        self._session_start = None
        self._session_directory = None

    def _drain_process_group(self) -> bool:
        protocol.require(self._process is not None,
                         "leaf stream process is absent during drain")
        clean = process.drain_process_group(self._process, "leaf stream producer")
        if not self._lock_is_held():
            return clean
        clean = False
        try:
            os.killpg(self._process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while self._lock_is_held() and time.monotonic() < deadline:
            time.sleep(0.01)
        if self._lock_is_held():
            try:
                os.killpg(self._process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while self._lock_is_held() and time.monotonic() < deadline:
                time.sleep(0.01)
        protocol.require(not self._lock_is_held(),
                         "leaf stream process group did not release the spool")
        return clean

    def _seal_foreign_session(self) -> None:
        protocol.require(self._foreign_session is not None,
                         "leaf stream has no recovered session")
        start = self._foreign_session
        receipt = self._session_receipt(
            start, "indeterminate_after_controller_loss", None, None,
        )
        directory = self.sessions_root / f"session-{start['session_index']:06d}"
        store.publish_new_or_identical(
            directory / "session-receipt.json", protocol.canonical_bytes(receipt),
            staging_directory=self.run_root / ".staging",
        )
        self._foreign_session = None

    def finish_leaf_stream(self, context: dict[str, Any]) -> None:
        if not self._initialized:
            self._last_context = context
            self._ensure_spool(context)
        if self._foreign_session is not None:
            deadline = time.monotonic() + self.timeout_seconds
            while self._lock_is_held() and time.monotonic() < deadline:
                time.sleep(0.02)
            protocol.require(not self._lock_is_held(),
                             "recovered leaf stream did not release its spool")
            self._seal_foreign_session()
        if self._process is not None:
            self._finish_current_process(require_complete=True)
        protocol.require(
            list(self._progress_records())
            == list(range(self.plan["real_segment_count"])),
            "leaf stream progress is incomplete",
        )

    def session_publications(self) -> list[dict[str, Any]]:
        result = []
        for index, directory in enumerate(sorted(
            self.sessions_root.iterdir(), key=lambda path: path.name,
        )):
            start = self._validate_session_start(directory / "session-start.json", index)
            receipt_path = directory / "session-receipt.json"
            receipt = self._validate_session_receipt(receipt_path, start)
            result.append({
                "receipt": receipt,
                "file": {
                    "path": str(receipt_path.relative_to(self.run_root)),
                    **store.file_identity(receipt_path, "leaf stream session receipt"),
                },
            })
        return result

    def _validate_leaf_result(
        self, path: Path, proof_root: Path, request: dict[str, Any], index: int,
    ) -> dict[str, Any]:
        value = protocol.exact(_result(path, f"leaf {index} result"), {
            "schema", "status", "request_sha256", "segment_index",
            "expected_authority_sha256", "statement_sha256", "root_sha256",
            "proof", "prove_timing", "content_sha256",
        }, f"leaf {index} result")
        segment = request["segments"][index]
        protocol.require(value["schema"] == LEAF_RESULT_SCHEMA
                         and value["status"] == "proved"
                         and value["request_sha256"] == request["content_sha256"]
                         and value["segment_index"] == index
                         and value["expected_authority_sha256"]
                         == segment["expected_authority"]["sha256"]
                         and value["statement_sha256"]
                         == segment["expected_statement_sha256"],
                         f"leaf {index} result authority differs")
        protocol._sha(value["root_sha256"], f"leaf {index} root")
        proof = protocol._identity(value["proof"], f"leaf {index} proof", path=True)
        proof_name = f"segment-{index:06d}.stw"
        protocol.require(proof["path"] == proof_name, f"leaf {index} proof path differs")
        store.validate_file_identity(
            proof_root / proof_name, _identity_without_path(proof), f"leaf {index} proof",
        )
        _timing(value["prove_timing"], f"leaf {index} prove timing")
        return {**value, "proof_path": str(proof_root / proof_name)}

    def _parent(self, request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return process.run_parent(
            self.plan, self.timeout_seconds, request, context, self._fresh_verify,
        )

    def _fresh_verify(
        self, request: dict[str, Any], context: dict[str, Any], proof_path: Path,
        root_sha256: str, *, process_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        scratch = Path(context["scratch_root"])
        with tempfile.TemporaryDirectory(prefix="ethereum-verify.", dir=scratch) as raw:
            workspace = Path(raw)
            request_path = workspace / "request.json"
            result_path = workspace / "verifier-result.json"
            process_request = process_request or request
            _write_exclusive(request_path, protocol.canonical_bytes(process_request))
            command = ("ethereum-leaf-verifier"
                       if request["task_kind"] == "real_leaf_proof"
                       else "ethereum-parent-verifier")
            argv = [
                str(context["verifier_path"]), command, "--request", str(request_path),
                "--proof", str(proof_path), "--result", str(result_path),
            ]
            process = _run_process(
                argv, self.plan["verifier"], "fresh_verifier", self.timeout_seconds,
                cwd=workspace,
            )
            value = protocol.exact(_result(result_path, "fresh verifier result"), {
                "schema", "status", "request_sha256", "verifier_sha256",
                "statement_sha256", "root_sha256", "proof_bytes", "proof_sha256",
                "verification_receipt", "content_sha256",
            }, "fresh verifier result")
            proof = store.file_identity(proof_path, "freshly verified proof")
            expected_receipt = protocol.expected_receipt(
                request, proof, root_sha256, self.plan["verifier"],
                self.plan["security_parameters"],
            )
            protocol.require(value["schema"] == VERIFIER_RESULT_SCHEMA
                             and value["status"] == "verified"
                             and value["request_sha256"]
                             == process_request["content_sha256"]
                             and value["verifier_sha256"]
                             == self.plan["verifier"]["sha256"]
                             and value["statement_sha256"]
                             == request["expected_statement_sha256"]
                             and value["root_sha256"] == root_sha256
                             and {"bytes": value["proof_bytes"],
                                  "sha256": value["proof_sha256"]} == proof
                             and value["verification_receipt"] == expected_receipt,
                             "fresh verifier result differs")
            return {"verification_receipt": expected_receipt, "process": process}
