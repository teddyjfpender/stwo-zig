"""Exact Zig0.15.2 case execution; private dev_test owner, never a proof attestation."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import threading
import time

from scripts.repo.ci_scope_plan import PlanError, strict_json, write_json
from scripts.repo.ci_scope_run import run_measured

VERSION = "0.15.2"
RSS_CAP, CPU_SECONDS, WALL_SECONDS = 1 << 30, 110, 120
MAX_FRAME = 16 << 20
LIMITS = {"sampled_child_tree_rss_bytes": RSS_CAP, "cpu_seconds": CPU_SECONDS,
          "wall_seconds": WALL_SECONDS, "sampling_seconds": 0.1}


def admit_cpu_seconds(value):
    """Explicit per-process CPU (including threads); never an aggregate-tree claim."""
    require(type(value) is int and 1 <= value <= 1920, "CPU seconds must be an integer1..1920")
    hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
    require(hard == resource.RLIM_INFINITY or value <= hard, "CPU seconds exceed inherited hard RLIMIT_CPU")
    return value


def require(condition, message):
    if not condition:
        raise PlanError("test cases: " + message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), "missing/indirect evidence: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def frame(reader, captured=None):
    def take(size, eof=False):
        data = b""
        while len(data) < size:
            block = reader.read(size - len(data))
            if not block:
                require(eof and not data, "truncated protocol frame")
                return None
            if captured is not None:
                captured.write(block)
            data += block
        return data
    header = take(8, True)
    if header is None:
        return None
    tag, size = struct.unpack("<II", header)
    require(size <= MAX_FRAME, "oversized protocol frame")
    return tag, take(size) if size else b""


def inventory(body):
    require(len(body) >= 8, "short metadata")
    size, count = struct.unpack("<II", body[:8])
    require(0 < count <= 65536 and len(body) == 8 + 8 * count + size, "metadata bounds")
    offsets = struct.unpack(f"<{count}I", body[8:8 + 4 * count])
    require(not any(body[8 + 4 * count:8 + 8 * count]), "unsupported expected-panic metadata")
    strings, cursor, names = body[8 + 8 * count:], 1, []
    require(strings.startswith(b"\0"), "metadata null sentinel")
    for offset in offsets:
        require(offset == cursor, "noncanonical name offset")
        end = strings.find(b"\0", cursor)
        require(cursor < end <= cursor + 8192, "metadata name bounds")
        try:
            names.append(strings[cursor:end].decode("utf-8", "strict"))
        except UnicodeDecodeError as error:
            raise PlanError("test cases: non-UTF8 name") from error
        cursor = end + 1
    require(cursor == len(strings) and len(set(names)) == count, "trailing/duplicate metadata names")
    return names


def status(flags):
    return "FAIL" if flags & 5 or flags >> 4 else "SKIP" if flags & 2 else "PASS"


def validate_protocol(path, metadata, index):
    require(path.is_file() and not path.is_symlink(), "invalid saved protocol")
    require(path.stat().st_size <= 3 * MAX_FRAME + 24, "oversized saved protocol")
    with path.open("rb") as source:
        require(frame(source) == (0, VERSION.encode()), "version/frame order changed")
        require(frame(source) == (3, metadata), "inventory/frame order changed")
        result = frame(source)
        require(result is not None and result[0] == 4 and len(result[1]) == 8, "missing result")
        observed, flags = struct.unpack("<II", result[1])
        require(observed == index and frame(source) is None, "reordered/duplicate/unknown result")
    return flags


class Session:
    """One guarded original process; transcript exchange borrows its live pipes."""
    def __init__(self, binary, seed, output, index, metadata, *, cpu_seconds=CPU_SECONDS):
        self.argv = [str(binary), f"--seed={seed:#x}", "--listen=-"]
        self.base, self.index, self.metadata = output, index, metadata
        self.cpu_seconds = cpu_seconds
        self.stop, self.peak, self.reason = threading.Event(), 0, None
        self.thread = None
        self.termination = None

    def watch(self, child):
        deadline = time.monotonic() + WALL_SECONDS
        while not self.stop.is_set():
            try:
                rows = subprocess.run(["ps", "-axo", "pid=,ppid=,rss="], capture_output=True,
                                      text=True, check=True, timeout=2).stdout.splitlines()
                entries = [tuple(map(int, row.split())) for row in rows]
                owned = {child.pid}
                while True:
                    expanded = owned | {pid for pid, parent, _ in entries if parent in owned}
                    if expanded == owned:
                        break
                    owned = expanded
                self.peak = max(self.peak, sum(rss * 1024 for pid, _, rss in entries if pid in owned))
                if self.peak > RSS_CAP or time.monotonic() >= deadline:
                    self.reason = "RSS_CAP" if self.peak > RSS_CAP else "WALL_CAP"
            except Exception as error:
                self.reason = "GUARD_ERROR: " + str(error)
            if self.reason:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    try:
                        os.kill(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                return
            self.stop.wait(0.1)

    def exchange(self, child):
        self.thread = threading.Thread(target=self.watch, args=(child,), daemon=True)
        self.thread.start()
        def send(tag, payload=b""):
            child.stdin.write(struct.pack("<II", tag, len(payload)) + payload)
            child.stdin.flush()
        with self.base.with_suffix(".stdout.bin").open("wb") as captured:
            try:
                require(frame(child.stdout, captured) == (0, VERSION.encode()), "wrong executable Zig version")
                send(4)  # std.zig.Client.Message.Tag.query_test_metadata
                message = frame(child.stdout, captured)
                require(message is not None and message[0] == 3, "expected complete metadata")
                inventory(message[1])
                require(self.metadata is None or message[1] == self.metadata, "changed inventory")
                self.metadata = message[1]
                if self.index is not None:
                    send(5, struct.pack("<I", self.index))
                    message = frame(child.stdout, captured)
                    require(message is not None and message[0] == 4 and len(message[1]) == 8, "expected one result")
                    observed, self.flags = struct.unpack("<II", message[1])
                    require(observed == self.index, "forged/reordered result index")
                send(0)  # exit: require clean termination and no additional frames
                child.stdin.close()
                require(frame(child.stdout, captured) is None, "duplicate/unknown trailing frame")
            finally:
                captured.flush()
                os.fsync(captured.fileno())

    def reaped(self, completed, resources, cleanup):
        self.termination = {"returncode": completed.returncode,
                            "signal": -completed.returncode if completed.returncode < 0 else None,
                            "resources": resources, "cleanup": cleanup}

    def run(self, cwd):
        admit_cpu_seconds(self.cpu_seconds)  # Recheck direct callers before files or spawn.
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
        with self.base.with_suffix(".stderr").open("wb") as stderr:
            try:
                completed, usage = run_measured(self.argv, cwd=cwd, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=stderr, start_new_session=True,
                    preexec_fn=limits, on_start=self.exchange, on_reap=self.reaped)
                require(completed.returncode == 0 and self.reason is None, "unclean process/guard termination")
                return usage
            finally:
                self.stop.set()
                if self.thread is not None:
                    self.thread.join(3)
                stderr.flush()
                os.fsync(stderr.fileno())


def interrupted(session, error, started):
    """Publish available failure evidence without replacing the original cause."""
    evidence, evidence_errors = {}, {}
    for extension in (".stdout.bin", ".stderr"):
        try:
            evidence[extension] = sha(session.base.with_suffix(extension))
        except Exception as hash_error:
            evidence[extension] = None
            evidence_errors[extension] = repr(hash_error)
    try:
        write_json(session.base.with_suffix(".interrupted.json"),
                   {"status": "INCOMPLETE", "guard_reason": session.reason, "error": repr(error),
                    "termination": session.termination, "duration_ns": time.monotonic_ns() - started,
                    "sampled_aggregate_peak_rss_bytes": session.peak,
                    "evidence": evidence, "evidence_errors": evidence_errors})
    except Exception as receipt_error:
        error.add_note("interrupted receipt: " + repr(receipt_error))


def execute(binary, expected_sha, seed, output, cwd, resume_digest=None, max_cases=1, *, cpu_seconds=CPU_SECONDS):
    admit_cpu_seconds(cpu_seconds)
    require(0 <= seed <= 0xffffffff, "seed must fit u32")
    require(1 <= max_cases <= 65536, "partition count must be positive and bounded")
    require(strict_json(cwd / "toolchain.json")["zig"]["version"] == VERSION, "unsupported pinned Zig")
    binary = (cwd / binary).resolve(strict=True)
    output = (cwd / output).resolve()
    require(sha(binary) == expected_sha, "executable SHA256 mismatch")
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            return execute_locked(binary, expected_sha, seed, output, cwd, resume_digest, max_cases, cpu_seconds)
        except PlanError:
            raise
        except (KeyError, TypeError, ValueError, struct.error) as error:
            raise PlanError("test cases: malformed receipt/protocol") from error


def execute_locked(binary, expected_sha, seed, output, cwd, resume_digest, max_cases, cpu_seconds):
    receipt = output / "receipt.json"
    identity = {"binary": str(binary), "binary_sha256": expected_sha, "zig": VERSION,
                "seed": seed, "cwd": str(cwd), "limits": {**LIMITS, "cpu_seconds": cpu_seconds},
                "environment_sha256": hashlib.sha256(json.dumps(sorted(os.environ.items())).encode()).hexdigest()}
    if receipt.exists():
        require(resume_digest is not None and sha(receipt) == resume_digest, "resume requires admitted receipt digest")
        aggregate = strict_json(receipt)
        require(aggregate["identity"] == identity, "resume identity changed")
    else:
        require(resume_digest is None and set(p.name for p in output.iterdir()) == {".lock"}, "nonempty output")
        aggregate = {"schema": "zig-exact-cases-v1", "identity": identity, "status": "INCOMPLETE", "results": []}
        write_json(receipt, aggregate)
    probe = Session(binary, seed, output / f"query-{time.time_ns()}", None, None, cpu_seconds=cpu_seconds)
    started = time.monotonic_ns()
    try:
        probe.run(cwd)
    except BaseException as error:
        interrupted(probe, error, started)
        raise
    require(sha(binary) == expected_sha, "executable changed during discovery")
    names, metadata = inventory(probe.metadata), probe.metadata
    meta_sha = hashlib.sha256(metadata).hexdigest()
    if "metadata_sha256" in aggregate:
        require(aggregate["metadata_sha256"] == meta_sha and aggregate["names"] == names, "resume inventory changed")
    else:
        require(not aggregate["results"], "missing prefix inventory")
        aggregate.update(metadata_sha256=meta_sha, names=names)
    require(len(aggregate["results"]) <= len(names), "oversized prefix")
    for index, record in enumerate(aggregate["results"]):
        base = output / f"{index:06d}"
        require(strict_json(base.with_suffix(".completed.json")) == record, "forged completed record")
        require(record["index"] == index and record["name"] == names[index], "reordered completed prefix")
        flags = validate_protocol(base.with_suffix(".stdout.bin"), metadata, index)
        require(record["flags"] == flags and record["status"] == status(flags), "forged result flags/status")
        for extension in (".stdout.bin", ".stderr"):
            require(record[extension] == sha(base.with_suffix(extension)), "saved evidence changed")
    for suffix in (".started.json", ".completed.json"):
        expected = {f"{i:06d}{suffix}" for i in range(len(aggregate["results"]))}
        require({p.name for p in output.glob("*" + suffix)} == expected,
                "unfinished/extra attempt cannot automatically retry")
    aggregate["status"] = "INCOMPLETE"
    write_json(receipt, aggregate)
    for index in range(len(aggregate["results"]), min(len(names), len(aggregate["results"]) + max_cases)):
        require(sha(binary) == expected_sha, "executable changed")
        base = output / f"{index:06d}"
        write_json(base.with_suffix(".started.json"), {"identity": identity, "index": index, "name": names[index]})
        session = Session(binary, seed, base, index, metadata, cpu_seconds=cpu_seconds)
        started = time.monotonic_ns()
        try:
            usage = session.run(cwd)
        except BaseException as error:
            interrupted(session, error, started)
            raise
        require(sha(binary) == expected_sha, "executable changed during execution")
        record = {"index": index, "name": names[index], "flags": session.flags,
                  "status": status(session.flags), "resources": usage,
                  "duration_ns": time.monotonic_ns() - started,
                  "sampled_aggregate_peak_rss_bytes": session.peak}
        for extension in (".stdout.bin", ".stderr"):
            record[extension] = sha(base.with_suffix(extension))
        write_json(base.with_suffix(".completed.json"), record)
        aggregate["results"].append(record)
        write_json(receipt, aggregate)
        print(f"case {index + 1}/{len(names)} {record['status']} prefix_sha256={sha(receipt)}", flush=True)
    require([r["index"] for r in aggregate["results"]] == list(range(len(aggregate["results"]))), "coverage gap")
    aggregate.update(passed=sum(r["status"] == "PASS" for r in aggregate["results"]),
                     skipped=sum(r["status"] == "SKIP" for r in aggregate["results"]),
                     failed=sum(r["status"] == "FAIL" for r in aggregate["results"]),
                     fuzz_initial_cases=sum(bool(r["flags"] & 8) for r in aggregate["results"]))
    aggregate["status"] = "INCOMPLETE" if len(aggregate["results"]) != len(names) else "FAIL" if aggregate["failed"] else "PASS"
    write_json(receipt, aggregate)
    return aggregate
