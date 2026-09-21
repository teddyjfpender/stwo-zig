"""Opt-in, measured native leaf verification beside the serialized heavy lane.

This is a monitored scheduling envelope, not an OS memory limit or proof
admission. Only the pinned one-worker fixed-program v5 leaf command is allowed.
Builds, producers, wrappers and whole bundles keep the existing heavy lock.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from scripts import ethereum_block_proof_process as transport
from scripts import ethereum_block_proof_store as store
from scripts.zig_serial_build import DEFAULT_LOCK, HELD_LOCK_ENV

GIB = 1024 ** 3
LANE_LOCK = DEFAULT_LOCK + ".bounded-native-verifier"
MODE = "verify-leaf-fixed-program-v5"
ENDPOINT = "verified_native_selected_leaf_fixed_program_v5"
POLICY_SCHEMA = "stwo.ethereum.bounded-native-verifier-policy.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(path: Path) -> dict:
    return {"path": str(path), **store.file_identity(path, "bounded verifier input")}


def checked_file(value: dict) -> Path:
    require(set(value) == {"path", "bytes", "sha256"}, "invalid pinned file identity")
    path = Path(value["path"])
    require(path.is_absolute(), "pinned path must be absolute")
    store.validate_file_identity(path, {key: value[key] for key in ("bytes", "sha256")}, "bounded verifier input")
    return path


def load_policy(path: Path, sha256: str) -> dict:
    raw = store.read_regular(path, "bounded verifier policy", maximum=128 * 1024)
    require(hashlib.sha256(raw).hexdigest() == sha256, "verification scheduling policy pin differs")
    policy = json.loads(raw)
    require(set(policy) == {"schema", "verifier", "materialization", "baselines", "child_byte_budget", "host_reserve_bytes", "maximum_proof_bytes", "timeout_seconds"}, "invalid bounded verifier policy fields")
    require(policy["schema"] == POLICY_SCHEMA, "unsupported bounded verifier policy")
    for name in ("child_byte_budget", "host_reserve_bytes", "maximum_proof_bytes", "timeout_seconds"):
        require(type(policy[name]) is int and policy[name] > 0, "invalid scheduling bound")
    require(policy["child_byte_budget"] <= 3 * GIB and policy["host_reserve_bytes"] >= 6 * GIB
            and policy["maximum_proof_bytes"] <= 128 * 1024 ** 2 and policy["timeout_seconds"] <= 180,
            "bounded verifier exceeds admitted lane envelope")
    binary = checked_file(policy["verifier"])
    checked_file(policy["materialization"])
    require(type(policy["baselines"]) is list and 0 < len(policy["baselines"]) <= 210, "missing measured verifier baseline")
    for baseline in policy["baselines"]:
        require(set(baseline) == {"request", "execution", "receipt", "plan"}, "invalid baseline custody")
        values = {name: json.loads(checked_file(pin).read_bytes()) for name, pin in baseline.items()}
        require(hashlib.sha256(Path(baseline["plan"]["path"]).read_bytes()).hexdigest() == values["request"]["plan_sha256"]
                and values["plan"]["verifier"] == policy["verifier"], "baseline executable pin differs from sealed campaign")
        argv = values["request"]["argv"]
        _check_command(policy, argv)
        require(Path(argv[0]) == binary and values["execution"]["exit_code"] == 0, "baseline did not execute the admitted verifier")
        receipt = values["receipt"]
        require(receipt["endpoint"] == ENDPOINT, "baseline profile differs")
        measured = receipt["verification"]
        require(measured["endpoint"] == "verified_native_selected_leaf" and measured["worker_count"] == 1
                and measured["retained_admission_destroyed_before_proof"] is True,
                "baseline is not independent one-worker leaf verification")
        require(all(type(measured[name]) is int for name in ("peak_footprint_bytes", "request_ns", "worker_count")),
                "invalid measured baseline values")
        require(bytes(measured["materialization_sha256"]).hex() == policy["materialization"]["sha256"]
                and 0 < measured["peak_footprint_bytes"] * 5 <= policy["child_byte_budget"] * 4
                and 0 < measured["request_ns"] <= policy["timeout_seconds"] * 1_000_000_000,
                "measured verifier exceeds scheduling envelope or lacks 25 percent headroom")
    return policy


def _check_command(policy: dict, argv: list[str]) -> None:
    require(len(argv) == 8 and argv[0] == policy["verifier"]["path"] and argv[1] == MODE
            and argv[4] == policy["materialization"]["path"]
            and argv[5] == policy["materialization"]["sha256"] and argv[6:] == ["--workers", "1"],
            "bounded lane requires exact pinned one-worker native leaf command")


def admit_command(policy: dict, argv: list[str]) -> list[dict]:
    _check_command(policy, argv)
    checked_file(policy["verifier"])
    checked_file(policy["materialization"])
    proof = store.file_identity(Path(argv[2]), "bounded verifier proof")
    require(0 < proof["bytes"] <= policy["maximum_proof_bytes"], "proof exceeds measured lane input bound")
    metadata_bytes = store.read_regular(Path(argv[3]), "bounded verifier metadata", maximum=128 * 1024)
    metadata = json.loads(metadata_bytes)
    require(metadata["proof_bytes"] == proof["bytes"] and bytes(metadata["proof_sha256"]).hex() == proof["sha256"],
            "proof differs from native metadata")
    return [{"path": argv[2], **proof}, {"path": argv[3], "bytes": len(metadata_bytes),
                                       "sha256": hashlib.sha256(metadata_bytes).hexdigest()}]


def host_headroom() -> dict:
    """Use OS pressure/availability reporting; unavailable measurements reject."""
    if sys.platform == "darwin":
        result = subprocess.run(["/usr/bin/memory_pressure", "-Q"], capture_output=True, text=True, timeout=2, check=True)
        total = re.search(r"The system has ([0-9]+) ", result.stdout)
        free = re.search(r"System-wide memory free percentage: ([0-9]+)%", result.stdout)
        require(total is not None and free is not None and 0 <= int(free[1]) <= 100, "cannot measure host memory pressure")
        return {"source": "darwin.memory_pressure.Q", "physical_bytes": int(total[1]), "available_bytes": int(total[1]) * int(free[1]) // 100}
    if sys.platform.startswith("linux"):
        values = dict(re.findall(r"^(MemTotal|MemAvailable):\s+([0-9]+) kB$", Path("/proc/meminfo").read_text(), re.MULTILINE))
        require(set(values) == {"MemTotal", "MemAvailable"}, "cannot measure host memory availability")
        return {"source": "linux.MemAvailable", "physical_bytes": int(values["MemTotal"]) * 1024, "available_bytes": int(values["MemAvailable"]) * 1024}
    raise ValueError("bounded native verification has no host memory monitor on this platform")


class _RusageV0(ctypes.Structure):
    # macOS SDK sys/resource.h, RUSAGE_INFO_V0: stable physical-footprint ABI.
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
        "user", "system", "idle", "interrupts", "pageins", "wired", "resident", "footprint", "started", "exited")]


def child_footprint(pid: int) -> int:
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        usage = _RusageV0()
        function = library.proc_pid_rusage
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        function.restype = ctypes.c_int
        if function(pid, 0, ctypes.byref(usage)) != 0:
            raise OSError(ctypes.get_errno(), "cannot sample native verifier footprint")
        return int(usage.footprint)
    if sys.platform.startswith("linux"):
        values = dict(re.findall(r"^(VmRSS|VmSwap):\s+([0-9]+) kB$", Path(f"/proc/{pid}/status").read_text(), re.MULTILINE))
        require(set(values) == {"VmRSS", "VmSwap"}, "cannot sample native verifier footprint")
        return sum(int(value) for value in values.values()) * 1024
    raise ValueError("unsupported child memory monitor")


@contextmanager
def lane():
    # One bounded verifier globally, independent of the unchanged heavy lock.
    with open(LANE_LOCK, "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("bounded native verifier lane is already occupied") from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def run(argv: list[str], policy: dict, *, stdout, stderr, timeout: float, observation: dict) -> subprocess.CompletedProcess:
    observation.update({"schema": "stwo.ethereum.bounded-native-verifier-observation.v1", "resource_envelope_passed": False,
                        "os_memory_limit": False, "peak_sampled_child_bytes": 0, "poll_seconds": 0.25})
    child = None
    started = time.monotonic()
    try:
        require(0 < timeout, "bounded verifier timeout must be positive")
        with lane():
            try:
                input_identities = admit_command(policy, argv)
                host = host_headroom()
                observation["host_before"] = host
                require(host["available_bytes"] >= policy["child_byte_budget"] + policy["host_reserve_bytes"], "insufficient measured host headroom for bounded verifier")
                environment = dict(os.environ)
                environment.pop(HELD_LOCK_ENV, None)
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, env=environment)
                observation["pid"] = child.pid
                deadline = time.monotonic() + min(timeout, policy["timeout_seconds"])
                while child.poll() is None:
                    require(time.monotonic() < deadline, "bounded native verifier timed out")
                    try:
                        footprint = child_footprint(child.pid)
                    except OSError:
                        if child.poll() is not None:
                            break
                        raise
                    observation["peak_sampled_child_bytes"] = max(observation["peak_sampled_child_bytes"], footprint)
                    require(footprint <= policy["child_byte_budget"], "bounded native verifier exceeded child footprint envelope")
                    host = host_headroom()
                    observation["host_latest"] = host
                    require(host["available_bytes"] >= policy["host_reserve_bytes"], "host headroom fell below verifier reserve")
                    require(max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) <= 1024 ** 2,
                            "bounded native verifier exceeded output transport bound")
                    time.sleep(0.25)
                require(transport.drain_process_group(child, "bounded native verifier"), "bounded native verifier left descendants")
                require(max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) <= 1024 ** 2,
                        "bounded native verifier exceeded output transport bound")
                require(admit_command(policy, argv) == input_identities, "verifier input custody changed during execution")
                observation["input_identities"] = input_identities
                observation["resource_envelope_passed"] = True
                observation["exit_code"] = child.returncode
                return subprocess.CompletedProcess(argv, child.returncode)
            finally:
                # Keep the lane until its child group has drained, including
                # resource failures; a second verifier cannot race cleanup.
                if child is not None:
                    transport.drain_process_group(child, "bounded native verifier cleanup")
    except BaseException as error:
        observation["error"] = str(error)
        raise
    finally:
        observation["elapsed_s"] = time.monotonic() - started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    policy = load_policy(args.policy, args.policy_sha256)
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    args.output.mkdir(parents=True, exist_ok=False)
    observation = {"policy_sha256": args.policy_sha256, "argv": argv}
    try:
        with (args.output / "stdout.json").open("xb") as stdout, (args.output / "stderr.log").open("xb") as stderr:
            result = run(argv, policy, stdout=stdout, stderr=stderr, timeout=policy["timeout_seconds"], observation=observation)
        raise SystemExit(result.returncode)
    finally:
        (args.output / "scheduling.json").write_text(json.dumps(observation, indent=2) + "\n")


if __name__ == "__main__":
    main()
