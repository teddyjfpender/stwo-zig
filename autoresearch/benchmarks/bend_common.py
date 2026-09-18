"""Frozen native-process measurement and exact binary parity utilities (Unix)."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
OPS = {"fft": 0, "ifft": 1, "multiply": 2, "prefix": 3, "fri_line": 4, "fri_circle": 5}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def measure(argv, data=b"", timeout=60):
    """Per-child wait4 usage, not cumulative RUSAGE_CHILDREN high-water marks."""
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stdin.write(data)
        stdin.seek(0)
        start = time.perf_counter_ns()
        child = subprocess.Popen([str(x) for x in argv], stdin=stdin, stdout=stdout, stderr=stderr)
        expired = threading.Event()
        def kill():
            expired.set()
            child.kill()
        timer = threading.Timer(timeout, kill)
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        finally:
            timer.cancel()
        wall = time.perf_counter_ns() - start
        stdout.seek(0)
        stderr.seek(0)
        out, err = stdout.read(), stderr.read().decode(errors="replace")
        if expired.is_set():
            raise TimeoutError(f"native child exceeded {timeout}s: {argv[0]}")
        if child.returncode:
            raise RuntimeError(f"child exit {child.returncode}: {err[-4000:]}")
        telemetry = [json.loads(line) for line in err.splitlines() if line.startswith('{')]
        if len(telemetry) != 1:
            raise ValueError(f"expected one measurement receipt, got {err!r}")
        return out, {**telemetry[0], "wall_ns": wall, "cpu_user_s": usage.ru_utime,
                     "cpu_system_s": usage.ru_stime,
                     "peak_rss_bytes": usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024),
                     "request_bytes": len(data), "response_bytes": len(out)}


def fixture(oracle, op, log, seed, directory):
    req, expected = directory / "request.bin", directory / "expected.bin"
    _, receipt = measure([oracle, OPS[op], log, seed, req, expected])
    return req.read_bytes(), expected.read_bytes(), receipt


def provenance(bend, oracle):
    sources = sorted((ROOT / "bend").rglob("*.bend")) + sorted((ROOT / "src/backends/bend").glob("*.zig"))
    sources += [ROOT / "bend/stwo/transport.c", ROOT / "autoresearch/benchmarks/bend_common.py"]
    return {"schema": "stwo-bend-evidence-v1", "toolchain": json.loads((ROOT / "bend/toolchain.json").read_text()),
            "host": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                     "cpu": next((l.split(':', 1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')), '') if Path('/proc/cpuinfo').exists() else platform.processor()},
            "bend_binary_sha256": digest(bend), "zig_oracle_sha256": digest(oracle),
            "sources": {str(p.relative_to(ROOT)): digest(p) for p in sources},
            "rust_oracle_qualified": False, "proof_throughput_claim": False,
            "scope": "fresh process per column; compute excludes input tree/plan construction and output serialization; wall includes native process launch and transport; compiler excluded",
            "limitations": ["shared host, uncontrolled frequency", "RSS includes runtime and IO", "logical operations are not machine instructions", "no full proof or universal arithmetic proof"]}
