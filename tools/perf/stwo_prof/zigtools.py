"""Zig profiling: build, counter runs, stack sampling, codegen summary, A/B."""

from __future__ import annotations

import json
import os
import re
import shutil
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

from stwo_perf import stats as perf_stats


class ProfError(RuntimeError):
    pass


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 900,
         env: dict | None = None) -> subprocess.CompletedProcess:
    merged = {**os.environ, **(env or {})}
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=merged)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        error_lines = [l for l in stderr.splitlines() if "error" in l.lower()]
        detail = "\n".join(error_lines[:12]) if error_lines else stderr[-800:]
        raise ProfError(f"{' '.join(cmd)} failed:\n{detail}")
    return proc


def build(bench_dir: Path, debug: bool = False) -> Path:
    mode = "Debug" if debug else "ReleaseFast"
    _run(["zig", "build", f"-Doptimize={mode}"], cwd=bench_dir)
    return bench_dir / "zig-out" / "bin" / "bench"


def run_counters(bench_dir: Path, iters: int, rounds: int = 5,
                 debug: bool = False) -> dict:
    """Build + run the harness; per-round counter JSON, medians across rounds."""
    binary = build(bench_dir, debug=debug)
    rows = []
    for _ in range(rounds):
        proc = _run([str(binary)], cwd=bench_dir,
                    env={"STWO_PROF_ITERS": str(iters)})
        try:
            rows.append(json.loads(proc.stdout.strip().splitlines()[-1]))
        except (json.JSONDecodeError, IndexError) as exc:
            raise ProfError(f"harness emitted non-JSON output: {proc.stdout[:200]!r}") from exc

    def med(key: str):
        values = [r[key] for r in rows if key in r]
        return statistics.median(values) if values else None

    from .scaffold import workload_imports
    summary = {
        "rounds": rounds,
        "iterations": iters,
        "ops_per_call": rows[0].get("ops_per_call"),
        "imports": workload_imports(bench_dir) or None,
        "ns_per_op": med("ns_per_op"),
        "ns_per_op_min": min((r["ns_per_op"] for r in rows), default=None),
        "instructions_per_op": med("instructions_per_op"),
        "cycles_per_op": med("cycles_per_op"),
        "ipc": med("ipc"),
        "energy_nj_median_round": med("energy_nj"),
        "peak_footprint_bytes": med("peak_footprint_bytes"),
        "raw_rounds": rows,
    }
    if summary["instructions_per_op"] is None:
        summary["note"] = "hardware counters unavailable (non-macOS?); wall time only"
    return summary


def compare(dir_a: Path, dir_b: Path, iters: int, rounds: int = 7) -> dict:
    """ABBA-interleaved comparison; wall ratios get a bootstrap CI,
    instruction/cycle ratios are near-deterministic and reported directly."""
    bin_a = build(dir_a)
    bin_b = build(dir_b)

    def one(binary: Path, cwd: Path) -> dict:
        proc = _run([str(binary)], cwd=cwd, env={"STWO_PROF_ITERS": str(iters)})
        return json.loads(proc.stdout.strip().splitlines()[-1])

    ratios, a_rows, b_rows = [], [], []
    for round_no in range(rounds):
        order = [("a",), ("b",)] if round_no % 2 == 0 else [("b",), ("a",)]
        results = {}
        for (arm,) in order:
            results[arm] = one(bin_a if arm == "a" else bin_b,
                               dir_a if arm == "a" else dir_b)
        a_rows.append(results["a"])
        b_rows.append(results["b"])
        ratios.append(results["b"]["ns_per_op"] / results["a"]["ns_per_op"])

    out = {
        "rounds": rounds,
        "wall_ratio_b_over_a": round(perf_stats.hodges_lehmann(ratios), 6),
        "wall_ratio_ci95": [round(v, 6) for v in perf_stats.bootstrap_ci(ratios, seed=1)],
        "a_ns_per_op": statistics.median(r["ns_per_op"] for r in a_rows),
        "b_ns_per_op": statistics.median(r["ns_per_op"] for r in b_rows),
    }
    if all("instructions_per_op" in r for r in a_rows + b_rows):
        ia = statistics.median(r["instructions_per_op"] for r in a_rows)
        ib = statistics.median(r["instructions_per_op"] for r in b_rows)
        ca = statistics.median(r["cycles_per_op"] for r in a_rows)
        cb = statistics.median(r["cycles_per_op"] for r in b_rows)
        out.update({
            "a_instructions_per_op": ia, "b_instructions_per_op": ib,
            "instruction_ratio_b_over_a": round(ib / ia, 6) if ia else None,
            "a_cycles_per_op": ca, "b_cycles_per_op": cb,
            "cycle_ratio_b_over_a": round(cb / ca, 6) if ca else None,
        })
    return out


def sample_stacks(bench_dir: Path, seconds: int = 5, iters: int = 2_000_000) -> str:
    """Run the bench under /usr/bin/sample and return the report text."""
    if shutil.which("sample") is None:
        raise ProfError("/usr/bin/sample not found (macOS required)")
    binary = build(bench_dir)
    child = subprocess.Popen([str(binary)], cwd=bench_dir,
                             env={**os.environ, "STWO_PROF_ITERS": str(iters)},
                             stdout=subprocess.DEVNULL)
    try:
        proc = subprocess.run(
            ["sample", str(child.pid), str(seconds), "-mayDie"],
            capture_output=True, text=True, timeout=seconds + 60,
        )
    finally:
        child.terminate()
        child.wait(timeout=30)
    if proc.returncode != 0:
        raise ProfError(f"sample failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


_SAMPLE_FRAME_RE = re.compile(r"[\s+!:|]+(\d+)\s+(\S+)\s+\(in bench\)")


def sample_hot_frames(report: str, top: int = 10) -> list[dict]:
    """Aggregate /usr/bin/sample call-tree lines for the bench binary.

    Counts are inclusive; a frame appearing at several call sites keeps its
    maximum count (the deepest attribution of that symbol)."""
    inclusive: dict[str, int] = {}
    for count, symbol in _SAMPLE_FRAME_RE.findall(report):
        inclusive[symbol] = max(inclusive.get(symbol, 0), int(count))
    total = max(inclusive.values(), default=0)
    return [
        {"symbol": sym, "samples": n,
         "pct_of_run": round(100.0 * n / total, 1) if total else 0.0}
        for sym, n in sorted(inclusive.items(), key=lambda kv: -kv[1])[:top]
    ]


# Zig std top-level namespaces plus compiler-rt: harness plumbing an agent
# almost never needs to see. `asm --all` shows everything.
_STD_NAMESPACES = (
    "Io.", "fs.", "fmt.", "log.", "debug.", "heap.", "posix.", "mem.",
    "math.", "process.", "Thread.", "os.", "time.", "meta.", "sort.",
    "ascii.", "atomic.", "simd.", "unicode.", "builtin.", "Random.",
    "start.", "c.", "compress.", "std.",
)


def is_std_symbol(name: str) -> bool:
    bare = name.lstrip("_")
    return (name.startswith("__") or bare.startswith(_STD_NAMESPACES)
            or bare in ("start", "main.frame", "memcpy", "memset", "memmove"))


_NEON_RE = re.compile(
    r"\.(?:16b|8b|8h|4h|4s|2s|2d|1d)\b|\bv\d+\.", re.IGNORECASE
)
_BRANCH_RE = re.compile(r"^\s*(b|b\.\w+|bl|blr|cbz|cbnz|tbz|tbnz|ret)(?:\s|$)", re.IGNORECASE)
_MEM_RE = re.compile(r"^\s*(ld|st)\w*\s", re.IGNORECASE)
_LABEL_RE = re.compile(r'^"?([A-Za-z_.$][^":]*)"?:')


def asm_summary(bench_dir: Path, symbol_filter: str | None = None) -> dict:
    """Emit assembly for workload.zig and summarize codegen per symbol:
    instruction count, NEON share, branches, loads/stores. Verifies the
    'vector claim needs disassembly evidence' rule mechanically."""
    # Emit from main.zig: unreferenced pub fns are lazily skipped, so the
    # workload only appears in the listing via the harness that calls it.
    from .scaffold import workload_imports
    out_s = bench_dir / "bench.s"
    cmd = [
        "zig", "build-obj", "-O", "ReleaseFast",
        "-fno-emit-bin", f"-femit-asm={out_s.name}", "-mcpu", "native",
    ]
    imports = workload_imports(bench_dir)
    if imports:
        # --dep flags attach to the next -M module; the first -M is the
        # main module, so root (with its deps) must come before the dep
        # module definitions.
        for mod in sorted(imports):
            cmd += ["--dep", mod]
        cmd += ["-Mroot=main.zig"]
        for mod, path in sorted(imports.items()):
            cmd += [f"-M{mod}={path}"]
    else:
        cmd += ["main.zig"]
    _run(cmd, cwd=bench_dir)
    current = None
    per_symbol: dict[str, dict] = defaultdict(
        lambda: {"instructions": 0, "neon": 0, "branches": 0, "memory": 0}
    )
    for line in out_s.read_text().splitlines():
        label = _LABEL_RE.match(line)
        if label:
            name = label.group(1)
            if name.startswith("_") or not name.startswith((".", "l", "L")):
                current = name if name.startswith("_") else name
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith((".", ";", "//")) or current is None:
            continue
        row = per_symbol[current]
        row["instructions"] += 1
        if _NEON_RE.search(stripped):
            row["neon"] += 1
        if _BRANCH_RE.match(line):
            row["branches"] += 1
        if _MEM_RE.match(line):
            row["memory"] += 1
    symbols = {
        name: {**row,
               "neon_pct": round(100.0 * row["neon"] / row["instructions"], 1),
               "std": is_std_symbol(name)}
        for name, row in per_symbol.items()
        if row["instructions"] > 0 and (symbol_filter is None or symbol_filter in name)
    }
    return {"asm_file": str(out_s), "symbols": symbols}
