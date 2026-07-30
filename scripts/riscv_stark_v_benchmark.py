#!/usr/bin/env python3
"""Matched RISC-V prove/verify benchmarks: Zig staged adapter vs pinned Stark-V.

Both lanes prove the committed release ELF corpus under the same PCS profile
(the Zig `functional` protocol equals the pinned oracle's `PcsConfig::default()`:
pow_bits 10, blowup 1, 3 queries, last layer 0). The Zig lane runs the staged
CLI under the admission phase published by that exact binary's `applications`
registry. Every row carries its release status verbatim, so staged numbers can
never impersonate promoted evidence. The Rust lane is the
pinned Stark-V `bench-cli`; its phase timings come from the tracing timestamps
it emits (the metrics JSON has no clocks). Rows fail closed: a lane error, a
cycle-count mismatch, or an unverified proof marks the row failed and the run
exits nonzero.

Usage:
  python3 scripts/riscv_stark_v_benchmark.py --stark-v-source <checkout> \
      [--warmups 1] [--samples 3] [--report-out PATH]

The checkout must be at the ledger's pinned Stark-V commit with
`target/release/stark-v-bench` built WITH the parallel feature:
`cargo build --locked --release -p bench-cli --features parallel`. The Zig lane
is multi-threaded, so the Rust lane must be too; the harness measures each Rust
run's CPU/wall ratio and fails the run if the binary looks single-threaded.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import resource
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import riscv_cli_admission  # noqa: E402
from scripts.riscv_csp_benchmark_lib.host import (  # noqa: E402
    power_evidence_block,
    sysctl_value,
)

# v2 added the `power_conditions` block. Battery power and low power mode
# throttle sustained multi-core CPU work, so a report without that evidence
# cannot say whether its numbers are measurements or throttling artefacts.
SCHEMA = "riscv_starkv_benchmark_v2"
PINNED_COMMIT = "d478f783055aa0d73a93768a433a3c6c31c91d1c"
DEFAULT_REPORT = ROOT / "vectors/reports/latest_riscv_starkv_benchmark_report.json"
ZIG_BINARY = ROOT / "zig-out/bin/stwo-zig"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOG_LINE_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z\s+INFO\b.*?(?P<message>[A-Z][^=]*?)\s*$"
)

PHASE_MARKERS = {
    "run_start": "Running guest program...",
    "prove_start": "Generating proof...",
    "verify_start": "Verifying proof...",
    "verify_done": "Proof verified successfully",
}

# Both provers must be measured with the same threading posture. The Zig lane
# runs multi-threaded by default; the pinned Stark-V prover is only parallel
# when built `--features parallel`, which is NON-default. Rather than trust the
# build flag, the harness measures each Rust run's CPU-time / wall-time and
# fails the run if the Rust lane looks single-threaded on a multi-core host —
# so a comparison can never silently pit parallel Zig against serial Rust.
MIN_RUST_PARALLELISM = 1.5


def _tool_version(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (result.stdout or result.stderr).strip().splitlines()
    return out[0] if result.returncode == 0 and out else None


def collect_host_environment(
    stark_v_source: Path | None = None,
    *,
    power_conditions: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Portable machine context for a benchmark report: what ran it, where.

    No serial numbers or user data. Fields absent on non-macOS hosts are null,
    with the platform block always populated so every report is self-describing.

    ## Power conditions ride here, in every harness that embeds this block

    All three harnesses that publish prove/verify timings embed this block, and
    only one of them used to record power state -- so the other two could publish
    battery-throttled numbers with nothing in the report saying so, which is the
    defect issue #152 item 6c exists to prevent. The evidence therefore lives
    here rather than in one harness's own report body, and its schema is v2
    because a consumer must be able to tell a report that carries the evidence
    from one that could not.

    ``power_conditions`` is the shared ``power_evidence_block`` -- one
    implementation, in ``riscv_csp_benchmark_lib.host``. Callers that already
    captured it (to warn an operator while the run is still worth aborting) pass
    it in, so one run reports one capture rather than two that can disagree.

    The field set is pinned on the consuming side by
    ``riscv_benchmark_matrix_contract.HOST_ENVIRONMENT_FIELDS``; this function's
    test asserts equality against that constant, so the producer and the contract
    cannot drift apart silently in either direction.
    """
    import platform

    memsize = sysctl_value("hw.memsize")
    stark_v_commit = None
    if stark_v_source is not None:
        stark_v_commit = _tool_version(
            ["git", "-C", str(stark_v_source), "rev-parse", "HEAD"]
        )
    return {
        "schema": "riscv_benchmark_host_environment_v2",
        "power_conditions": (
            power_evidence_block() if power_conditions is None else dict(power_conditions)
        ),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "os_product_version": _tool_version(["sw_vers", "-productVersion"]),
            "os_build_version": _tool_version(["sw_vers", "-buildVersion"]),
        },
        "hardware": {
            "chip": sysctl_value("machdep.cpu.brand_string"),
            "machine_model": sysctl_value("hw.model"),
            "logical_cpu_count": os.cpu_count(),
            "physical_memory_bytes": int(memsize) if memsize else None,
        },
        "toolchain": {
            "zig_version": _tool_version(["zig", "version"]),
            "host_rustc": _tool_version(["rustc", "--version"]),
            "python": platform.python_version(),
        },
        "stark_v_commit": stark_v_commit,
    }


def parse_phase_seconds(stderr: str) -> dict[str, float]:
    """Extract execution/prove/verify durations from bench-cli tracing output."""
    stamps: dict[str, dt.datetime] = {}
    for raw in stderr.splitlines():
        line = ANSI_RE.sub("", raw)
        match = LOG_LINE_RE.match(line.strip())
        if not match:
            continue
        message = match.group("message").strip()
        for key, marker in PHASE_MARKERS.items():
            if marker in message and key not in stamps:
                stamps[key] = dt.datetime.fromisoformat(match.group("stamp"))
    missing = [key for key in PHASE_MARKERS if key not in stamps]
    if missing:
        raise ValueError(f"bench-cli output lacks phase markers: {missing}")
    return {
        "execution_seconds": (stamps["prove_start"] - stamps["run_start"]).total_seconds(),
        "prove_seconds": (stamps["verify_start"] - stamps["prove_start"]).total_seconds(),
        "verify_seconds": (stamps["verify_done"] - stamps["verify_start"]).total_seconds(),
    }


def load_corpus() -> tuple[str, list[dict[str, str]]]:
    manifest = json.loads((ROOT / "vectors/riscv_elfs/trace_vectors.json").read_text())
    if manifest.get("stark_v_commit") != PINNED_COMMIT:
        raise SystemExit("trace vector manifest is pinned to a different Stark-V commit")
    vectors = []
    for vector in manifest["vectors"]:
        elf = ROOT / vector["elf"]
        digest = hashlib.sha256(elf.read_bytes()).hexdigest()
        if digest != vector["elf_sha256"]:
            raise SystemExit(f"ELF digest mismatch for {vector['name']}")
        vectors.append({
            "name": vector["name"],
            "elf": str(elf),
            "elf_sha256": digest,
            "proof_admission": vector.get("proof_admission", {}),
        })
    if not vectors:
        raise SystemExit("release corpus has no positive vectors")
    return PINNED_COMMIT, vectors


def validate_stark_v(source: Path) -> Path:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != PINNED_COMMIT:
        raise SystemExit(f"Stark-V checkout is at {head}, not the pinned {PINNED_COMMIT}")
    binary = source / "target/release/stark-v-bench"
    if not binary.exists():
        raise SystemExit(
            "stark-v-bench is not built; run: "
            "cargo build --locked --release -p bench-cli --features parallel"
        )
    return binary


def run_zig_lane(
    elf: str,
    warmups: int,
    samples: int,
    admission: riscv_cli_admission.Admission,
) -> dict[str, object]:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_start = dt.datetime.now()
    result = subprocess.run(
        [
            str(ZIG_BINARY), "bench", "--elf", elf, "--backend", "cpu",
            "--protocol", "functional", *admission.arguments,
            "--warmups", str(warmups), "--samples", str(samples),
        ],
        capture_output=True, text=True, timeout=1800,
    )
    wall = (dt.datetime.now() - wall_start).total_seconds()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout).strip()[-400:]}
    report_lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    if not report_lines:
        return {"error": "no report JSON on stdout"}
    report = json.loads(report_lines[-1])
    if (
        report.get("release_status") != admission.release_status
        or report.get("experimental") is not admission.experimental
    ):
        return {"error": "benchmark admission differs from CLI registry"}
    if report.get("verified_samples") != samples:
        return {"error": f"verified_samples={report.get('verified_samples')} != {samples}"}
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    return {
        "release_status": report["release_status"],
        "total_steps": report["total_steps"],
        "prove_seconds": report["mean_proving_seconds"],
        "verify_seconds": report["mean_verification_seconds"],
        "execution_seconds": report["mean_execution_seconds"],
        "statement_sha256": report["statement_sha256"],
        "implementation_commit": report["implementation_commit"],
        "implementation_dirty": report["implementation_dirty"],
        # Whole-invocation ratio over warmups+samples; a coarse threading check,
        # not a per-phase figure like the medians above.
        "cpu_wall_ratio": (cpu / wall) if wall > 0 else 0.0,
    }


def run_rust_lane(binary: Path, elf: str, warmups: int, samples: int) -> dict[str, object]:
    runs: list[dict[str, float]] = []
    parallelism: list[float] = []
    cycles: set[int] = set()
    for index in range(warmups + samples):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        wall_start = dt.datetime.now()
        result = subprocess.run(
            [str(binary), "bench", "--elf", elf, "--metrics-out", "/dev/null"],
            capture_output=True, text=True, timeout=1800,
            env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info"},
        )
        wall = (dt.datetime.now() - wall_start).total_seconds()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        log = result.stdout + "\n" + result.stderr
        if result.returncode != 0:
            return {"error": ANSI_RE.sub("", log).strip()[-400:]}
        if "Proof verified successfully" not in ANSI_RE.sub("", log):
            return {"error": "rust lane did not report successful verification"}
        cycle_match = re.search(r"completed with (\d+) cycles", ANSI_RE.sub("", log))
        if cycle_match:
            cycles.add(int(cycle_match.group(1)))
        if index >= warmups:
            runs.append(parse_phase_seconds(log))
            cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
            if wall > 0:
                parallelism.append(cpu / wall)
    if len(cycles) > 1:
        return {"error": f"nondeterministic cycle counts: {sorted(cycles)}"}
    return {
        "cycles": cycles.pop() if cycles else None,
        "prove_seconds": statistics.median(run["prove_seconds"] for run in runs),
        "verify_seconds": statistics.median(run["verify_seconds"] for run in runs),
        "execution_seconds": statistics.median(run["execution_seconds"] for run in runs),
        "cpu_wall_ratio": statistics.median(parallelism) if parallelism else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stark-v-source", required=True, type=Path)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)

    if not ZIG_BINARY.exists():
        raise SystemExit("stwo-zig is not built; run: zig build stwo-zig -Doptimize=ReleaseFast")
    try:
        admission = riscv_cli_admission.resolve(ZIG_BINARY, cwd=ROOT)
    except riscv_cli_admission.AdmissionError as error:
        raise SystemExit(f"invalid Zig applications registry: {error}") from error
    rust_binary = validate_stark_v(args.stark_v_source.resolve())
    pinned, corpus = load_corpus()
    multicore = (os.cpu_count() or 1) > 1
    # Captured before the first sample so an operator sees a throttled host
    # while the run is still worth aborting, not after it finishes.
    power = power_evidence_block()
    if not power["admissible"]:
        print(f"[power] {'; '.join(power['reasons'])}", flush=True)

    rows = []
    failures = 0
    for vector in corpus:
        # Named apart from `admission`, the binary's own registry phase: the
        # manifest's per-vector admission decides whether a family is proved at
        # all, and shadowing the CLI authority with it published the manifest's
        # word as the binary's.
        proof_admission = vector["proof_admission"]
        if proof_admission.get("status") != "supported":
            rows.append({
                "name": vector["name"],
                "elf_sha256": vector["elf_sha256"],
                "status": "skipped_unsupported_family",
                "proof_admission": proof_admission,
            })
            print(
                f"{vector['name']:20s} skip   "
                f"{proof_admission.get('known_limitation', proof_admission.get('status'))}",
                flush=True,
            )
            continue
        zig = run_zig_lane(
            vector["elf"], args.warmups, args.samples, admission,
        )
        rust = run_rust_lane(rust_binary, vector["elf"], args.warmups, args.samples)
        row: dict[str, object] = {"name": vector["name"], "elf_sha256": vector["elf_sha256"]}
        problems = []
        for side, lane in (("zig", zig), ("rust", rust)):
            if "error" in lane:
                problems.append(f"{side}: {lane['error']}")
        if not problems and zig["total_steps"] != rust["cycles"]:
            problems.append(f"step mismatch: zig={zig['total_steps']} rust={rust['cycles']}")
        if not problems and multicore and rust["cpu_wall_ratio"] < MIN_RUST_PARALLELISM:
            problems.append(
                f"rust lane looks single-threaded (cpu/wall={rust['cpu_wall_ratio']:.2f} "
                f"< {MIN_RUST_PARALLELISM}); rebuild with `cargo build --locked --release "
                "-p bench-cli --features parallel`"
            )
        row["zig"] = zig
        row["rust"] = rust
        # RISC-V has no Metal prover on either lane (adapter is CPU-only), so the
        # Metal column is uniformly gated; native CPU-vs-Metal is a separate matrix.
        row["metal"] = "gated"
        if problems:
            row["status"] = "failed"
            row["problems"] = problems
            failures += 1
        else:
            row["status"] = "ok"
            row["zig_over_rust_prove"] = zig["prove_seconds"] / rust["prove_seconds"]
            row["zig_over_rust_verify"] = zig["verify_seconds"] / rust["verify_seconds"]
        rows.append(row)
        summary = (
            f"prove z/r={row.get('zig_over_rust_prove'):.3f}" if row["status"] == "ok"
            else "; ".join(problems)[:160]
        )
        print(f"{vector['name']:20s} {row['status']:6s} {summary}", flush=True)

    ok_ratios = [r["rust"]["cpu_wall_ratio"] for r in rows if r["status"] == "ok"]
    report = {
        "schema": SCHEMA,
        "stark_v_commit": pinned,
        "zig_release_status": admission.release_status,
        "zig_experimental": admission.experimental,
        "pcs_profile": "functional == pinned PcsConfig::default() (pow 10, blowup 1, 3 queries)",
        "threading": {
            "host_cpu_count": os.cpu_count(),
            "both_lanes_multi_threaded": multicore,
            "rust_features_required": "parallel",
            "min_rust_cpu_wall_ratio": MIN_RUST_PARALLELISM,
            "observed_median_rust_cpu_wall_ratio": (
                statistics.median(ok_ratios) if ok_ratios else None
            ),
        },
        "metal_note": "RISC-V adapter is CPU-only; no RISC-V Metal prover on "
                      "either lane. Native CPU-vs-Metal is in the native proof matrix.",
        "host_environment": collect_host_environment(
            args.stark_v_source.resolve(), power_conditions=power,
        ),
        # Same evidence, same implementation, same verdict as the CSP harness:
        # a check that exists on one benchmark path and not its sibling is how
        # throttled numbers get published as clean ones.
        #
        # Retained at the root because this report's own v2 schema declared it
        # there before the shared host block could carry it. It is the *same*
        # capture the host block embeds -- `test_riscv_stark_v_benchmark` pins the
        # two equal -- so a consumer reading either spelling reads one verdict.
        "power_conditions": power,
        "warmups": args.warmups,
        "samples": args.samples,
        "failure_count": failures,
        "rows": rows,
    }
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"report: {args.report_out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
