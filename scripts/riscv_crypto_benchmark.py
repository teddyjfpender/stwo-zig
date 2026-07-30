#!/usr/bin/env python3
"""Cryptographic RISC-V guest benchmarks: Zig staged adapter vs pinned Stark-V.

Runs the vendored crypto guests (SHA-256, Keccak, ECDSA from Stark-V's guest-lib
plus the repo's Poseidon2-M31) over the sizes recorded in the provenance file,
under the matched functional PCS profile. Two row classes:

  proof     - prove + verify on both lanes, cycle-parity checked (SHA-256 at all
              sizes; Keccak single-block only). Reports prove/verify ratios.
  execution - both lanes only EXECUTE the guest (Stark-V `run`, Zig
              `riscv-trace-dump`); neither proves it at the pinned config.
              Reports VM cycles (parity-checked) and execution-time ratio.
              Covers ECDSA, Poseidon2-M31, and multi-block Keccak.

Metal column: the RISC-V adapter is CPU-only (backend enum {cpu,
unavailable_device}) and pinned Stark-V ships no RISC-V Metal prover, so every
row's metal cell is `gated` — recorded, not silently omitted. A native
(non-RISC-V) CPU-vs-Metal comparison lives in the native proof matrix instead.

Usage:
  python3 scripts/riscv_crypto_benchmark.py --stark-v-source <checkout> \
      [--warmups 1] [--samples 3] [--report-out PATH]

Requires `build_crypto_guests.py` to have vendored the ELFs, the Zig binaries
(stwo-zig, riscv-trace-dump) built, and stark-v-bench built --features parallel.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.riscv_stark_v_benchmark import (  # noqa: E402
    ANSI_RE,
    MIN_RUST_PARALLELISM,
    PINNED_COMMIT,
    collect_host_environment,
    parse_phase_seconds,
    power_evidence_block,
)
from scripts import riscv_cli_admission  # noqa: E402
from scripts.riscv_csp_benchmark_lib.build_identity import (  # noqa: E402
    read_trace_provenance,
)
from scripts.riscv_csp_benchmark_lib.contract import BenchmarkError, Case  # noqa: E402
# v2 carries `host_environment` schema v2, whose `power_conditions` block records
# whether this run's numbers are measurements or throttling artefacts, and
# `trace_provenance`, which binds the trace dumper that produced every cycle
# count in the execution rows (issue #152 items 6b and 6c).
SCHEMA = "riscv_crypto_benchmark_v2"
CRYPTO_DIR = ROOT / "vectors/riscv_elfs/crypto"
PROVENANCE = CRYPTO_DIR / "provenance.json"
DEFAULT_REPORT = ROOT / "vectors/reports/latest_riscv_crypto_benchmark_report.json"
ZIG_BENCH = ROOT / "zig-out/bin/stwo-zig"
ZIG_TRACE = ROOT / "zig-out/bin/riscv-trace-dump"
ECDSA_MAX_STEPS = 8_000_000  # ECDSA runs ~6M steps; trace-dump default is 1M
METAL_CELL = "gated"  # RISC-V adapter is CPU-only; no RISC-V Metal prover exists


def rust_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "RUST_LOG": "info"}


def cycles_from_log(log: str) -> int | None:
    match = re.search(r"completed with (\d+) cycles", ANSI_RE.sub("", log))
    return int(match.group(1)) if match else None


def zig_prove(
    elf: Path,
    input_path: Path | None,
    warmups: int,
    samples: int,
    admission: riscv_cli_admission.Admission,
) -> dict:
    cmd = [str(ZIG_BENCH), "bench", "--elf", str(elf), "--backend", "cpu",
           "--protocol", "functional", *admission.arguments,
           "--warmups", str(warmups), "--samples", str(samples)]
    if input_path:
        cmd += ["--input", str(input_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout).strip()[-300:]}
    lines = [x for x in result.stdout.splitlines() if x.startswith("{")]
    if not lines:
        return {"error": "no report JSON"}
    report = json.loads(lines[-1])
    if (
        report.get("release_status") != admission.release_status
        or report.get("experimental") is not admission.experimental
    ):
        return {"error": "benchmark admission differs from CLI registry"}
    if report.get("verified_samples") != samples:
        return {"error": f"verified_samples={report.get('verified_samples')}"}
    return {
        "steps": report["total_steps"],
        "prove_seconds": report["mean_proving_seconds"],
        "verify_seconds": report["mean_verification_seconds"],
    }


def rust_prove(binary: Path, elf: Path, input_path: Path | None,
               warmups: int, samples: int) -> dict:
    proves, verifies, cpu_wall, cycles = [], [], [], set()
    for index in range(warmups + samples):
        cmd = [str(binary), "bench", "--elf", str(elf), "--metrics-out", "/dev/null"]
        if input_path:
            cmd += ["--input", str(input_path)]
        wall_start = dt.datetime.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=rust_env())
        wall = (dt.datetime.now() - wall_start).total_seconds()
        log = ANSI_RE.sub("", result.stdout + "\n" + result.stderr)
        if result.returncode != 0 or "Proof verified successfully" not in log:
            return {"error": log.strip()[-300:] or f"exit {result.returncode}"}
        c = cycles_from_log(log)
        if c is not None:
            cycles.add(c)
        if index >= warmups:
            phases = parse_phase_seconds(log)
            proves.append(phases["prove_seconds"])
            verifies.append(phases["verify_seconds"])
    return {
        "cycles": cycles.pop() if len(cycles) == 1 else None,
        "prove_seconds": statistics.median(proves),
        "verify_seconds": statistics.median(verifies),
    }


def zig_execute(elf: Path, input_path: Path | None, samples: int) -> dict:
    times, steps = [], set()
    for _ in range(samples):
        cmd = [str(ZIG_TRACE), "--elf", str(elf), "--output", "/dev/null",
               "--max-steps", str(ECDSA_MAX_STEPS)]
        if input_path:
            cmd += ["--input", str(input_path)]
        wall_start = dt.datetime.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        wall = (dt.datetime.now() - wall_start).total_seconds()
        if result.returncode != 0:
            return {"error": (result.stderr or result.stdout).strip()[-300:]}
        times.append(wall)
    # A second pass writing the trace lets us read the authoritative step count.
    cmd = [str(ZIG_TRACE), "--elf", str(elf), "--max-steps", str(ECDSA_MAX_STEPS)]
    if input_path:
        cmd += ["--input", str(input_path)]
    trace = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    # Fail closed on the step count. An unreadable dump used to be swallowed
    # here, and the row's only correctness check -- cycle parity against the Rust
    # lane -- is skipped when either side's count is missing, so the row then
    # reported `ok` on the strength of nothing at all.
    if trace.returncode != 0:
        return {"error": (trace.stderr or trace.stdout).strip()[-300:]}
    try:
        steps.add(json.loads(trace.stdout)["total_steps"])
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        return {"error": f"trace dump published no total_steps: {error}"}
    return {
        "steps": steps.pop(),
        "execute_seconds": statistics.median(times),
    }


def rust_execute(binary: Path, elf: Path, input_path: Path | None, samples: int) -> dict:
    times, cycles = [], set()
    for _ in range(samples):
        cmd = [str(binary), "run", "--elf", str(elf), "--metrics-out", "/dev/null"]
        if input_path:
            cmd += ["--input", str(input_path)]
        wall_start = dt.datetime.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=rust_env())
        wall = (dt.datetime.now() - wall_start).total_seconds()
        log = ANSI_RE.sub("", result.stdout + "\n" + result.stderr)
        if result.returncode != 0:
            return {"error": log.strip()[-300:]}
        c = cycles_from_log(log)
        if c is not None:
            cycles.add(c)
        times.append(wall)
    return {
        "cycles": cycles.pop() if len(cycles) == 1 else None,
        "execute_seconds": statistics.median(times),
    }


def input_for(guest: str, spec: dict, provenance: dict) -> list[tuple[str, Path | None]]:
    """Yield (label, input_path) pairs for a guest's sweep."""
    kind = spec.get("kind")
    if kind == "input_sweep":
        return [(f"{n}B", CRYPTO_DIR / "inputs" / f"msg_{n}.bin")
                for n in provenance["byte_input_sizes"]]
    if kind == "field_sweep":
        return [(f"{n}fe", CRYPTO_DIR / "inputs" / f"field_{n}.bin")
                for n in provenance["poseidon_field_widths"]]
    return [("fixed", None)]


def repository_head() -> str:
    """The commit every measuring executable must have been built from."""
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False, timeout=15,
    )
    if head.returncode != 0 or not head.stdout.strip():
        raise SystemExit("cannot read the repository HEAD to validate build provenance")
    return head.stdout.strip()


def admit_trace_executable(provenance: dict) -> dict:
    """Validate the trace dumper before it produces a single published cycle.

    Every execution row's cycle count comes from ``riscv-trace-dump``, and this
    harness took those counts on trust: nothing checked that the binary was built
    from this commit, or from a clean worktree. The provenance gate that answers
    exactly that already exists for the CSP harness, so this calls it rather than
    growing a second one -- a parallel implementation is the hazard, not the fix
    (issue #152 item 6b).

    The probe fixture is the smallest authenticated byte-input case. Its digests
    come from the committed provenance file, and ``read_trace_provenance`` refuses
    a dump whose ``source`` digests differ, so this also authenticates the ELF and
    input the harness is about to measure.
    """
    guest = provenance["guests"]["sha2_input"]
    size = min(provenance["byte_input_sizes"])
    input_name = f"msg_{size}.bin"
    # `read_trace_provenance` reads four of these fields -- the two paths it runs
    # and the two digests it holds the dump to. The rest belong to the CSP
    # harness's own expectations and are inert here; they are spelled out rather
    # than defaulted so a field gaining meaning cannot pass unnoticed.
    case = Case(
        target="sha2_input",
        input_size=size,
        input_path=CRYPTO_DIR / "inputs" / input_name,
        input_sha256=provenance["input_sha256"][input_name],
        expected_digest="",
        expected_cycles=0,
        guest_path=ROOT / guest["elf"],
        guest_sha256=guest["elf_sha256"],
        guest_bytes=0,
        uses_precompile=False,
    )
    try:
        return read_trace_provenance(
            ZIG_TRACE,
            case,
            repository_head=repository_head(),
            max_steps=ECDSA_MAX_STEPS,
            timeout=3600,
        )
    except BenchmarkError as error:
        raise SystemExit(f"trace dumper is not publishable: {error}") from error


def is_proof_size(guest: str, spec: dict, label: str) -> bool:
    if spec["eval"] == "provable":
        return True
    if spec["eval"] == "provable_single_block_only":
        return label == "128B"
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stark-v-source", required=True, type=Path)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)

    provenance = json.loads(PROVENANCE.read_text())
    if provenance["stark_v_commit"] != PINNED_COMMIT:
        raise SystemExit("crypto provenance pins a different Stark-V commit")
    rust_binary = (args.stark_v_source.resolve() / "target/release/stark-v-bench")
    if not rust_binary.exists():
        raise SystemExit("stark-v-bench missing; build --features parallel")
    for binary in (ZIG_BENCH, ZIG_TRACE):
        if not binary.exists():
            raise SystemExit(f"missing {binary}; build the Zig products first")
    try:
        admission = riscv_cli_admission.resolve(ZIG_BENCH, cwd=ROOT)
    except riscv_cli_admission.AdmissionError as error:
        raise SystemExit(f"invalid Zig applications registry: {error}") from error
    trace_provenance = admit_trace_executable(provenance)
    # Captured before the first sample so an operator sees a throttled host while
    # the run is still worth aborting, not after it finishes.
    power = power_evidence_block()
    if not power["admissible"]:
        print(f"[power] {'; '.join(power['reasons'])}", flush=True)

    rows, failures = [], 0
    for guest, spec in provenance["guests"].items():
        elf = ROOT / spec["elf"]
        for label, input_path in input_for(guest, spec, provenance):
            proof = is_proof_size(guest, spec, label)
            row = {"guest": guest, "size": label, "class": "proof" if proof else "execution",
                   "metal": METAL_CELL}
            if proof:
                zig = zig_prove(
                    elf, input_path, args.warmups, args.samples, admission,
                )
                rust = rust_prove(rust_binary, elf, input_path, args.warmups, args.samples)
            else:
                zig = zig_execute(elf, input_path, args.samples)
                rust = rust_execute(rust_binary, elf, input_path, args.samples)
            problems = [f"{side}: {lane['error']}"
                        for side, lane in (("zig", zig), ("rust", rust)) if "error" in lane]
            zsteps = zig.get("steps")
            rcycles = rust.get("cycles")
            # Cycle parity is this row's only correctness evidence, so a missing
            # count is a failure rather than a reason to skip the comparison. Read
            # as `is not None` guards, an absent count on either lane silently
            # turned the check off and still printed `ok`.
            if not problems and (zsteps is None or rcycles is None):
                problems.append(f"missing cycle evidence zig={zsteps} rust={rcycles}")
            elif not problems and zsteps != rcycles:
                problems.append(f"cycle mismatch zig={zsteps} rust={rcycles}")
            row["zig"], row["rust"] = zig, rust
            if problems:
                row["status"], row["problems"] = "failed", problems
                failures += 1
                summary = "; ".join(problems)[:150]
            else:
                row["status"] = "ok"
                if proof:
                    row["zig_over_rust_prove"] = zig["prove_seconds"] / rust["prove_seconds"]
                    summary = f"prove z/r={row['zig_over_rust_prove']:.3f}"
                else:
                    row["zig_over_rust_execute"] = zig["execute_seconds"] / rust["execute_seconds"]
                    summary = f"exec z/r={row['zig_over_rust_execute']:.3f} steps={zsteps}"
            print(f"{guest:14s} {label:5s} {row['class']:9s} {row['status']:6s} {summary}", flush=True)
            rows.append(row)

    report = {
        "schema": SCHEMA,
        "stark_v_commit": PINNED_COMMIT,
        "zig_release_status": admission.release_status,
        "zig_experimental": admission.experimental,
        "pcs_profile": "functional == pinned PcsConfig::default()",
        "metal_note": "RISC-V adapter is CPU-only (no RISC-V Metal prover on either "
                      "lane); native CPU-vs-Metal lives in the native proof matrix",
        "min_rust_cpu_wall_ratio": MIN_RUST_PARALLELISM,
        "host_environment": collect_host_environment(
            args.stark_v_source.resolve(), power_conditions=power,
        ),
        # The executable behind every execution row's cycle count, validated
        # against this commit before the first sample.
        "trace_provenance": trace_provenance,
        "warmups": args.warmups,
        "samples": args.samples,
        "failure_count": failures,
        "rows": rows,
    }
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"report: {args.report_out} ({failures} failures)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
