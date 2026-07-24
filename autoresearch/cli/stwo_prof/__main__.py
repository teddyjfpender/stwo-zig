"""stwo-prof command surface. Companion skills document the methodology."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stwo_perf import ansi

from . import __version__, cudatools, metaltools, scaffold, zigtools


def _fail(message: str) -> int:
    print(f"{ansi.style('error:', 'red', 'bold')} {message}", file=sys.stderr)
    return 1


def _panel(title: str, data: dict, keys: list[tuple[str, str]]) -> None:
    pairs = []
    for label, key in keys:
        value = data.get(key)
        if value is not None:
            pairs.append((label, f"{value:,.4g}" if isinstance(value, float) else str(value)))
    print(ansi.kv_panel(title, pairs))


def cmd_zig_isolate(args) -> int:
    source = Path(args.source) if args.source else None
    imports = {}
    for spec in args.imports or []:
        name, _, path = spec.partition("=")
        if not path:
            return _fail(f"--import expects name=path, got {spec!r}")
        imports[name] = path
    dest = scaffold.isolate_zig(args.name, source, imports=imports or None)
    print(f"{ansi.OK} scratch harness: {dest}")
    wired = scaffold.workload_imports(dest)
    if wired:
        for mod, path in sorted(wired.items()):
            print(f"  @import(\"{mod}\") -> {path}")
        print("  the workload profiles LIVE repo code — no copy, no drift")
    print(f"  edit {dest}/workload.zig (contract in the file header), then:")
    print(f"  stwo-prof zig run {args.name}")
    return 0


def cmd_zig_run(args) -> int:
    bench = scaffold.resolve(args.name)
    summary = zigtools.run_counters(bench, iters=args.iters, rounds=args.rounds,
                                    debug=args.debug)
    _panel(f"zig counters · {bench.name}", summary, [
        ("ns/op (median)", "ns_per_op"),
        ("ns/op (min)", "ns_per_op_min"),
        ("instructions/op", "instructions_per_op"),
        ("cycles/op", "cycles_per_op"),
        ("IPC", "ipc"),
        ("energy/round (nJ)", "energy_nj_median_round"),
        ("peak footprint (B)", "peak_footprint_bytes"),
    ])
    if "note" in summary:
        print(ansi.style(f"  {summary['note']}", "yellow"))
    if args.json:
        out = bench / "counters.json"
        out.write_text(json.dumps(summary, indent=1) + "\n")
        print(ansi.style(f"  written to {out}", "dim"))
    return 0


def cmd_zig_compare(args) -> int:
    bench_a, bench_b = scaffold.resolve(args.a), scaffold.resolve(args.b)
    result = zigtools.compare(bench_a, bench_b, iters=args.iters, rounds=args.rounds)
    print(ansi.rule(f"A/B · {args.a} vs {args.b}"))
    ratio = result["wall_ratio_b_over_a"]
    lo, hi = result["wall_ratio_ci95"]
    verdict = "B faster" if hi < 1.0 else ("A faster" if lo > 1.0 else "no verdict (CI spans 1.0)")
    print(f"  wall  B/A {ansi.ratio(ratio)}  CI95 [{lo}, {hi}]  → {verdict}")
    if "instruction_ratio_b_over_a" in result:
        print(f"  instr B/A {ansi.ratio(result['instruction_ratio_b_over_a'])}"
              f"   cycles B/A {ansi.ratio(result['cycle_ratio_b_over_a'])}")
    print(ansi.style(
        f"  A {result['a_ns_per_op']:.3f} ns/op · B {result['b_ns_per_op']:.3f} ns/op", "dim"))
    if args.json:
        out = bench_a / f"compare-vs-{bench_b.name}.json"
        out.write_text(json.dumps(result, indent=1) + "\n")
        print(ansi.style(f"  written to {out}", "dim"))
    return 0


def cmd_zig_asm(args) -> int:
    summary = zigtools.asm_summary(scaffold.resolve(args.name), args.symbol)
    ranked = sorted(summary["symbols"].items(), key=lambda kv: -kv[1]["instructions"])
    hidden = 0
    if not args.all:
        hidden = sum(1 for _, s in ranked if s["std"])
        ranked = [(n, s) for n, s in ranked if not s["std"]]
    rows = [
        [name, str(s["instructions"]), f"{s['neon_pct']}%", str(s["branches"]), str(s["memory"])]
        for name, s in ranked
    ][:args.top]
    print(ansi.table(["symbol", "instrs", "neon", "branches", "mem"], rows, aligns="lrrrr"))
    if hidden:
        print(ansi.style(f"  {hidden} std/runtime symbols hidden (--all to show)", "dim"))
    print(ansi.style(f"  full listing: {summary['asm_file']}", "dim"))
    if args.json:
        out = scaffold.resolve(args.name) / "asm.json"
        out.write_text(json.dumps(summary, indent=1) + "\n")
        print(ansi.style(f"  written to {out}", "dim"))
    return 0


def cmd_zig_sample(args) -> int:
    report = zigtools.sample_stacks(scaffold.resolve(args.name),
                                    seconds=args.seconds, iters=args.iters)
    out = scaffold.resolve(args.name) / "sample.txt"
    out.write_text(report)
    frames = zigtools.sample_hot_frames(report, top=args.top)
    if frames:
        rows = [[f["symbol"], str(f["samples"]), f"{f['pct_of_run']}%"] for f in frames]
        print(ansi.table(["frame (inclusive)", "samples", "of run"], rows, aligns="lrr"))
    else:
        print(ansi.style("  no bench frames captured — raise --iters so the "
                         "workload outlives the sampler", "yellow"))
    print(f"{ansi.OK} full stack report: {out}")
    if args.json:
        jout = scaffold.resolve(args.name) / "sample.json"
        jout.write_text(json.dumps({"hot_frames": frames}, indent=1) + "\n")
        print(ansi.style(f"  written to {jout}", "dim"))
    return 0


def cmd_metal_isolate(args) -> int:
    source = Path(args.source) if args.source else None
    dest = scaffold.isolate_metal(args.name, source)
    print(f"{ansi.OK} scratch kernel dir: {dest}")
    print(f"  edit {dest}/kernel.metal, then:")
    print(f"  stwo-prof metal run {args.name} --entry <kernel name>")
    return 0


def cmd_metal_run(args) -> int:
    bench = scaffold.resolve(args.name)
    kernel = bench / "kernel.metal" if bench.is_dir() else bench
    if args.sweep_tg:
        return _metal_sweep(bench, kernel, args)
    result = metaltools.run_kernel(kernel, args.entry, grid=args.grid, tg=args.tg,
                                   iters=args.iters, buffers=args.buffers)
    _panel(f"metal · {args.entry}", result, [
        ("GPU ms (median)", "gpu_ms_median"),
        ("GPU ms (min)", "gpu_ms_min"),
        ("~GB/s touched", "approx_gb_per_s"),
        ("grid", "grid"),
        ("threadgroup", "threadgroup"),
    ])
    pso = result.get("pipeline", {})
    print(ansi.style(
        f"  PSO: maxThreads {pso.get('max_total_threads_per_threadgroup')} · "
        f"width {pso.get('thread_execution_width')} · "
        f"tg-mem {pso.get('static_threadgroup_memory_bytes')} B", "dim"))
    if args.json:
        out = (bench if bench.is_dir() else bench.parent) / "metal.json"
        out.write_text(json.dumps(result, indent=1) + "\n")
        print(ansi.style(f"  written to {out}", "dim"))
    return 0


def _metal_sweep(bench: Path, kernel: Path, args) -> int:
    """Threadgroup-size sweep: the skill's 'a single point is not an
    occupancy conclusion' rule, mechanized."""
    points, max_threads = [], None
    for tg in (64, 128, 256, 512, 1024):
        if max_threads is not None and tg > max_threads:
            break
        result = metaltools.run_kernel(kernel, args.entry, grid=args.grid, tg=tg,
                                       iters=args.iters, buffers=args.buffers)
        max_threads = result.get("pipeline", {}).get("max_total_threads_per_threadgroup")
        points.append({"tg": tg, "gpu_ms_median": result["gpu_ms_median"],
                       "approx_gb_per_s": result.get("approx_gb_per_s")})
    best = min(points, key=lambda p: p["gpu_ms_median"])
    rows = [[str(p["tg"]), f"{p['gpu_ms_median']:.4f}",
             f"{p['approx_gb_per_s']:.1f}" if p["approx_gb_per_s"] else "-",
             "◀ best" if p is best else ""]
            for p in points]
    print(ansi.rule(f"metal tg sweep · {args.entry} · grid {args.grid}"))
    print(ansi.table(["tg", "GPU ms", "~GB/s", ""], rows, aligns="rrrl"))
    if max_threads is not None and max_threads < 1024:
        print(ansi.style(f"  PSO caps threadgroups at {max_threads} — "
                         "register pressure is limiting occupancy", "yellow"))
    if args.json:
        out = (bench if bench.is_dir() else bench.parent) / "sweep.json"
        out.write_text(json.dumps({"entry": args.entry, "grid": args.grid,
                                   "points": points}, indent=1) + "\n")
        print(ansi.style(f"  written to {out}", "dim"))
    return 0


def cmd_metal_caps(_args) -> int:
    data = metaltools.caps()
    print(ansi.kv_panel("metal device", [(k, str(v)) for k, v in sorted(data.items())]))
    return 0


def cmd_metal_trace(args) -> int:
    output = Path(args.output)
    metaltools.trace(args.command, output)
    print(f"{ansi.OK} trace written: {output} (open in Instruments)")
    return 0


def cmd_cuda_caps(_args) -> int:
    devices = cudatools.caps()
    rows = [
        [
            device["index"],
            device["name"],
            device["compute_cap"],
            device["memory.total"],
            device["driver_version"],
        ]
        for device in devices
    ]
    print(ansi.table(
        ["device", "name", "SM", "memory MiB", "driver"],
        rows,
        aligns="rllrr",
    ))
    return 0


def cmd_cuda_systems(args) -> int:
    artifact = cudatools.systems_trace(
        args.command,
        Path(args.output),
        timeout=args.timeout,
    )
    print(f"{ansi.OK} Nsight Systems trace: {artifact}")
    return 0


def cmd_cuda_compute(args) -> int:
    artifact = cudatools.compute_profile(
        args.command,
        Path(args.output),
        kernel=args.kernel,
        set_name=args.set,
        timeout=args.timeout,
    )
    print(f"{ansi.OK} Nsight Compute report: {artifact}")
    return 0


def cmd_cuda_report(args) -> int:
    report = cudatools.load_stage_report(Path(args.report))
    timing = report["device_stage_timing_ns"]
    total = timing["total"]
    rows = []
    for stage, nanoseconds in timing.items():
        if stage == "total":
            continue
        share = 0.0 if total == 0 else nanoseconds * 100.0 / total
        rows.append([stage, f"{nanoseconds / 1e6:.4f}", f"{share:.2f}%"])
    rows.sort(key=lambda row: -float(row[1]))
    print(ansi.rule("CUDA device stage attribution"))
    print(ansi.table(["stage", "device ms", "share"], rows, aligns="lrr"))
    print(ansi.style(f"  total device timeline {total / 1e6:.4f} ms", "dim"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stwo-prof",
        description="Isolation and profiling tools for autoresearch "
                    "(skills: autoresearch/skills/{zig,metal,cuda}-profiling).",
    )
    parser.add_argument("--version", action="version", version=f"stwo-prof {__version__}")
    sub = parser.add_subparsers(dest="lane", required=True)

    zig = sub.add_parser("zig", help="CPU profiling lane")
    zs = zig.add_subparsers(dest="cmd", required=True)
    p = zs.add_parser("isolate", help="create a scratch bench harness")
    p.add_argument("name")
    p.add_argument("--from", dest="source", help="seed workload.zig from a file")
    p.add_argument("--import", dest="imports", action="append", metavar="NAME=PATH",
                   help="wire a module into the harness (e.g. stwo=/repo/src/stwo.zig) "
                        "so the workload profiles live repo code")
    p = zs.add_parser("run", help="build + run with in-process hardware counters")
    p.add_argument("name")
    p.add_argument("--iters", type=int, default=2000)
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--json", action="store_true")
    p = zs.add_parser("compare", help="ABBA A/B of two harnesses")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--iters", type=int, default=2000)
    p.add_argument("--rounds", type=int, default=7)
    p.add_argument("--json", action="store_true")
    p = zs.add_parser("asm", help="codegen summary (instrs, NEON share, branches)")
    p.add_argument("name")
    p.add_argument("--symbol")
    p.add_argument("--top", type=int, default=12)
    p.add_argument("--all", action="store_true",
                   help="include std/runtime symbols (hidden by default)")
    p.add_argument("--json", action="store_true")
    p = zs.add_parser("sample", help="stack sampling via /usr/bin/sample")
    p.add_argument("name")
    p.add_argument("--seconds", type=int, default=5)
    p.add_argument("--iters", type=int, default=2_000_000)
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", action="store_true")

    metal = sub.add_parser("metal", help="GPU profiling lane")
    ms = metal.add_subparsers(dest="cmd", required=True)
    p = ms.add_parser("isolate", help="create a scratch kernel dir")
    p.add_argument("name")
    p.add_argument("--from", dest="source")
    p = ms.add_parser("run", help="time a kernel via the generic runner")
    p.add_argument("name")
    p.add_argument("--entry", required=True)
    p.add_argument("--grid", type=int, default=1_048_576)
    p.add_argument("--tg", type=int, default=256)
    p.add_argument("--iters", type=int, default=50)
    p.add_argument("--buffers", default="f32:1048576,f32:1048576,f32:1048576")
    p.add_argument("--sweep-tg", action="store_true",
                   help="sweep threadgroup sizes 64..1024 and print the curve")
    p.add_argument("--json", action="store_true")
    ms.add_parser("caps", help="device capabilities")
    p = ms.add_parser("trace", help="Metal System Trace around a command")
    p.add_argument("--output", default="stwo-prof.trace")
    p.add_argument("command", nargs=argparse.REMAINDER)

    cuda = sub.add_parser("cuda", help="CUDA profiling lane")
    cs = cuda.add_subparsers(dest="cmd", required=True)
    cs.add_parser("caps", help="pinned CUDA device and driver capabilities")
    p = cs.add_parser("systems", help="capture CUDA/NVTX lifecycle and concurrency")
    p.add_argument("--output", default="stwo-cuda-systems.nsys-rep")
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = cs.add_parser("compute", help="capture kernel-level hardware counters")
    p.add_argument("--output", default="stwo-cuda-compute.ncu-rep")
    p.add_argument("--kernel", help="demangled kernel-name regular expression")
    p.add_argument("--set", choices=("basic", "detailed", "full"), default="basic")
    p.add_argument("--timeout", type=int, default=7200)
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = cs.add_parser("report", help="rank device stages from a proof report")
    p.add_argument("report")
    return parser


HANDLERS = {
    ("zig", "isolate"): cmd_zig_isolate,
    ("zig", "run"): cmd_zig_run,
    ("zig", "compare"): cmd_zig_compare,
    ("zig", "asm"): cmd_zig_asm,
    ("zig", "sample"): cmd_zig_sample,
    ("metal", "isolate"): cmd_metal_isolate,
    ("metal", "run"): cmd_metal_run,
    ("metal", "caps"): cmd_metal_caps,
    ("metal", "trace"): cmd_metal_trace,
    ("cuda", "caps"): cmd_cuda_caps,
    ("cuda", "systems"): cmd_cuda_systems,
    ("cuda", "compute"): cmd_cuda_compute,
    ("cuda", "report"): cmd_cuda_report,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return HANDLERS[(args.lane, args.cmd)](args)
    except KeyboardInterrupt:
        print()
        return 130
    except zigtools.ProfError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
