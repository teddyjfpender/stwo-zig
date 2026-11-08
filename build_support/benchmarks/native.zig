const std = @import("std");

pub const Context = struct {
    b: *std.Build,
};

pub fn addProducts(context: Context) void {
    const b = context.b;

    const holistic_cpu = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "benchmark-native-cpu",
        "-Doptimize=ReleaseFast",
    });
    const holistic_metal = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "native-proof-bench-metal",
        "-Doptimize=ReleaseFast",
    });
    holistic_metal.step.dependOn(&holistic_cpu.step);
    const holistic_smoke = b.addSystemCommand(&.{
        "python3",
        "scripts/native/native_proof_matrix.py",
        "--suite",
        "holistic",
        "--protocol",
        "smoke",
        "--warmups",
        "0",
        "--samples",
        "1",
        "--cooldown-seconds",
        "0",
        "--allow-non-headline",
        "--output-dir",
        "zig-out/native-proof-holistic-smoke",
    });
    holistic_smoke.step.dependOn(&holistic_metal.step);
    const holistic_smoke_step = b.step(
        "bench-native-holistic-smoke",
        "Run cheap non-headline CPU/Metal parity over the holistic native suite",
    );
    holistic_smoke_step.dependOn(&holistic_smoke.step);

    // Benchmark smoke gate with deterministic short workloads.
    const bench_smoke_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/benchmark_smoke.py" });
    const bench_smoke_step = b.step("bench-smoke", "Run benchmark smoke harness and emit report");
    bench_smoke_step.dependOn(&bench_smoke_cmd.step);

    // Targeted kernel benchmark gate for eval_at_point/folding/fft hotspots.
    const bench_kernels_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/benchmark_kernels.py" });
    const bench_kernels_step = b.step("bench-kernels", "Run targeted kernel benchmark harness");
    bench_kernels_step.dependOn(&bench_kernels_cmd.step);

    // Benchmark strict gate with medium workloads enabled and stabilized sampling.
    const bench_strict_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/benchmark_smoke.py",
        "--include-medium",
        "--warmups",
        "3",
        "--repeats",
        "11",
    });
    const bench_strict_step = b.step("bench-strict", "Run strict benchmark harness (base + medium workloads, stabilized samples)");
    bench_strict_step.dependOn(&bench_strict_cmd.step);

    // Optimization-track benchmark gate (native tuned, non-release-authoritative).
    const bench_opt_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/benchmark_smoke.py",
        "--include-medium",
        "--warmups",
        "3",
        "--repeats",
        "11",
        "--max-zig-over-rust",
        "10.0",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--report-label",
        "optimization_track",
        "--report-out",
        "vectors/reports/benchmark_opt_report.json",
    });
    const bench_opt_step = b.step("bench-opt", "Run optimization-track benchmark harness (native CPU)");
    bench_opt_step.dependOn(&bench_opt_cmd.step);

    const bench_opt_binary_codec_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/benchmark_smoke.py",
        "--include-medium",
        "--warmups",
        "3",
        "--repeats",
        "11",
        "--max-zig-over-rust",
        "10.0",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--zig-bench-proof-codec",
        "binary",
        "--merkle-workers",
        "12",
        "--report-label",
        "optimization_track_binary_codec",
        "--report-out",
        "vectors/reports/benchmark_opt_binary_codec_report.json",
    });
    const bench_opt_binary_codec_step = b.step(
        "bench-opt-binary-codec",
        "Run optimization-track benchmark with binary internal proof codec (non-default)",
    );
    bench_opt_binary_codec_step.dependOn(&bench_opt_binary_codec_cmd.step);

    // Large contrast benchmark (adds long-running workload slices).
    const bench_contrast_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/benchmark_smoke.py",
        "--include-medium",
        "--include-large",
        "--warmups",
        "2",
        "--repeats",
        "7",
        "--max-zig-over-rust",
        "10.0",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--report-label",
        "benchmark_contrast",
        "--report-out",
        "vectors/reports/benchmark_contrast_report.json",
    });
    const bench_contrast_step = b.step(
        "bench-contrast",
        "Run heavy contrast benchmark harness (wide_fibonacci fib100/fib500/fib1000 + plonk_large)",
    );
    bench_contrast_step.dependOn(&bench_contrast_cmd.step);

    const bench_contrast_long_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/benchmark_smoke.py",
        "--include-medium",
        "--include-large",
        "--include-long",
        "--warmups",
        "1",
        "--repeats",
        "5",
        "--max-zig-over-rust",
        "10.0",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--merkle-pool-reuse-workloads",
        "blake_deep,poseidon_deep,wide_fibonacci_fib2000",
        "--report-label",
        "benchmark_contrast_long",
        "--report-out",
        "vectors/reports/benchmark_contrast_long_report.json",
    });
    const bench_contrast_long_step = b.step(
        "bench-contrast-long",
        "Run long contrast benchmark harness (fib2000/fib5000 + deep poseidon/blake)",
    );
    bench_contrast_long_step.dependOn(&bench_contrast_long_cmd.step);

    // Full benchmark matrix gate (11 upstream family labels).
    const bench_full_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/benchmark_full.py" });
    const bench_targeted_compare_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/compare_optimization.py",
        "--baseline",
        "vectors/reports/optimization_baseline_wave4.json",
        "--benchmark-report",
        "vectors/reports/benchmark_smoke_report.json",
        "--benchmark-full-report",
        "vectors/reports/benchmark_full_report.json",
        "--profile-report",
        "vectors/reports/profile_smoke_report.json",
        "--kernel-report",
        "vectors/reports/benchmark_kernels_report.json",
        "--max-prove-regression-pct",
        "100.0",
        "--max-verify-regression-pct",
        "100.0",
        "--max-rss-regression-pct",
        "100.0",
        "--max-zig-profile-regression-pct",
        "100.0",
        "--max-kernel-regression-pct",
        "100.0",
        "--kernel-min-baseline-seconds",
        "0.01",
        "--kernel-min-absolute-delta-seconds",
        "0.002",
        "--max-target-family-regression-pct",
        "3.0",
        "--max-target-family-rss-regression-pct",
        "3.0",
    });
    bench_targeted_compare_cmd.step.dependOn(&bench_full_cmd.step);
    bench_targeted_compare_cmd.step.dependOn(&bench_strict_cmd.step);
    bench_targeted_compare_cmd.step.dependOn(&bench_kernels_cmd.step);
    const bench_targeted_step = b.step(
        "bench-targeted-families",
        "Run full benchmark and block regressions on eval_at_point/eval_at_point_by_folding/fft",
    );
    bench_targeted_step.dependOn(&bench_targeted_compare_cmd.step);
    const bench_pages_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/benchmark_pages.py" });
    const bench_pages_step = b.step(
        "bench-pages",
        "Build the formal benchmark site catalog from committed immutable history",
    );
    bench_pages_step.dependOn(&bench_pages_cmd.step);
    const bench_full_step = b.step(
        "bench-full",
        "Run the full family and long example benchmark suites",
    );
    bench_full_step.dependOn(&bench_full_cmd.step);
    bench_full_step.dependOn(&bench_contrast_long_cmd.step);
    const bench_pages_validate_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/benchmark_pages.py", "--validate" });
    const bench_pages_validate_step = b.step("bench-pages-validate", "Validate static benchmark pages assets are current");
    bench_pages_validate_step.dependOn(&bench_pages_validate_cmd.step);

    // Profiling smoke gate with coarse wall-clock and peak-RSS collection.
    const profile_smoke_cmd = b.addSystemCommand(&.{ "python3", "scripts/bench/profile_smoke.py" });
    const profile_smoke_step = b.step("profile-smoke", "Run profiling smoke harness and emit report");
    profile_smoke_step.dependOn(&profile_smoke_cmd.step);
    bench_targeted_compare_cmd.step.dependOn(&profile_smoke_cmd.step);

    // Optimization-track profiling gate (native tuned, non-release-authoritative).
    const profile_opt_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/profile_smoke.py",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--report-label",
        "optimization_track",
        "--report-out",
        "vectors/reports/profile_opt_report.json",
    });
    const profile_opt_step = b.step("profile-opt", "Run optimization-track profile harness (native CPU)");
    profile_opt_step.dependOn(&profile_opt_cmd.step);

    const profile_contrast_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/profile_smoke.py",
        "--include-large",
        "--repeats",
        "1",
        "--sample-duration-seconds",
        "1",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--report-label",
        "profile_contrast",
        "--report-out",
        "vectors/reports/profile_contrast_report.json",
    });
    const profile_contrast_step = b.step(
        "profile-contrast",
        "Run larger contrast profile harness (adds fib500/plonk_deep hotspots)",
    );
    profile_contrast_step.dependOn(&profile_contrast_cmd.step);

    const profile_contrast_long_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/profile_smoke.py",
        "--include-large",
        "--include-long",
        "--repeats",
        "1",
        "--sample-duration-seconds",
        "2",
        "--zig-opt-mode",
        "ReleaseFast",
        "--zig-cpu",
        "native",
        "--merkle-workers",
        "12",
        "--merkle-pool-reuse-workloads",
        "blake_deep,poseidon_deep,wide_fibonacci_fib2000",
        "--report-label",
        "profile_contrast_long",
        "--report-out",
        "vectors/reports/profile_contrast_long_report.json",
    });
    const profile_contrast_long_step = b.step(
        "profile-contrast-long",
        "Run long contrast profile harness (adds fib2000/fib5000 + deep poseidon/blake hotspots)",
    );
    profile_contrast_long_step.dependOn(&profile_contrast_long_cmd.step);

    // Deterministic deep-workload soak for 2/4/8 Merkle workers with opt-in pool reuse.
    const merkle_worker_stress_cmd = b.addSystemCommand(&.{ "python3", "scripts/interop/merkle_worker_stress.py" });
    const merkle_worker_stress_step = b.step(
        "merkle-worker-stress",
        "Run deterministic deep workload stress checks for opt-in Merkle pool reuse (2/4/8 workers)",
    );
    merkle_worker_stress_step.dependOn(&merkle_worker_stress_cmd.step);

    // Optimization acceptance gate against frozen baseline (additive to strict conformance gate).
    const opt_compare_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/bench/compare_optimization.py",
        "--baseline",
        "vectors/reports/optimization_baseline_wave4.json",
        "--benchmark-report",
        "vectors/reports/benchmark_smoke_report.json",
        "--benchmark-full-report",
        "vectors/reports/benchmark_full_report.json",
        "--profile-report",
        "vectors/reports/profile_smoke_report.json",
        "--kernel-report",
        "vectors/reports/benchmark_kernels_report.json",
        "--max-prove-regression-pct",
        "10.0",
        "--max-verify-regression-pct",
        "12.0",
        "--max-rss-regression-pct",
        "5.0",
        "--max-zig-profile-regression-pct",
        "15.0",
        "--max-kernel-regression-pct",
        "18.0",
        "--kernel-min-baseline-seconds",
        "0.01",
        "--kernel-min-absolute-delta-seconds",
        "0.002",
        "--max-target-family-regression-pct",
        "14.0",
        "--max-target-family-rss-regression-pct",
        "80.0",
    });
    opt_compare_cmd.step.dependOn(&bench_strict_cmd.step);
    opt_compare_cmd.step.dependOn(&profile_smoke_cmd.step);
    opt_compare_cmd.step.dependOn(&bench_kernels_cmd.step);
    opt_compare_cmd.step.dependOn(&bench_full_cmd.step);
    opt_compare_cmd.step.dependOn(&merkle_worker_stress_cmd.step);
    opt_compare_cmd.step.dependOn(&bench_opt_cmd.step);
    opt_compare_cmd.step.dependOn(&profile_opt_cmd.step);
    const opt_gate_step = b.step(
        "opt-gate",
        "Run optimization acceptance gate (bench/profile + baseline comparator)",
    );
    opt_gate_step.dependOn(&opt_compare_cmd.step);
}
