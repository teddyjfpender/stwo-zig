const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module (importable by downstream packages).
    _ = b.addModule("stwo", .{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests.
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Expanded compile/test graph gate.
    const deep_gate_cmd = b.addSystemCommand(&.{ "zig", "test", "src/stwo_deep.zig" });
    const deep_gate_step = b.step("deep-gate", "Run expanded deep graph coverage");
    deep_gate_step.dependOn(&deep_gate_cmd.step);

    // Deterministic parity vectors gate (Rust upstream -> JSON fixtures).
    const vectors_fields_cmd = b.addSystemCommand(&.{ "python3", "scripts/parity_fields.py", "--skip-zig" });
    const vectors_constraint_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_constraint_expr.py",
        "--skip-zig",
    });
    vectors_constraint_cmd.step.dependOn(&vectors_fields_cmd.step);
    const vectors_air_derive_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_air_derive.py",
        "--skip-zig",
    });
    vectors_air_derive_cmd.step.dependOn(&vectors_constraint_cmd.step);
    const vectors_step = b.step("vectors", "Validate committed parity vectors");
    vectors_step.dependOn(&vectors_air_derive_cmd.step);

    // Cross-language interoperability gate (true Rust<->Zig proof exchange + tamper rejection).
    const interop_cmd = b.addSystemCommand(&.{ "python3", "scripts/e2e_interop.py" });
    const interop_step = b.step("interop", "Run interoperability harness (Rust <-> Zig proof exchange)");
    interop_step.dependOn(&interop_cmd.step);

    // Prove/prove_ex checkpoint parity gate (deterministic proof-byte parity + tamper rejection).
    const prove_checkpoints_cmd = b.addSystemCommand(&.{ "python3", "scripts/prove_checkpoints.py" });
    const prove_checkpoints_step = b.step(
        "prove-checkpoints",
        "Run prove/prove_ex checkpoint harness (Rust -> Zig/Rust verification)",
    );
    prove_checkpoints_step.dependOn(&prove_checkpoints_cmd.step);

    // Benchmark smoke gate with deterministic short workloads.
    const bench_smoke_cmd = b.addSystemCommand(&.{ "python3", "scripts/benchmark_smoke.py" });
    const bench_smoke_step = b.step("bench-smoke", "Run benchmark smoke harness and emit report");
    bench_smoke_step.dependOn(&bench_smoke_cmd.step);

    // Benchmark strict gate with medium workloads enabled.
    const bench_strict_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/benchmark_smoke.py",
        "--include-medium",
    });
    const bench_strict_step = b.step("bench-strict", "Run strict benchmark harness (base + medium workloads)");
    bench_strict_step.dependOn(&bench_strict_cmd.step);

    // Profiling smoke gate with coarse wall-clock and peak-RSS collection.
    const profile_smoke_cmd = b.addSystemCommand(&.{ "python3", "scripts/profile_smoke.py" });
    const profile_smoke_step = b.step("profile-smoke", "Run profiling smoke harness and emit report");
    profile_smoke_step.dependOn(&profile_smoke_cmd.step);

    // Freestanding verifier profile compile check.
    const std_shims_smoke_cmd = b.addSystemCommand(&.{
        "zig",
        "build-lib",
        "src/std_shims_freestanding.zig",
        "-target",
        "wasm32-freestanding",
        "-O",
        "ReleaseSmall",
        "-femit-bin=/tmp/stwo-zig-std-shims-verifier.wasm",
    });
    const std_shims_smoke_step = b.step(
        "std-shims-smoke",
        "Build freestanding verifier profile shim (wasm32-freestanding)",
    );
    std_shims_smoke_step.dependOn(&std_shims_smoke_cmd.step);

    // Canonical release evidence manifest generator.
    const release_evidence_cmd = b.addSystemCommand(&.{
        "python3",
        "scripts/release_evidence.py",
        "--gate-mode",
        "strict",
    });
    const release_evidence_step = b.step(
        "release-evidence",
        "Generate canonical release evidence manifest (vectors/reports/release_evidence.json)",
    );
    release_evidence_step.dependOn(&release_evidence_cmd.step);

    // Formatting gate.
    const fmt_cmd = b.addSystemCommand(&.{ "zig", "fmt", "--check", "build.zig", "src", "tools" });
    const fmt_step = b.step("fmt", "Check formatting (zig fmt --check)");
    fmt_step.dependOn(&fmt_cmd.step);

    // Deterministic release gate sequence:
    // fmt -> test -> vectors -> interop -> bench-smoke -> profile-smoke
    const rg_fmt = b.addSystemCommand(&.{ "zig", "fmt", "--check", "build.zig", "src", "tools" });
    const rg_test = b.addSystemCommand(&.{ "zig", "test", "src/stwo.zig" });
    rg_test.step.dependOn(&rg_fmt.step);
    const rg_vectors_fields = b.addSystemCommand(&.{ "python3", "scripts/parity_fields.py", "--skip-zig" });
    rg_vectors_fields.step.dependOn(&rg_test.step);
    const rg_vectors_constraint = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_constraint_expr.py",
        "--skip-zig",
    });
    rg_vectors_constraint.step.dependOn(&rg_vectors_fields.step);
    const rg_vectors_air_derive = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_air_derive.py",
        "--skip-zig",
    });
    rg_vectors_air_derive.step.dependOn(&rg_vectors_constraint.step);
    const rg_interop = b.addSystemCommand(&.{ "python3", "scripts/e2e_interop.py" });
    rg_interop.step.dependOn(&rg_vectors_air_derive.step);
    const rg_bench = b.addSystemCommand(&.{ "python3", "scripts/benchmark_smoke.py" });
    rg_bench.step.dependOn(&rg_interop.step);
    const rg_profile = b.addSystemCommand(&.{ "python3", "scripts/profile_smoke.py" });
    rg_profile.step.dependOn(&rg_bench.step);

    const release_gate_step = b.step(
        "release-gate",
        "Run release gate sequence (fmt -> test -> vectors -> interop -> bench-smoke -> profile-smoke)",
    );
    release_gate_step.dependOn(&rg_profile.step);

    // Strict release gate sequence:
    // fmt -> test -> deep-gate -> vectors -> interop -> prove-checkpoints -> bench-strict -> profile-smoke -> std-shims-smoke
    const rgs_fmt = b.addSystemCommand(&.{ "zig", "fmt", "--check", "build.zig", "src", "tools" });
    const rgs_test = b.addSystemCommand(&.{ "zig", "test", "src/stwo.zig" });
    rgs_test.step.dependOn(&rgs_fmt.step);
    const rgs_deep = b.addSystemCommand(&.{ "zig", "test", "src/stwo_deep.zig" });
    rgs_deep.step.dependOn(&rgs_test.step);
    const rgs_vectors_fields = b.addSystemCommand(&.{ "python3", "scripts/parity_fields.py", "--skip-zig" });
    rgs_vectors_fields.step.dependOn(&rgs_deep.step);
    const rgs_vectors_constraint = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_constraint_expr.py",
        "--skip-zig",
    });
    rgs_vectors_constraint.step.dependOn(&rgs_vectors_fields.step);
    const rgs_vectors_air_derive = b.addSystemCommand(&.{
        "python3",
        "scripts/parity_air_derive.py",
        "--skip-zig",
    });
    rgs_vectors_air_derive.step.dependOn(&rgs_vectors_constraint.step);
    const rgs_interop = b.addSystemCommand(&.{ "python3", "scripts/e2e_interop.py" });
    rgs_interop.step.dependOn(&rgs_vectors_air_derive.step);
    const rgs_prove_checkpoints = b.addSystemCommand(&.{ "python3", "scripts/prove_checkpoints.py" });
    rgs_prove_checkpoints.step.dependOn(&rgs_interop.step);
    const rgs_bench = b.addSystemCommand(&.{
        "python3",
        "scripts/benchmark_smoke.py",
        "--include-medium",
    });
    rgs_bench.step.dependOn(&rgs_prove_checkpoints.step);
    const rgs_profile = b.addSystemCommand(&.{ "python3", "scripts/profile_smoke.py" });
    rgs_profile.step.dependOn(&rgs_bench.step);
    const rgs_std_shims = b.addSystemCommand(&.{
        "zig",
        "build-lib",
        "src/std_shims_freestanding.zig",
        "-target",
        "wasm32-freestanding",
        "-O",
        "ReleaseSmall",
        "-femit-bin=/tmp/stwo-zig-std-shims-verifier.wasm",
    });
    rgs_std_shims.step.dependOn(&rgs_profile.step);
    const rgs_evidence = b.addSystemCommand(&.{
        "python3",
        "scripts/release_evidence.py",
        "--gate-mode",
        "strict",
    });
    rgs_evidence.step.dependOn(&rgs_std_shims.step);

    const release_gate_strict_step = b.step(
        "release-gate-strict",
        "Run strict release gate sequence (fmt -> test -> deep-gate -> vectors -> interop -> prove-checkpoints -> bench-strict -> profile-smoke -> std-shims-smoke -> release-evidence)",
    );
    release_gate_strict_step.dependOn(&rgs_evidence.step);
}
