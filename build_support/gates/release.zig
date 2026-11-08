//! Aggregate compatibility release sequences composed from public focused gates.

const std = @import("std");

pub fn addGates(b: *std.Build, optimize: std.builtin.OptimizeMode) void {
    const build_optimize = b.fmt("-Doptimize={s}", .{@tagName(optimize)});
    const zig_optimize = b.fmt("-O{s}", .{@tagName(optimize)});
    const deep_command: []const []const u8 = if (b.graph.env_map.get("STWO_ZIG_BUILD_HELD_LOCK") != null)
        &.{ "python3", "scripts/repo/zig_protocol_test.py", "--no-lock", "src/stwo_deep.zig", zig_optimize }
    else
        &.{ "python3", "scripts/repo/zig_protocol_test.py", "src/stwo_deep.zig", zig_optimize };
    const normal = [_][]const []const u8{
        &.{ "zig", "fmt", "--check", "build.zig", "build_support", "src", "tools" },
        &.{ "python3", "scripts/repo/check_upstream_pins.py" },
        &.{ "python3", "scripts/repo/check_source_conformance.py" },
        &.{ "python3", "scripts/repo/check_package_workspace.py" },
        &.{ "python3", "scripts/repo/check_registry_parity.py" },
        &.{ "zig", "build", "test", build_optimize },
        &.{ "zig", "build", "test-riscv", build_optimize },
        &.{ "zig", "build", "test-riscv-prover", build_optimize },
        &.{ "python3", "scripts/riscv/riscv_trace_vectors.py" },
        &.{ "python3", "scripts/repo/check_api_parity.py" },
        deep_command,
        &.{ "python3", "scripts/repo/parity_fields.py", "--skip-zig" },
        &.{ "python3", "scripts/repo/parity_constraint_expr.py", "--skip-zig" },
        &.{ "python3", "scripts/repo/parity_air_derive.py", "--skip-zig" },
        &.{ "python3", "scripts/interop/e2e_interop.py", "--archive-dir", "zig-out/release-evidence/native/interop-history" },
        &.{ "python3", "scripts/bench/benchmark_smoke.py" },
        &.{ "python3", "scripts/bench/profile_smoke.py" },
    };
    addSequence(
        b,
        "release-gate",
        "Run focused compatibility release gates",
        &normal,
    );

    const strict = [_][]const []const u8{
        &.{ "zig", "fmt", "--check", "build.zig", "build_support", "src", "tools" },
        &.{ "python3", "scripts/repo/check_upstream_pins.py" },
        &.{ "python3", "scripts/repo/check_source_conformance.py", "--strict-rv64-flags" },
        &.{ "python3", "scripts/repo/check_package_workspace.py" },
        &.{ "python3", "scripts/repo/check_registry_parity.py" },
        &.{ "zig", "build", "test", build_optimize },
        &.{ "zig", "build", "test-riscv", build_optimize },
        &.{ "zig", "build", "test-riscv-prover", build_optimize },
        &.{ "python3", "scripts/riscv/riscv_trace_vectors.py" },
        &.{ "python3", "scripts/repo/check_api_parity.py" },
        deep_command,
        &.{ "python3", "scripts/repo/parity_fields.py", "--skip-zig" },
        &.{ "python3", "scripts/repo/parity_constraint_expr.py", "--skip-zig" },
        &.{ "python3", "scripts/repo/parity_air_derive.py", "--skip-zig" },
        &.{ "python3", "scripts/interop/e2e_interop.py", "--archive-dir", "zig-out/release-evidence/native/interop-history" },
        &.{ "python3", "scripts/interop/prove_checkpoints.py" },
        &.{ "python3", "scripts/bench/benchmark_smoke.py", "--include-medium", "--warmups", "3", "--repeats", "11" },
        &.{ "python3", "scripts/bench/profile_smoke.py" },
        &.{ "zig", "build-lib", "src/std_shims_freestanding.zig", "-target", "wasm32-freestanding", "-O", "ReleaseSmall", "-femit-bin=/tmp/stwo-zig-std-shims-verifier.wasm" },
        &.{ "python3", "scripts/interop/std_shims_behavior.py" },
        &.{ "python3", "scripts/release/release_evidence.py", "--gate-mode", "strict" },
    };
    addSequence(
        b,
        "release-gate-strict",
        "Run strict focused compatibility release gates",
        &strict,
    );
}

fn addSequence(
    b: *std.Build,
    name: []const u8,
    description: []const u8,
    commands: []const []const []const u8,
) void {
    var previous: ?*std.Build.Step = null;
    for (commands) |arguments| {
        const run = b.addSystemCommand(arguments);
        if (previous) |dependency| run.step.dependOn(dependency);
        previous = &run.step;
    }
    b.step(name, description).dependOn(previous.?);
}
