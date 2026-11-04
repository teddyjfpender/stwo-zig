const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dep_opts = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", dep_opts).module("stwo_core");
    const engine = b.dependency("stwo_prover_engine", dep_opts).module("stwo_prover_engine");
    // Challenge field (security.md section 10): qm31 (default, |F| = p^4) or
    // om31 (degree 8, |F| = p^8; the >=128-bit levels). A build-time choice:
    // the default build is byte-for-byte the qm31 protocol.
    const challenge = b.option(Challenge, "challenge", "Challenge field: qm31 (default) or om31 (degree 8, 128-bit levels)") orelse .qm31;
    const use_metal = (b.option(bool, "metal", "Build the Metal GPU path (default: on for macOS)") orelse (target.result.os.tag == .macos)) and challenge == .qm31;
    const topts = b.addOptions();
    topts.addOption(u32, "challenge_degree", if (challenge == .om31) 8 else 4);

    const tensor = b.addModule("stwo_tensor", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    tensor.addImport("stwo_core", core);
    tensor.addImport("stwo_prover_engine", engine);
    tensor.addOptions("tensor_options", topts);

    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this string") orelse &.{};
    const tests = b.addTest(.{ .root_module = tensor, .filters = test_filters });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run tensor frontend tests").dependOn(&run_tests.step);

    const opts = b.addOptions();
    opts.addOption(bool, "metal", use_metal);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    bench_mod.addImport("stwo_tensor", tensor);
    bench_mod.addImport("stwo_core", core);
    bench_mod.addOptions("build_options", opts);

    if (use_metal) {
        const metal = metalModule(b, target, optimize, tensor);
        metal.addImport("stwo_prover_engine", engine);
        bench_mod.addImport("stwo_tensor_metal", metal);
        const mt_mod = b.createModule(.{
            .root_source_file = b.path("metal/test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mt_mod.addImport("stwo_tensor", tensor);
        mt_mod.addImport("stwo_tensor_metal", metal);
        mt_mod.addImport("stwo_prover_engine", engine);
        const mt = b.addTest(.{ .root_module = mt_mod });
        const run_mt = b.addRunArtifact(mt);
        run_mt.has_side_effects = true;
        b.step("test-metal", "Metal GPU path: CPU/GPU bit-identity tests").dependOn(&run_mt.step);
    }

    const bench = b.addExecutable(.{ .name = if (challenge == .om31) "tensor-bench-om31" else "tensor-bench", .root_module = bench_mod });
    b.installArtifact(bench);
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |args| run_bench.addArgs(args);
    b.step("bench", "Run tensor benchmarks").dependOn(&run_bench.step);

    // tensor-accuracy: replays a quantized model file through lm.buildModel
    // (scripts/tensor_accuracy.py), optionally calibrates / proves requests
    const acc_mod = b.createModule(.{ .root_source_file = b.path("accuracy_cli.zig"), .target = target, .optimize = optimize });
    acc_mod.addImport("stwo_tensor", tensor);
    const acc_exe = b.addExecutable(.{ .name = "tensor-accuracy", .root_module = acc_mod });
    b.installArtifact(acc_exe);

    // tensor-verify: verifies statement / key / proof files (wire.zig format)
    const verify_mod = b.createModule(.{ .root_source_file = b.path("verify_cli.zig"), .target = target, .optimize = optimize });
    verify_mod.addImport("stwo_tensor", tensor);
    const verify_exe = b.addExecutable(.{ .name = if (challenge == .om31) "tensor-verify-om31" else "tensor-verify", .root_module = verify_mod });
    b.installArtifact(verify_exe);
    const run_verify = b.addRunArtifact(verify_exe);
    if (b.args) |args| run_verify.addArgs(args);
    b.step("verify", "Verify tensor proof files: zig build verify -- <dir>").dependOn(&run_verify.step);

    // Lean formal proofs (formal/tensor-frontend): lake build + axiom audit +
    // the exact security re-check. Needs elan/lake on PATH; not part of `test`.
    const run_lean = b.addSystemCommand(&.{"scripts/check.sh"});
    run_lean.setCwd(b.path("../../formal/tensor-frontend"));
    b.step("lean", "Build and audit the Lean proofs (formal/tensor-frontend)").dependOn(&run_lean.step);
}

const Challenge = enum { qm31, om31 };

/// The Metal module compiles the stwo-zig Metal backend's MSL sources (field,
/// Blake2s, circle transform, commitment kernels) together with the tensor
/// kernels; the sources are embedded through a generated module.
fn metalModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, tensor: *std.Build.Module) *std.Build.Module {
    const shader_files = [_][2][]const u8{
        .{ "base.metal", "../backends/metal/shaders/include/base.metal" },
        .{ "m31.metal", "../backends/metal/shaders/include/m31.metal" },
        .{ "extension_fields.metal", "../backends/metal/shaders/include/extension_fields.metal" },
        .{ "blake2s.metal", "../backends/metal/shaders/include/blake2s.metal" },
        .{ "blake3.metal", "../backends/metal/shaders/include/blake3.metal" },
        .{ "merkle.metal", "../backends/metal/shaders/include/merkle.metal" },
        .{ "poseidon2_m31.metal", "../backends/metal/shaders/include/poseidon2_m31.metal" },
        .{ "circle.metal", "../backends/metal/shaders/include/circle.metal" },
        .{ "circle_transform.metal", "../backends/metal/shaders/core/circle_transform.metal" },
        .{ "circle_transform_wide.metal", "../backends/metal/shaders/core/circle_transform_wide.metal" },
        .{ "commitments.metal", "../backends/metal/shaders/core/commitments.metal" },
        .{ "tensor_kernels.metal", "metal/kernels.metal" },
    };
    const wf = b.addWriteFiles();
    var src: std.ArrayList(u8) = .empty;
    src.appendSlice(b.allocator, "pub const source: [:0]const u8 = \"#define STWO_ZIG_AMALGAMATED 1\\n\"") catch @panic("OOM");
    for (shader_files) |sf| {
        _ = wf.addCopyFile(b.path(sf[1]), sf[0]);
        src.appendSlice(b.allocator, b.fmt(" ++ @embedFile(\"{s}\") ++ \"\\n\"", .{sf[0]})) catch @panic("OOM");
    }
    src.appendSlice(b.allocator, ";\n") catch @panic("OOM");
    const shaders_zig = wf.add("shaders.zig", src.items);
    const shaders = b.createModule(.{ .root_source_file = shaders_zig, .target = target, .optimize = optimize });

    const metal = b.addModule("stwo_tensor_metal", .{
        .root_source_file = b.path("metal/gpu.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    metal.addImport("stwo_tensor", tensor);
    metal.addImport("tensor_metal_shaders", shaders);
    metal.addCSourceFile(.{ .file = b.path("metal/runtime.m"), .flags = &.{ "-fobjc-arc", "-fblocks" } });
    metal.linkFramework("Foundation", .{});
    metal.linkFramework("Metal", .{});
    metal.linkSystemLibrary("objc", .{});
    return metal;
}
