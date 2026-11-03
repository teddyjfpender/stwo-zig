const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dep_opts = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", dep_opts).module("stwo_core");
    const engine = b.dependency("stwo_prover_engine", dep_opts).module("stwo_prover_engine");

    const tensor = b.addModule("stwo_tensor", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    tensor.addImport("stwo_core", core);
    tensor.addImport("stwo_prover_engine", engine);

    const tests = b.addTest(.{ .root_module = tensor });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run tensor frontend tests").dependOn(&run_tests.step);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    bench_mod.addImport("stwo_tensor", tensor);
    bench_mod.addImport("stwo_core", core);
    const bench = b.addExecutable(.{ .name = "tensor-bench", .root_module = bench_mod });
    b.installArtifact(bench);
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |args| run_bench.addArgs(args);
    b.step("bench", "Run tensor benchmarks").dependOn(&run_bench.step);
}
