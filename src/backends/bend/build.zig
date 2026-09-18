const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const opts = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", opts).module("stwo_core");
    const contracts = b.dependency("stwo_backend_contracts", opts).module("stwo_backend_contracts");
    const prover = b.dependency("stwo_prover_engine", opts).module("stwo_prover_engine");
    const backend = b.addModule("stwo_bend_backend", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    backend.addImport("stwo_core", core);
    backend.addImport("stwo_prover_engine", prover);
    backend.addImport("stwo_backend_contracts", contracts);
    const tests = b.addTest(.{ .root_module = backend });
    b.step("test", "Test the experimental Bend boundary").dependOn(&b.addRunArtifact(tests).step);
    if (b.option([]const u8, "bend-executable", "Absolute path to the pinned Bend native runner")) |path| {
        const options = b.addOptions();
        options.addOption([]const u8, "executable", path);
        const integration = b.createModule(.{ .root_source_file = b.path("integration_test.zig"), .target = target, .optimize = optimize });
        integration.addOptions("config", options);
        integration.addImport("stwo_core", core);
        integration.addImport("stwo_prover_engine", prover);
        integration.addImport("stwo_bend_backend", backend);
        const run = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
        b.step("test-integration", "Run native subprocess parity, LDE and failure tests").dependOn(&run.step);
    }
    const oracle = b.createModule(.{ .root_source_file = b.path("oracle.zig"), .target = target, .optimize = optimize });
    oracle.addImport("stwo_core", core);
    oracle.addImport("stwo_prover_engine", prover);
    oracle.addImport("stwo_bend_backend", backend);
    b.installArtifact(b.addExecutable(.{ .name = "bend-oracle", .root_module = oracle }));
}
