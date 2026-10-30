const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    _ = b.addModule("rv64_execution", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    const tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("execution_test_root.zig"), .target = target, .optimize = optimize }) });
    b.step("test", "Test experimental RV64IM execution (no proof support)").dependOn(&b.addRunArtifact(tests).step);
    const diagnostic = b.addExecutable(.{ .name = "rv64-diagnostic", .root_module = b.createModule(.{ .root_source_file = b.path("diagnostic.zig"), .target = target, .optimize = optimize }) });
    b.installArtifact(diagnostic);
    const run = b.addRunArtifact(diagnostic);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Inspect an ELF64 or check independent execution vectors").dependOn(&run.step);
    const csp = b.addExecutable(.{ .name = "rv64-csp-execution", .root_module = b.createModule(.{ .root_source_file = b.path("csp_benchmark.zig"), .target = target, .optimize = optimize }) });
    const csp_run = b.addRunArtifact(csp);
    if (b.args) |args| csp_run.addArgs(args);
    b.step("csp-run", "Execute a software CSP case with an explicit I/O contract").dependOn(&csp_run.step);
}
