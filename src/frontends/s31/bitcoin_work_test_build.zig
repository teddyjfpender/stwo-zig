const std = @import("std");

pub fn build(b: *std.Build) void {
    const opts = .{ .target = b.standardTargetOptions(.{}), .optimize = b.standardOptimizeOption(.{}) };
    const cpu = b.dependency("stwo_circuit_cpu_integration", opts).module("stwo_circuit_cpu_integration");
    const root = b.createModule(.{ .root_source_file = b.path("bitcoin_work.zig"), .target = opts.target, .optimize = opts.optimize });
    root.addImport("stwo_core", cpu.import_table.get("stwo_core").?);
    root.addImport("stwo_circuit_frontend", cpu.import_table.get("stwo_circuit_frontend").?);
    b.step("test", "Test checked Bitcoin work arithmetic").dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = root })).step);
}
