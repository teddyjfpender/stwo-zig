const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.addModule("stwo_core", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = core });
    const run_tests = b.addRunArtifact(tests);
    const deep_tests = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    deep_tests.addImport("stwo_core", core);
    const run_deep_tests = b.addRunArtifact(b.addTest(.{
        .root_module = deep_tests,
    }));

    const test_step = b.step("test", "Compile and test the stwo_core package");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_deep_tests.step);
}
