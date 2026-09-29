const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const frontend = b.addModule("stwo_circuit_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);

    // Fixture tests read committed vectors relative to the repository root,
    // independent of the directory `zig build` runs from.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };

    const unit_tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend, .filters = filters }));
    const fixture_root = b.createModule(.{
        .root_source_file = b.path("fixture_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    fixture_root.addImport("stwo_circuit_frontend", frontend);
    fixture_root.addImport("stwo_core", core);
    const fixture_tests = b.addRunArtifact(b.addTest(.{ .root_module = fixture_root, .filters = filters }));
    fixture_tests.setCwd(repository_root);

    const test_step = b.step("test", "Compile and test the stwo_circuit_frontend package");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&fixture_tests.step);

    const r3_step = b.step("test-r3", "Rung R3: all 94 in-circuit evaluators against the oracle");
    r3_step.dependOn(&fixture_tests.step);

    const check_module = b.createModule(.{
        .root_source_file = b.path("air_eval/projection_check.zig"),
        .target = target,
        .optimize = optimize,
    });
    check_module.addImport("stwo_circuit_frontend", frontend);
    const check = b.addRunArtifact(b.addExecutable(.{
        .name = "circuit-air-projection-check",
        .root_module = check_module,
    }));
    check.setCwd(repository_root);
    const check_step = b.step(
        "circuit-air-projection-check",
        "Authenticate and decode vectors/circuit/official/compiled_air_constraints_v1.bin",
    );
    check_step.dependOn(&check.step);
}
