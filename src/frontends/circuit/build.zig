const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit frontend tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const frontend = b.addModule("stwo_circuit_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);

    // Fixture tests read the committed vectors (`vectors/circuit`) relative to
    // the repository root, independent of where `zig build` started.
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

    // R1: the upstream `expect!` snapshots (unit tests) and the R1 builder
    // cases of `vectors/circuit/r2/gadgets.json`; R2: its gadget cases.
    const r1_step = b.step("circuit-parity-r1", "Rung R1: builder snapshots and builder cases against the oracle");
    r1_step.dependOn(&unit_tests.step);
    r1_step.dependOn(&fixture_tests.step);
    const r2_step = b.step("circuit-parity-r2", "Rung R2: gadget gate lists, values and outputs against the oracle");
    r2_step.dependOn(&fixture_tests.step);
}
