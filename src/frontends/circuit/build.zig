const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit frontend tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");

    const frontend = b.addModule("stwo_circuit_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_engine", prover);

    // Tests that read the committed circuit fixtures (`vectors/circuit`) run
    // from the repository root, independent of where `zig build` started.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };

    const unit_tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend, .filters = filters }));
    unit_tests.setCwd(repository_root);

    const fixture_root = b.createModule(.{
        .root_source_file = b.path("fixture_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    fixture_root.addImport("stwo_circuit_frontend", frontend);
    fixture_root.addImport("stwo_core", core);
    const fixture_tests = b.addRunArtifact(b.addTest(.{ .root_module = fixture_root, .filters = filters }));
    fixture_tests.setCwd(repository_root);

    const fold_topology_root = b.createModule(.{
        .root_source_file = b.path("conformance/fold_topology_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    fold_topology_root.addImport("circuit_frontend", frontend);
    fold_topology_root.addImport("stwo_core", core);
    const fold_topology = b.addRunArtifact(b.addTest(.{ .root_module = fold_topology_root, .filters = filters }));
    fold_topology.setCwd(repository_root);

    const test_step = b.step("test", "Compile and test the stwo_circuit_frontend package");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&fixture_tests.step);
    test_step.dependOn(&fold_topology.step);

    const r3_step = b.step("test-r3", "Rung R3: all 94 in-circuit evaluators against the oracle");
    r3_step.dependOn(&fixture_tests.step);

    const r6_step = b.step(
        "circuit-parity-r6-fold",
        "Fold topology rung: 45-column layout, registry circuit hashes and proof size",
    );
    r6_step.dependOn(&fold_topology.step);

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
