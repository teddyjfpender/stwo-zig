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

    // Shared fixture helpers of the conformance roots (and of the circuit
    // integrations' fixture tests): `testing/mod.zig`.
    const testing_module = b.addModule("circuit_testing", .{
        .root_source_file = b.path("testing/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    testing_module.addImport("stwo_circuit_frontend", frontend);
    testing_module.addImport("stwo_core", core);

    const fold_topology = addConformanceTest(b, "conformance/fold_topology_test.zig", frontend, core, testing_module, filters, repository_root);

    const test_step = b.step("test", "Compile and test the stwo_circuit_frontend package");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&fixture_tests.step);
    test_step.dependOn(&fold_topology.step);

    const r3_step = b.step("circuit-parity-r3", "Rung R3: all 94 in-circuit evaluators, sample evaluations and statement trace against the oracle");
    r3_step.dependOn(&fixture_tests.step);

    // R4 and the fold rebuild of R6 build multiverifiers of 2^21 to 2^23
    // rows and commit their preprocessed traces: labelled large, run by
    // their own steps rather than `test`.
    const r4 = addConformanceTest(b, "conformance/verifier_stages_test.zig", frontend, core, testing_module, filters, repository_root);
    const r4_step = b.step("circuit-parity-r4", "Rung R4: the in-circuit verifier's stages and the multiverifier's preprocessed root (topology) against the oracle");
    r4_step.dependOn(&r4.step);

    const r5_tests = b.addRunArtifact(b.addTest(.{ .root_module = fixture_root, .filters = &.{"R5"} }));
    r5_tests.setCwd(repository_root);
    const r5_step = b.step("circuit-parity-r5", "Rung R5: finalize_constants, guess finalization, per-kind padding and ZK blinding against the oracle");
    r5_step.dependOn(&r5_tests.step);

    const fold_rebuild = addConformanceTest(b, "conformance/fold_rebuild_test.zig", frontend, core, testing_module, filters, repository_root);
    const r6_step = b.step(
        "circuit-parity-r6-fold",
        "Fold topology rung: 45-column layout, rebuilt multiverifiers' preprocessed roots and circuit hashes, proof size",
    );
    r6_step.dependOn(&fold_topology.step);
    r6_step.dependOn(&fold_rebuild.step);

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

    const qm31_export_module = b.createModule(.{
        .root_source_file = b.path("export_qm31_ops.zig"),
        .target = target,
        .optimize = optimize,
    });
    qm31_export_module.addImport("stwo_core", core);
    const qm31_export = b.addRunArtifact(b.addExecutable(.{
        .name = "circuit-export-qm31-air-lean",
        .root_module = qm31_export_module,
    }));
    b.step("export-qm31-air-lean", "Print native qm31_ops AIR expressions as Lean source")
        .dependOn(&qm31_export.step);

    const logup_export_module = b.createModule(.{
        .root_source_file = b.path("export_logup_air.zig"),
        .target = target,
        .optimize = optimize,
    });
    const logup_export = b.addRunArtifact(b.addExecutable(.{
        .name = "circuit-export-logup-air-lean",
        .root_module = logup_export_module,
    }));
    b.step("export-logup-air-lean", "Print native LogUp formulas as Lean source")
        .dependOn(&logup_export.step);

    // R1: the upstream `expect!` snapshots (unit tests) and the R1 builder
    // cases of `vectors/circuit/r2/gadgets.json`; R2: its gadget cases.
    const r1_step = b.step("circuit-parity-r1", "Rung R1: builder snapshots and builder cases against the oracle");
    r1_step.dependOn(&unit_tests.step);
    r1_step.dependOn(&fixture_tests.step);
    const r2_step = b.step("circuit-parity-r2", "Rung R2: gadget gate lists, values and outputs against the oracle");
    r2_step.dependOn(&fixture_tests.step);
}

fn addConformanceTest(
    b: *std.Build,
    path: []const u8,
    frontend: *std.Build.Module,
    core: *std.Build.Module,
    testing_module: *std.Build.Module,
    filters: []const []const u8,
    repository_root: std.Build.LazyPath,
) *std.Build.Step.Run {
    const root = b.createModule(.{
        .root_source_file = b.path(path),
        .target = frontend.resolved_target,
        .optimize = frontend.optimize,
    });
    root.addImport("circuit_frontend", frontend);
    root.addImport("stwo_core", core);
    root.addImport("circuit_testing", testing_module);
    const run = b.addRunArtifact(b.addTest(.{ .root_module = root, .filters = filters }));
    run.setCwd(repository_root);
    return run;
}
