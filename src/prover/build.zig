const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(
        bool,
        "check-only",
        "Type-check focused roots without emitting or running test binaries",
    ) orelse false;
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const backend_contracts = b.dependency(
        "stwo_backend_contracts",
        dependency_options,
    ).module("stwo_backend_contracts");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const prover = b.addModule("stwo_prover_engine", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    prover.addImport("stwo_core", core);
    prover.addImport("stwo_backend_contracts", backend_contracts);
    prover.addImport("stwo_prover_api", prover_api);

    const tests = b.addTest(.{ .root_module = prover });
    const run_tests = b.addRunArtifact(tests);
    const deep_tests = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    deep_tests.addImport("stwo_core", core);
    deep_tests.addImport("stwo_prover_engine", prover);
    deep_tests.addImport("stwo_prover_api", prover_api);
    const run_deep_tests = b.addRunArtifact(b.addTest(.{
        .root_module = deep_tests,
    }));
    const test_step = b.step("test", "Compile and test the stwo_prover_engine package");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_deep_tests.step);

    const air_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-air",
        .description = "Run only prover AIR orchestration tests",
        .root = "air_test_root.zig",
    });
    const poly_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-poly",
        .description = "Run only prover polynomial tests",
        .root = "poly_test_root.zig",
    });
    const pcs_commitments_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-commitments",
        .description = "Run only prover PCS commitment tests",
        .root = "pcs_commitments_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-shell-work",
        .description = "Run only transcript and PCS shell exact-work tests",
        .root = "pcs_shell_work_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-quotient-geometry",
        .description = "Run only prover quotient geometry tests",
        .root = "pcs_quotient_geometry_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-quotient-planning",
        .description = "Run only prover quotient planning tests",
        .root = "pcs_quotient_planning_test_root.zig",
    });
    // quotient_ops imports the complete quotient execution graph, so this is
    // also the exhaustive quotient root. Keep the smaller geometry, planning,
    // row, and tile roots above/below for local edits that do not touch it.
    const quotient_ops_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-quotient-ops",
        .description = "Run only prover quotient arithmetic tests",
        .root = "pcs_quotient_ops_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-quotient-rows",
        .description = "Run only prover quotient row-executor tests",
        .root = "pcs_quotient_rows_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-quotient-tiles",
        .description = "Run only prover quotient tile-executor tests",
        .root = "pcs_quotient_tiles_test_root.zig",
    });

    test_step.dependOn(air_step);
    test_step.dependOn(poly_step);
    test_step.dependOn(pcs_commitments_step);
    test_step.dependOn(quotient_ops_step);
}

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
};

fn addFocusedTests(
    b: *std.Build,
    core: *std.Build.Module,
    backend_contracts: *std.Build.Module,
    prover_api: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    spec: FocusedTest,
) *std.Build.Step {
    const root = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", core);
    root.addImport("stwo_backend_contracts", backend_contracts);
    root.addImport("stwo_prover_api", prover_api);
    const tests = b.addTest(.{ .root_module = root });
    const step = b.step(spec.step, spec.description);
    step.dependOn(if (check_only) &tests.step else &b.addRunArtifact(tests).step);
    return step;
}
