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

    const core_package = b.dependency("stwo_core", dependency_options);
    const core = core_package.module("stwo_core");
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
    // Test-only Rust-oracle data owned by core, outside the stwo_core API.
    deep_tests.addImport("lifted_height_vectors", b.createModule(.{
        .root_source_file = core_package.path("vcs_lifted/testdata/lifted_height_vectors.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const run_deep_tests = b.addRunArtifact(b.addTest(.{
        .root_module = deep_tests,
    }));
    const merkle_tests = b.addTest(.{
        .root_module = deep_tests,
        .filters = &.{"prover vcs_lifted"},
    });
    const merkle_step = b.step("test-merkle", "Run lifted Merkle commitment, continuation and worker-path regressions");
    merkle_step.dependOn(&b.addRunArtifact(merkle_tests).step);
    // Continuation implementation tests belong to the engine module itself;
    // importing its source into the separate deep-test module duplicates files.
    const merkle_engine_tests = b.addTest(.{
        .root_module = prover,
        .filters = &.{ "prover vcs_lifted", "prover lifted BLAKE2s" },
    });
    merkle_step.dependOn(&b.addRunArtifact(merkle_engine_tests).step);
    const test_step = b.step("test", "Compile and test the stwo_prover_engine package");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_deep_tests.step);

    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-blake3-prefix-reuse",
        .description = "Verify BLAKE3 bounded prefix reuse across budgets and worker counts",
        .root = "blake3_prefix_reuse_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-coefficient-storage",
        .description = "Qualify compact polynomial commitments, quotients, openings and failure custody",
        .root = "coefficient_storage_test_root.zig",
        .filters = &.{"coefficient storage"},
    });
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
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-shared-commitment",
        .description = "Check immutable PCS commitment ownership and allocation failures",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{"PCS shared commitment"},
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-budgeted-merkle",
        .description = "Check Merkle layer budget admission and allocator custody",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{"budgeted Merkle"},
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-borrowed-streaming",
        .description = "Check bounded borrowed commitments and failure ownership",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{"PCS borrowed streaming"},
    });
    const pow_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-blake3-pow",
        .description = "Check BLAKE3 nonce batching against the streaming hash and deterministic pool search",
        .root = "pcs_pow_test_root.zig",
        .filters = &.{"BLAKE3 PoW"},
    });
    const pcs_revision_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-revision",
        .description = "Prove PCS openings under protocol revision proving_5a7c5ed against Rust vectors",
        .root = "pcs_revision_test_root.zig",
    });
    const pcs_commitments_step = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-commitments",
        .description = "Run only prover PCS commitment tests",
        .root = "pcs_commitments_test_root.zig",
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-cached-merkle",
        .description = "Check authenticated owned-tree cache hits, openings and corrupt-load refusal",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{"cached owned Merkle"},
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-sampled-values",
        .description = "Check sampled-value parity, barycentric scheduling and exact-work accounting",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{ "sampled", "barycentric" },
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-owned-source",
        .description = "Check combined and streaming PCS ownership, root parity and allocation failures",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{"PCS owned source admission"},
    });
    _ = addFocusedTests(b, core, backend_contracts, prover_api, target, optimize, check_only, .{
        .step = "test-pcs-retained-columns",
        .description = "Prove and freshly verify PCS proofs with independently owned or mapped retained columns",
        .root = "pcs_commitments_test_root.zig",
        .filters = &.{ "PCS retained column storage", "file backed columns" },
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
    test_step.dependOn(pow_step);
    test_step.dependOn(pcs_revision_step);
    test_step.dependOn(quotient_ops_step);
}

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
    filters: []const []const u8 = &.{},
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
    const tests = b.addTest(.{ .root_module = root, .filters = spec.filters });
    const step = b.step(spec.step, spec.description);
    step.dependOn(if (check_only) &tests.step else &b.addRunArtifact(tests).step);
    return step;
}
