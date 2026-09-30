const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit CPU tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");
    const prover_api = b.dependency("stwo_prover_api", dependency_options).module("stwo_prover_api");
    const cpu_backend = b.dependency("stwo_cpu_backend", dependency_options).module("stwo_cpu_backend");
    const circuit = b.dependency("stwo_circuit_frontend", dependency_options).module("stwo_circuit_frontend");
    const cairo = b.dependency("stwo_cairo_frontend", dependency_options).module("stwo_cairo_frontend");
    // The wire package shares the Cairo frontend's injected interop modules:
    // a file belongs to one module per compilation
    // (`build_support/graph/modules.zig` `createCircuitRecursionWire`).
    const wire = b.createModule(.{
        .root_source_file = b.dependency("stwo_circuit_recursion_wire", dependency_options).path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    wire.addImport("stwo_core", core);
    inline for (.{ "interop_felt_json", "interop_cairo_prover_parameters" }) |name| {
        wire.addImport(name, cairo.import_table.get(name) orelse @panic("Cairo frontend is missing " ++ name));
    }

    const integration = b.addModule("stwo_circuit_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_circuit_frontend", circuit);
    integration.addImport("stwo_cairo_frontend", cairo);
    integration.addImport("stwo_circuit_recursion_wire", wire);

    // Fixture tests read `vectors/circuit` from the repository root.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };

    const unit_tests = b.addRunArtifact(b.addTest(.{ .root_module = integration, .filters = filters }));
    unit_tests.setCwd(repository_root);
    const test_step = b.step("test", "Compile and test the stwo_circuit_cpu_integration package");
    test_step.dependOn(&unit_tests.step);

    // The frontend's fixture helpers (the oracle's test circuits, digests).
    const circuit_testing = b.dependency("stwo_circuit_frontend", dependency_options).module("circuit_testing");
    const r7_root = b.createModule(.{
        .root_source_file = b.path("tests/r7_prove_small_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r7_root.addImport("stwo_circuit_cpu_integration", integration);
    r7_root.addImport("stwo_core", core);
    r7_root.addImport("stwo_prover_engine", prover);
    r7_root.addImport("stwo_circuit_frontend", circuit);
    r7_root.addImport("stwo_cairo_frontend", cairo);
    r7_root.addImport("stwo_circuit_recursion_wire", wire);
    r7_root.addImport("circuit_testing", circuit_testing);
    const r7_tests = b.addRunArtifact(b.addTest(.{ .root_module = r7_root, .filters = filters }));
    r7_tests.setCwd(repository_root);
    test_step.dependOn(&r7_tests.step);
    const multiverifier_root = b.createModule(.{
        .root_source_file = b.path("tests/multiverifier_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    multiverifier_root.addImport("stwo_circuit_cpu_integration", integration);
    multiverifier_root.addImport("stwo_core", core);
    multiverifier_root.addImport("stwo_prover_engine", prover);
    multiverifier_root.addImport("stwo_circuit_frontend", circuit);
    multiverifier_root.addImport("stwo_circuit_recursion_wire", wire);
    const multiverifier_tests = b.addRunArtifact(b.addTest(.{ .root_module = multiverifier_root, .filters = filters }));
    multiverifier_tests.setCwd(repository_root);
    // Large (a 2^21-row circuit at blowup 3); not part of `test`.
    b.step(
        "circuit-parity-r7-multiverifier",
        "Rung R7: reproduce test_data/circuit_multiverifier/proof.bin (needs STWO_CIRCUIT_MULTIVERIFIER_INPUTS)",
    ).dependOn(&multiverifier_tests.step);

    // R4, value mode: the multiverifier over the committed proofs, stage by
    // stage (the frontend's `circuit-parity-r4` runs topology mode).
    const r4_root = b.createModule(.{
        .root_source_file = b.path("tests/r4_verifier_values_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r4_root.addImport("stwo_circuit_cpu_integration", integration);
    r4_root.addImport("stwo_core", core);
    r4_root.addImport("stwo_circuit_frontend", circuit);
    r4_root.addImport("stwo_circuit_recursion_wire", wire);
    r4_root.addImport("circuit_testing", circuit_testing);
    const r4_tests = b.addRunArtifact(b.addTest(.{ .root_module = r4_root, .filters = filters }));
    r4_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-r4-values",
        "Rung R4: the in-circuit verifier over test_data/circuit_multiverifier in value mode, and the circuit proof.bin proves",
    ).dependOn(&r4_tests.step);

    // R6, leaf: the canonical_small leaf verifier's preprocessed root and
    // circuit hash against the committed registry. Large (a 2^23-row
    // circuit); not part of `test`.
    const r6_leaf_root = b.createModule(.{
        .root_source_file = b.path("tests/r6_leaf_topology_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r6_leaf_root.addImport("stwo_core", core);
    r6_leaf_root.addImport("stwo_circuit_frontend", circuit);
    r6_leaf_root.addImport("stwo_cairo_frontend", cairo);
    r6_leaf_root.addImport("stwo_circuit_recursion_wire", wire);
    r6_leaf_root.addImport("circuit_testing", circuit_testing);
    r6_leaf_root.addImport("stwo_circuit_cpu_integration", integration);
    const r6_leaf_tests = b.addRunArtifact(b.addTest(.{ .root_module = r6_leaf_root, .filters = filters }));
    r6_leaf_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-r6-leaf",
        "Rung R6, leaf: the canonical_small leaf verifier's preprocessed root and circuit hash against the committed registry",
    ).dependOn(&r6_leaf_tests.step);

    // R9: the recursive tree against upstream, raw bytes. Large (every
    // reduction proves a 2^23-row multiverifier); not part of `test`.
    const r9_root = b.createModule(.{
        .root_source_file = b.path("tests/r9_fold_tree_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r9_root.addImport("stwo_core", core);
    r9_root.addImport("stwo_prover_engine", prover);
    r9_root.addImport("stwo_circuit_frontend", circuit);
    r9_root.addImport("stwo_circuit_cpu_integration", integration);
    r9_root.addImport("stwo_circuit_recursion_wire", wire);
    r9_root.addImport("circuit_testing", circuit_testing);
    const r9_tests = b.addRunArtifact(b.addTest(.{ .root_module = r9_root, .filters = filters }));
    r9_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-r9",
        "Rung R9: the recursive tree over 1, 2, 3, 4 and 5 golden leaves against upstream, byte for byte",
    ).dependOn(&r9_tests.step);

    // Registry generation against the committed canonical_small registries.
    // Large (2^23-row leaf and multiverifier circuits); not part of `test`.
    const params_root = b.createModule(.{
        .root_source_file = b.path("tests/r11_circuit_params_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    params_root.addImport("stwo_cairo_frontend", cairo);
    params_root.addImport("stwo_circuit_frontend", circuit);
    params_root.addImport("stwo_circuit_cpu_integration", integration);
    params_root.addImport("stwo_circuit_recursion_wire", wire);
    const params_tests = b.addRunArtifact(b.addTest(.{ .root_module = params_root, .filters = filters }));
    params_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-registry",
        "Registry generation: both canonical_small test definitions generate their committed registries byte for byte",
    ).dependOn(&params_tests.step);

    // R11: acceptance and tamper, the Zig verifier against upstream's
    // committed verdicts. Medium (two 2^21-2^23-row proofs verified in value
    // mode, nine times each); not part of `test`.
    const r11_root = b.createModule(.{
        .root_source_file = b.path("tests/r11_verify_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r11_root.addImport("stwo_core", core);
    r11_root.addImport("stwo_circuit_frontend", circuit);
    r11_root.addImport("stwo_circuit_cpu_integration", integration);
    r11_root.addImport("stwo_circuit_recursion_wire", wire);
    r11_root.addImport("circuit_testing", circuit_testing);
    const r11_tests = b.addRunArtifact(b.addTest(.{ .root_module = r11_root, .filters = filters }));
    r11_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-r11",
        "Rung R11: the Zig circuit verifier and upstream verify_circuit accept three proofs and reject every tampering",
    ).dependOn(&r11_tests.step);

    // Grind throughput on both circuit channels (design §9.1); a benchmark,
    // not a test. Arguments after `--`: `[seeds] [bits...]`.
    const grind_bench_root = b.createModule(.{
        .root_source_file = b.path("tests/grind_bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    grind_bench_root.addImport("stwo_core", core);
    grind_bench_root.addImport("stwo_prover_engine", prover);
    grind_bench_root.addImport("stwo_cpu_backend", cpu_backend);
    const grind_bench = b.addRunArtifact(b.addExecutable(.{ .name = "circuit-grind-bench", .root_module = grind_bench_root }));
    if (b.args) |args| grind_bench.addArgs(args);
    b.step("bench-grind", "Benchmark the interaction and FRI proof-of-work grinds on both circuit channels").dependOn(&grind_bench.step);

    // The R9 tree's wall time and stage profile (design §9.2 item 6); a
    // benchmark, not a test. Arguments after `--`: `[n_leaves] [repeats]`.
    const fold_bench_root = b.createModule(.{
        .root_source_file = b.path("tests/fold_bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    fold_bench_root.addImport("stwo_prover_engine", prover);
    fold_bench_root.addImport("stwo_circuit_frontend", circuit);
    fold_bench_root.addImport("stwo_circuit_cpu_integration", integration);
    fold_bench_root.addImport("stwo_circuit_recursion_wire", wire);
    const fold_bench = b.addRunArtifact(b.addExecutable(.{ .name = "circuit-fold-bench", .root_module = fold_bench_root }));
    fold_bench.setCwd(repository_root);
    if (b.args) |args| fold_bench.addArgs(args);
    b.step("bench-fold", "Benchmark the R9 recursive tree (stage profile, CPU utilisation), checked against upstream").dependOn(&fold_bench.step);

    const r7_step = b.step(
        "circuit-parity-r7",
        "Rung R7: the prover_test.rs circuits proved byte for byte against the oracle's prove-small",
    );
    r7_step.dependOn(&r7_tests.step);
}
