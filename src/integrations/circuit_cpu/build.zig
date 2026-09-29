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
    const multiverifier_tests = b.addRunArtifact(b.addTest(.{ .root_module = multiverifier_root, .filters = filters }));
    multiverifier_tests.setCwd(repository_root);
    // Large (a 2^21-row circuit at blowup 3); not part of `test`.
    b.step(
        "circuit-parity-r7-multiverifier",
        "Rung R7: reproduce test_data/circuit_multiverifier/proof.bin (needs STWO_CIRCUIT_MULTIVERIFIER_INPUTS)",
    ).dependOn(&multiverifier_tests.step);

    const r7_step = b.step(
        "circuit-parity-r7",
        "Rung R7: the prover_test.rs circuits proved byte for byte against the oracle's prove-small",
    );
    r7_step.dependOn(&r7_tests.step);
}
