const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    // The CairoSerde transport (`cairo_serialize`) is shared with the Cairo
    // frontend; it is injected as a single-file module because a file cannot
    // belong to two modules.
    const felt_json = b.createModule(.{
        .root_source_file = b.path("../felt_json.zig"),
        .target = target,
        .optimize = optimize,
    });
    felt_json.addImport("stwo_core", core);
    // `ProverParameters` is shared with the Cairo frontend's leaf lane the
    // same way.
    const prover_parameters = b.createModule(.{
        .root_source_file = b.path("../cairo_prover_parameters.zig"),
        .target = target,
        .optimize = optimize,
    });
    prover_parameters.addImport("stwo_core", core);
    const wire = b.addModule("stwo_circuit_recursion_wire", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    wire.addImport("stwo_core", core);
    wire.addImport("interop_felt_json", felt_json);
    wire.addImport("interop_cairo_prover_parameters", prover_parameters);

    const unit_tests = b.addRunArtifact(b.addTest(.{ .root_module = wire, .filters = filters }));

    // Upstream fixtures live in the monorepo's `vectors/circuit/`; the
    // round-trip tests read them relative to the repository root.
    const vectors_root = b.createModule(.{
        .root_source_file = b.path("vectors_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    vectors_root.addImport("stwo_circuit_recursion_wire", wire);
    const vector_tests = b.addRunArtifact(b.addTest(.{ .root_module = vectors_root, .filters = filters }));
    vector_tests.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });

    const test_step = b.step("test", "Run the stwo_circuit_recursion_wire package tests");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&vector_tests.step);
}
