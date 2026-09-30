const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const cairo = b.dependency("stwo_cairo_frontend", dependency_options).module("stwo_cairo_frontend");
    const cairo_cpu = b.dependency("stwo_cairo_cpu_integration", dependency_options).module("stwo_cairo_cpu_integration");
    const circuit = b.dependency("stwo_circuit_frontend", dependency_options).module("stwo_circuit_frontend");
    const circuit_cpu = b.dependency("stwo_circuit_cpu_integration", dependency_options).module("stwo_circuit_cpu_integration");
    // The integration's own wire module: a file belongs to one module per
    // compilation.
    const wire = circuit_cpu.import_table.get("stwo_circuit_recursion_wire") orelse
        @panic("circuit CPU integration is missing stwo_circuit_recursion_wire");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");

    const app = b.createModule(.{
        .root_source_file = b.path("app.zig"),
        .target = target,
        .optimize = optimize,
    });
    app.addImport("stwo_core", core);
    app.addImport("stwo_cairo_frontend", cairo);
    app.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    app.addImport("stwo_circuit_frontend", circuit);
    app.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    app.addImport("stwo_circuit_recursion_wire", wire);
    app.addImport("stwo_prover_engine", prover);

    const main = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main.addImport("stwo_core", core);
    main.addImport("stwo_cairo_frontend", cairo);
    main.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    main.addImport("stwo_circuit_frontend", circuit);
    main.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    main.addImport("stwo_circuit_recursion_wire", wire);
    main.addImport("stwo_prover_engine", prover);
    const exe = b.addExecutable(.{ .name = "stwo-circuit-recursion-cpu", .root_module = main });
    b.installArtifact(exe);

    // Tests read `vectors/` from the repository root.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };
    const unit_tests = b.addRunArtifact(b.addTest(.{ .root_module = main }));
    unit_tests.setCwd(repository_root);
    b.step("test", "Test the stwo-circuit-recursion-cpu product").dependOn(&unit_tests.step);

    // R8: large (a 2^23-row circuit proof); not part of `test`.
    const r8_root = b.createModule(.{
        .root_source_file = b.path("tests/r8_leaf_wrap_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r8_root.addImport("app", app);
    const r8_tests = b.addRunArtifact(b.addTest(.{ .root_module = r8_root }));
    r8_tests.setCwd(repository_root);
    b.step(
        "circuit-parity-r8",
        "Rung R8: leaf-wrap of the leaf prover's test program equals leaf-prover's expected_output.json",
    ).dependOn(&r8_tests.step);
}
