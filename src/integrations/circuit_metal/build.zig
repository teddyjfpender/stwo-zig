const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit Metal tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");
    const prover_api = b.dependency("stwo_prover_api", dependency_options).module("stwo_prover_api");
    const metal = b.dependency("stwo_metal_backend", dependency_options).module("stwo_metal_backend");
    const circuit_dependency = b.dependency("stwo_circuit_frontend", dependency_options);
    const circuit = circuit_dependency.module("stwo_circuit_frontend");
    const circuit_testing = circuit_dependency.module("circuit_testing");
    const cairo = b.dependency("stwo_cairo_frontend", dependency_options).module("stwo_cairo_frontend");
    const cairo_metal = b.dependency("stwo_cairo_metal_integration", dependency_options).module("stwo_cairo_metal_integration");
    const cpu_dependency = b.dependency("stwo_circuit_cpu_integration", dependency_options);
    const circuit_cpu = cpu_dependency.module("stwo_circuit_cpu_integration");
    // The CPU integration's wire module (one module per file per compilation).
    const wire = circuit_cpu.import_table.get("stwo_circuit_recursion_wire") orelse
        @panic("circuit CPU integration is missing stwo_circuit_recursion_wire");

    const integration = b.addModule("stwo_circuit_metal_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_metal_backend", metal);
    integration.addImport("stwo_circuit_frontend", circuit);
    integration.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    integration.addImport("stwo_cairo_metal_integration", cairo_metal);

    const test_step = b.step("test", "Compile and test the stwo_circuit_metal_integration package (macOS, Metal)");
    const r9_step = b.step(
        "circuit-parity-r9-metal",
        "Rung R9 on Metal: the recursive tree over the golden leaves, every reduction proved on the device, byte for byte against upstream (large)",
    );
    const r8_step = b.step(
        "circuit-parity-r8-metal",
        "Rung R8 on Metal: the leaf wrap proved on the device equals leaf-prover's expected_output.json (large)",
    );
    const r8b_step = b.step(
        "circuit-parity-r8b-metal",
        "Rung R8b on Metal: the Zig leaf wrapped and four copies folded on the device equal the four_leaves goldens (large)",
    );
    const r7_step = b.step(
        "circuit-parity-r7-metal",
        "Rung R7 on Metal: the prover_test.rs circuits proved on the device, byte for byte against the CPU oracle's fixture",
    );
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail("stwo_circuit_metal_integration requires macOS and the Apple Metal SDK");
        test_step.dependOn(&unsupported.step);
        r7_step.dependOn(&unsupported.step);
        r8_step.dependOn(&unsupported.step);
        r8b_step.dependOn(&unsupported.step);
        r9_step.dependOn(&unsupported.step);
        return;
    }
    // Fixture tests read `vectors/circuit` from the repository root.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };

    const unit_tests = b.addTest(.{ .root_module = integration, .filters = filters });
    linkMetal(unit_tests);
    const run_unit = b.addRunArtifact(unit_tests);
    run_unit.setCwd(repository_root);
    test_step.dependOn(&run_unit.step);

    // R7 on the device: the CPU rung's test, proving with the Metal provers.
    const metal_provers = b.createModule(.{
        .root_source_file = b.path("tests/metal_provers.zig"),
        .target = target,
        .optimize = optimize,
    });
    metal_provers.addImport("stwo_circuit_metal_integration", integration);
    const r7_root = b.createModule(.{
        .root_source_file = cpu_dependency.path("tests/r7_prove_small_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r7_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    r7_root.addImport("stwo_core", core);
    r7_root.addImport("stwo_prover_engine", prover);
    r7_root.addImport("stwo_circuit_frontend", circuit);
    r7_root.addImport("stwo_cairo_frontend", cairo);
    r7_root.addImport("stwo_circuit_recursion_wire", wire);
    r7_root.addImport("circuit_testing", circuit_testing);
    r7_root.addImport("circuit_provers_under_test", metal_provers);
    const r7_tests = b.addTest(.{ .root_module = r7_root, .filters = filters });
    linkMetal(r7_tests);
    const run_r7 = b.addRunArtifact(r7_tests);
    run_r7.setCwd(repository_root);
    r7_step.dependOn(&run_r7.step);
    test_step.dependOn(&run_r7.step);

    // R9 on the device (large: every reduction is a 2^23-row multiverifier;
    // not part of `test`).
    const r9_root = b.createModule(.{
        .root_source_file = cpu_dependency.path("tests/r9_fold_tree_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    r9_root.addImport("stwo_core", core);
    r9_root.addImport("stwo_prover_engine", prover);
    r9_root.addImport("stwo_circuit_frontend", circuit);
    r9_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    r9_root.addImport("stwo_circuit_recursion_wire", wire);
    r9_root.addImport("circuit_testing", circuit_testing);
    r9_root.addImport("circuit_provers_under_test", metal_provers);
    const r9_tests = b.addTest(.{ .root_module = r9_root, .filters = filters });
    linkMetal(r9_tests);
    const run_r9 = b.addRunArtifact(r9_tests);
    run_r9.setCwd(repository_root);
    r9_step.dependOn(&run_r9.step);

    // R8 and R8b on the device: the circuit recursion product's app and its
    // rung tests, with the Metal provers injected (the leaf Cairo proof stays
    // on the CPU lane; the wrap and the folds run on the device). Large.
    const cairo_cpu = b.dependency("stwo_cairo_cpu_integration", dependency_options).module("stwo_cairo_cpu_integration");
    const app = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cpu/app.zig") },
        .target = target,
        .optimize = optimize,
    });
    app.addImport("stwo_cairo_frontend", cairo);
    app.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    app.addImport("stwo_circuit_frontend", circuit);
    app.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    app.addImport("stwo_circuit_recursion_wire", wire);
    app.addImport("stwo_prover_engine", prover);
    app.addAnonymousImport("circuit_air_projection", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") },
    });
    app.addAnonymousImport("circuit_air_programs", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") },
    });
    const executable_root = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_metal/main.zig") },
        .target = target,
        .optimize = optimize,
    });
    executable_root.addImport("circuit_recursion_app", app);
    executable_root.addImport("stwo_cairo_metal_integration", cairo_metal);
    executable_root.addImport("stwo_circuit_metal_integration", integration);
    const executable = b.addExecutable(.{ .name = "stwo-circuit-recursion-metal", .root_module = executable_root });
    linkMetal(executable);
    b.installArtifact(executable);
    inline for (.{ .{ "r8_leaf_wrap_test.zig", r8_step }, .{ "r8b_leaf_chain_test.zig", r8b_step } }) |rung| {
        const root = b.createModule(.{
            .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cpu/tests/" ++ rung[0]) },
            .target = target,
            .optimize = optimize,
        });
        root.addImport("app", app);
        root.addImport("stwo_prover_engine", prover);
        root.addImport("circuit_provers_under_test", metal_provers);
        const tests = b.addTest(.{ .root_module = root, .filters = filters });
        linkMetal(tests);
        const run = b.addRunArtifact(tests);
        run.setCwd(repository_root);
        rung[1].dependOn(&run.step);
    }
}

fn linkMetal(compile: *std.Build.Step.Compile) void {
    compile.linkLibC();
    compile.linkFramework("Foundation");
    compile.linkFramework("Metal");
    compile.linkSystemLibrary("objc");
}
