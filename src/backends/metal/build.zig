const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const backend_contracts = b.dependency(
        "stwo_backend_contracts",
        dependency_options,
    ).module("stwo_backend_contracts");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const backend = b.addModule("stwo_metal_backend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(backend, core, backend_contracts, prover_api, prover);

    const test_step = b.step(
        "test",
        "Compile the stwo_metal_backend package tests",
    );
    const lookup_v2_step = b.step(
        "test-lookup-polynomial-v2-owner",
        "Run device-free Metal lookup-polynomial V2 ownership tests",
    );
    const sampled_receipt_step = b.step(
        "test-sampled-coefficient-work-receipt",
        "Run the Metal sampled-coefficient execution-receipt tests",
    );
    const fri_receipt_step = b.step(
        "test-fri-fold-work-receipt",
        "Run the focused Metal FRI fold execution-receipt test",
    );
    const precommitted_unit_step = b.step(
        "test-precommitted-work-receipt",
        "Run device-free Metal precommitted exact-work receipt tests",
    );
    const precommitted_runtime_step = b.step(
        "test-precommitted-work-runtime",
        "Run the Metal precommitted exact-work transaction test",
    );
    const precommitted_unit_root = b.createModule(.{
        .root_source_file = b.path("runtime/precommitted_work.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(precommitted_unit_root, core, backend_contracts, prover_api, prover);
    const precommitted_unit_tests = b.addTest(.{ .root_module = precommitted_unit_root });
    precommitted_unit_step.dependOn(&b.addRunArtifact(precommitted_unit_tests).step);
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail(
            "stwo_metal_backend tests require a macOS target and the Apple Metal SDK",
        );
        test_step.dependOn(&unsupported.step);
        lookup_v2_step.dependOn(&unsupported.step);
        sampled_receipt_step.dependOn(&unsupported.step);
        fri_receipt_step.dependOn(&unsupported.step);
        precommitted_runtime_step.dependOn(&unsupported.step);
        return;
    }
    const tests = b.addTest(.{ .root_module = backend });
    linkRuntime(b, tests);
    const deep_root = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(deep_root, core, backend_contracts, prover_api, prover);
    const deep_tests = b.addTest(.{ .root_module = deep_root });
    linkRuntime(b, deep_tests);

    const lookup_v2_root = b.createModule(.{
        .root_source_file = b.path("runtime/lookup_polynomial_v2_owner.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(lookup_v2_root, core, backend_contracts, prover_api, prover);
    const lookup_v2_tests = b.addTest(.{ .root_module = lookup_v2_root });
    linkRuntime(b, lookup_v2_tests);
    lookup_v2_step.dependOn(&b.addRunArtifact(lookup_v2_tests).step);

    const sampled_receipt_root = b.createModule(.{
        .root_source_file = b.path("sampled_coefficient_work_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(sampled_receipt_root, core, backend_contracts, prover_api, prover);
    const sampled_receipt_tests = b.addTest(.{ .root_module = sampled_receipt_root });
    linkRuntime(b, sampled_receipt_tests);
    sampled_receipt_step.dependOn(&b.addRunArtifact(sampled_receipt_tests).step);

    const fri_receipt_root = b.createModule(.{
        .root_source_file = b.path("fri_fold_work_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(fri_receipt_root, core, backend_contracts, prover_api, prover);
    const fri_receipt_tests = b.addTest(.{
        .root_module = fri_receipt_root,
        .filters = &.{
            "metal: resident FRI inverse-y cache matches shifted host domains",
            "metal: line FRI cascade preserves every root, challenge, and final value",
        },
    });
    linkRuntime(b, fri_receipt_tests);
    const run_fri_receipt_tests = b.addRunArtifact(fri_receipt_tests);
    run_fri_receipt_tests.has_side_effects = true;
    fri_receipt_step.dependOn(&run_fri_receipt_tests.step);

    const precommitted_runtime_tests = b.addTest(.{
        .root_module = deep_root,
        .filters = &.{
            "metal: heterogeneous precommit authenticates exact transform and Merkle work",
            "metal: uniform owned and polynomial precommits return device receipts",
            "metal: profiled heterogeneous post-dispatch failure remains incomplete",
        },
    });
    const run_precommitted_runtime_tests = b.addRunArtifact(precommitted_runtime_tests);
    run_precommitted_runtime_tests.has_side_effects = true;
    precommitted_runtime_step.dependOn(&run_precommitted_runtime_tests.step);

    test_step.dependOn(&tests.step);
    test_step.dependOn(&deep_tests.step);
}

fn addImports(
    module: *std.Build.Module,
    core: *std.Build.Module,
    backend_contracts: *std.Build.Module,
    prover_api: *std.Build.Module,
    prover: *std.Build.Module,
) void {
    module.addImport("stwo_core", core);
    module.addImport("stwo_backend_contracts", backend_contracts);
    module.addImport("stwo_prover_api", prover_api);
    module.addImport("stwo_prover_engine", prover);
}

fn linkRuntime(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    artifact.addCSourceFile(.{
        .file = b.path("runtime.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
