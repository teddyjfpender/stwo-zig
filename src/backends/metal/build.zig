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
    const sampled_barycentric_step = b.step(
        "test-sampled-barycentric-epoch",
        "Run the exact Metal resident barycentric epoch tests",
    );
    const composition_profile_step = b.step(
        "test-composition-task-profile",
        "Run the device-free Metal composition task-profile authority tests",
    );
    const fri_receipt_step = b.step(
        "test-fri-fold-work-receipt",
        "Run the focused Metal FRI fold execution-receipt test",
    );
    const quotient_parity_step = b.step(
        "test-quotient-output-parity",
        "Run device-free Metal quotient-output parity tests",
    );
    const quotient_internal_parity_step = b.step(
        "test-quotient-internal-parity",
        "Run device-free segmented Metal quotient-boundary parity tests",
    );
    const precommitted_unit_step = b.step(
        "test-precommitted-work-receipt",
        "Run device-free Metal precommitted exact-work receipt tests",
    );
    const precommitted_runtime_step = b.step(
        "test-precommitted-work-runtime",
        "Run the Metal precommitted exact-work transaction test",
    );
    const proof_of_work_step = b.step(
        "test-proof-of-work",
        "Run deterministic Metal proof-of-work parity",
    );
    const circle_lde_batch_step = b.step(
        "test-circle-lde-batch",
        "Run focused Metal multi-group circle-LDE command parity",
    );
    const circle_lde_output_parity_step = b.step(
        "test-circle-lde-output-parity",
        "Run device-free retained circle-LDE output parity tests",
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
        sampled_barycentric_step.dependOn(&unsupported.step);
        composition_profile_step.dependOn(&unsupported.step);
        fri_receipt_step.dependOn(&unsupported.step);
        quotient_parity_step.dependOn(&unsupported.step);
        quotient_internal_parity_step.dependOn(&unsupported.step);
        precommitted_runtime_step.dependOn(&unsupported.step);
        proof_of_work_step.dependOn(&unsupported.step);
        circle_lde_batch_step.dependOn(&unsupported.step);
        circle_lde_output_parity_step.dependOn(&unsupported.step);
        return;
    }
    const tests = b.addTest(.{ .root_module = backend });
    linkRuntime(b, tests);
    const composition_profile_root = b.createModule(.{
        .root_source_file = b.path("composition_profile_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(
        composition_profile_root,
        core,
        backend_contracts,
        prover_api,
        prover,
    );
    const composition_profile_tests = b.addTest(.{
        .root_module = composition_profile_root,
        .filters = &.{
            "profiled Metal host graph attributes exact 1 2 4 and max worker arms",
            "profiled Metal composition fails closed when the resident route declines",
            "Metal composition keeps retained semantic and lookup roster outputs disjoint then merges",
            "Metal composition device bucket ownership cleans every allocation failure",
            "Metal composition same-output dispatches are order independent with a buffer barrier",
            "Metal generated column offsets keep 254 255 256 and 339 distinct at log 24",
            "Metal composition partition mismatch reports exact row and coordinate",
            "base polynomial codegen widens retained column offsets before multiplication",
            "lookup polynomial codegen widens main and secure-column offsets",
            "Metal composition domain scratch exact byte count is degree aware",
            "Metal composition domain scratch evaluates retained coefficients in one exact resident owner",
            "Metal composition domain scratch clone cleans every allocation failure",
        },
    });
    linkRuntime(b, composition_profile_tests);
    composition_profile_tests.addCSourceFile(.{
        .file = b.path("runtime/composition_dispatch_barrier_test.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    composition_profile_step.dependOn(
        &b.addRunArtifact(composition_profile_tests).step,
    );
    const deep_root = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(deep_root, core, backend_contracts, prover_api, prover);
    const deep_tests = b.addTest(.{ .root_module = deep_root });
    const proof_of_work_tests = b.addTest(.{
        .root_module = backend,
        .filters = &.{"metal proof of work returns the protocol lowest nonce"},
    });
    const run_proof_of_work_tests = b.addRunArtifact(proof_of_work_tests);
    run_proof_of_work_tests.has_side_effects = true;
    proof_of_work_step.dependOn(&run_proof_of_work_tests.step);
    linkRuntime(b, deep_tests);

    const circle_lde_batch_root = b.createModule(.{
        .root_source_file = b.path("circle_lde_batch_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(circle_lde_batch_root, core, backend_contracts, prover_api, prover);
    const circle_lde_batch_tests = b.addTest(.{ .root_module = circle_lde_batch_root });
    linkRuntime(b, circle_lde_batch_tests);
    const run_circle_lde_batch_tests = b.addRunArtifact(circle_lde_batch_tests);
    run_circle_lde_batch_tests.has_side_effects = true;
    circle_lde_batch_step.dependOn(&run_circle_lde_batch_tests.step);

    const circle_lde_output_parity_root = b.createModule(.{
        .root_source_file = b.path("circle_lde_output_parity_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(
        circle_lde_output_parity_root,
        core,
        backend_contracts,
        prover_api,
        prover,
    );
    const circle_lde_output_parity_tests = b.addTest(.{
        .root_module = circle_lde_output_parity_root,
        .filters = &.{
            "Metal circle LDE parity reconstructs CPU coefficients and evaluations",
            "Metal circle LDE parity reports a structured extended mutation",
            "Metal circle LDE parity selects retained u32 split boundaries",
            "Metal circle LDE parity releases every diagnostic allocation",
        },
    });
    linkRuntime(b, circle_lde_output_parity_tests);
    circle_lde_output_parity_step.dependOn(
        &b.addRunArtifact(circle_lde_output_parity_tests).step,
    );

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

    const sampled_barycentric_root = b.createModule(.{
        .root_source_file = b.path("sampled_coefficient_work_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(
        sampled_barycentric_root,
        core,
        backend_contracts,
        prover_api,
        prover,
    );
    const sampled_barycentric_tests = b.addTest(.{
        .root_module = sampled_barycentric_root,
        .filters = &.{
            "Metal sampled barycentric domain operation count follows exact pow schedule",
            "Metal sampled barycentric execution rejects inverse coverage mutation",
            "Metal sampled barycentric planner deduplicates exact cross-tree points",
            "Metal sampled barycentric planner releases every allocation failure",
            "Metal sampled barycentric planner rejects normalized-point mutation",
            "Metal sampled barycentric planner rejects a sampled domain point",
            "metal: resident barycentric epoch matches CPU across trees and points",
        },
    });
    linkRuntime(b, sampled_barycentric_tests);
    sampled_barycentric_step.dependOn(
        &b.addRunArtifact(sampled_barycentric_tests).step,
    );

    const fri_receipt_root = b.createModule(.{
        .root_source_file = b.path("fri_fold_work_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(fri_receipt_root, core, backend_contracts, prover_api, prover);
    const fri_receipt_tests = b.addTest(.{
        .root_module = fri_receipt_root,
        // The six named protocol tests retain the root and runtime import
        // closure tests, for an exact successful inventory of eight.
        .filters = &.{
            "metal: packed FRI retains exact resident opening columns through decommit",
            "metal: four-fold FRI prover owns packed resident openings until query",
            "metal: resident FRI inverse-y cache matches shifted host domains",
            "metal: line FRI cascade preserves every root, challenge, and final value",
            "metal: FRI parity reports the first circle coordinate mutation",
            "metal: complete line FRI chain matches CPU and has zero terminal coefficient one",
        },
    });
    linkRuntime(b, fri_receipt_tests);
    const run_fri_receipt_tests = b.addRunArtifact(fri_receipt_tests);
    run_fri_receipt_tests.has_side_effects = true;
    fri_receipt_step.dependOn(&run_fri_receipt_tests.step);

    const quotient_parity_root = b.createModule(.{
        .root_source_file = b.path("quotient_output_parity_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(quotient_parity_root, core, backend_contracts, prover_api, prover);
    const quotient_parity_tests = b.addTest(.{
        .root_module = quotient_parity_root,
        .filters = &.{
            "Metal quotient parity reconstructs the ordinary CPU quotient exactly",
            "Metal quotient parity returns the first structured mismatch",
            "Metal quotient CPU parity releases every diagnostic allocation",
        },
    });
    linkRuntime(b, quotient_parity_tests);
    quotient_parity_step.dependOn(
        &b.addRunArtifact(quotient_parity_tests).step,
    );

    const quotient_internal_parity_root = b.createModule(.{
        .root_source_file = b.path("quotient_internal_parity_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(
        quotient_internal_parity_root,
        core,
        backend_contracts,
        prover_api,
        prover,
    );
    const quotient_internal_parity_tests = b.addTest(.{
        .root_module = quotient_internal_parity_root,
        // Seven named semantic tests plus the root import closure.
        .filters = &.{
            "Metal quotient internal parity binds two cumulative raw segments and final output",
            "Metal quotient incremental oracle is scheduling independent across four workers",
            "Metal quotient internal parity reports segment component row coordinate mutation",
            "Metal quotient internal parity rejects domain and source-run authority drift",
            "Metal quotient internal parity reports finalized quotient mutation before FRI",
            "Metal quotient internal parity releases every diagnostic allocation",
            "Metal quotient wide source views reject wrap reorder and local overflow",
        },
    });
    linkRuntime(b, quotient_internal_parity_tests);
    quotient_internal_parity_step.dependOn(
        &b.addRunArtifact(quotient_internal_parity_tests).step,
    );

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
