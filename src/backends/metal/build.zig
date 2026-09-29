const std = @import("std");
pub const runtime_source = @import("build_runtime_source.zig");

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
    if (target.result.os.tag == .macos) backend.addCSourceFile(.{
        .file = b.path("runtime.m"),
        .flags = runtime_source.flags(b, b.pathFromRoot("runtime.m")),
    });
    const runtime_source_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("build_runtime_source.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    b.step("test-runtime-source-closure", "Check transitive runtime source identity and include admission")
        .dependOn(&b.addRunArtifact(runtime_source_tests).step);

    const abi_digests_update = b.addExecutable(.{
        .name = "abi-declaration-digests-update",
        .root_module = b.createModule(.{
            .root_source_file = b.path("abi_declaration_digests_update.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_abi_digests_update = b.addRunArtifact(abi_digests_update);
    run_abi_digests_update.addArg(b.pathFromRoot("shaders/abi_declaration_digests.zig"));
    b.step(
        "update-abi-declaration-digests",
        "Regenerate shaders/abi_declaration_digests.zig natively after a kernel declaration change",
    ).dependOn(&run_abi_digests_update.step);

    const shader_authority_root = b.createModule(.{
        .root_source_file = b.path("shader_authority_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const shader_authority_tests = b.addTest(.{ .root_module = shader_authority_root });
    b.step("test-shader-authority", "Check current shader declarations and pipeline initialization authority")
        .dependOn(&b.addRunArtifact(shader_authority_tests).step);
    const framework_codegen_root = b.createModule(.{
        .root_source_file = b.path("framework_polynomial_codegen_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(framework_codegen_root, core, backend_contracts, prover_api, prover);
    const framework_codegen_tests = b.addTest(.{ .root_module = framework_codegen_root });
    b.step("test-framework-polynomial-codegen", "Check authenticated recursive Metal polynomial generation without a device")
        .dependOn(&b.addRunArtifact(framework_codegen_tests).step);

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
    const leaf_stream_root = b.createModule(.{
        .root_source_file = b.path("leaf_stream_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(leaf_stream_root, core, backend_contracts, prover_api, prover);
    const leaf_stream_tests = b.addTest(.{ .root_module = leaf_stream_root, .filters = &.{ "metal: streaming BLAKE2s", "metal: native coefficient fold" } });
    linkRuntime(b, leaf_stream_tests);
    const run_leaf_stream = b.addRunArtifact(leaf_stream_tests);
    run_leaf_stream.has_side_effects = true;
    b.step("test-leaf-stream", "Qualify native coefficient-commitment leaf custody, block boundaries, height changes and budgets")
        .dependOn(&run_leaf_stream.step);
    const native_quotient_root = b.createModule(.{
        .root_source_file = b.path("native_quotient_reduction_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(native_quotient_root, core, backend_contracts, prover_api, prover);
    const native_quotient_tests = b.addTest(.{
        .root_module = native_quotient_root,
        .filters = &.{"metal: native segmented quotient reduction matches scalar mixed heights and batches"},
    });
    linkRuntime(b, native_quotient_tests);
    const run_native_quotient = b.addRunArtifact(native_quotient_tests);
    run_native_quotient.has_side_effects = true;
    b.step("test-native-quotient-reduction", "Compare real segmented native-height Metal quotients with the scalar oracle")
        .dependOn(&run_native_quotient.step);

    const framework_device_root = b.createModule(.{
        .root_source_file = b.path("framework_polynomial_device_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(framework_device_root, core, backend_contracts, prover_api, prover);
    const framework_device_tests = b.addTest(.{ .root_module = framework_device_root });
    framework_device_tests.addCSourceFile(.{
        .file = b.path("runtime/framework_polynomial_device_test.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    framework_device_tests.linkLibC();
    framework_device_tests.linkFramework("Foundation");
    framework_device_tests.linkFramework("Metal");
    framework_device_tests.linkSystemLibrary("objc");
    const run_framework_device = b.addRunArtifact(framework_device_tests);
    run_framework_device.has_side_effects = true;
    b.step("test-framework-polynomial-device", "Execute generated recursive framework constraints on Metal and compare CPU values")
        .dependOn(&run_framework_device.step);

    const interaction_device_root = b.createModule(.{
        .root_source_file = b.path("framework_interaction_device_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(interaction_device_root, core, backend_contracts, prover_api, prover);
    const interaction_device_tests = b.addTest(.{ .root_module = interaction_device_root, .filters = &.{"framework interaction"} });
    interaction_device_tests.addCSourceFile(.{
        .file = b.path("runtime/framework_interaction_device_test.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    interaction_device_tests.linkLibC();
    interaction_device_tests.linkFramework("Foundation");
    interaction_device_tests.linkFramework("Metal");
    interaction_device_tests.linkSystemLibrary("objc");
    const interaction_device_run = b.addRunArtifact(interaction_device_tests);
    interaction_device_run.has_side_effects = true;
    b.step("test-framework-interaction-device", "Generate independent-prefix interactions on Metal and check exact native columns, claims and rejection")
        .dependOn(&interaction_device_run.step);

    const tests = b.addTest(.{ .root_module = backend });
    linkRuntime(b, tests);
    const merkle_host_root = b.createModule(.{
        .root_source_file = b.path("merkle_host_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(merkle_host_root, core, backend_contracts, prover_api, prover);
    const merkle_host_tests = b.addTest(.{ .root_module = merkle_host_root, .filters = &.{"Metal host-backed compact Merkle"} });
    linkRuntime(b, merkle_host_tests);
    b.step("test-merkle-host", "Check compact cached host-tree openings without initializing a Metal device")
        .dependOn(&b.addRunArtifact(merkle_host_tests).step);
    const compact_merkle_root = b.createModule(.{
        .root_source_file = b.path("compact_merkle_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(compact_merkle_root, core, backend_contracts, prover_api, prover);
    const compact_merkle_tests = b.addTest(.{ .root_module = compact_merkle_root, .filters = &.{"Metal resident compact Merkle"} });
    linkRuntime(b, compact_merkle_tests);
    b.step("test-merkle-compact", "Check resident Merkle compaction admission and exact mixed-height openings")
        .dependOn(&b.addRunArtifact(compact_merkle_tests).step);
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
            "strict Metal",
            "every Event maps to a distinct counter",
            "Metal telemetry cached artifacts",
            "proof of work backend rejects forbidden host search",
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
            "Metal composition domain scratch unifies short and current domains from retained coefficients",
            "Metal composition domain scratch evaluates retained coefficients in one exact resident owner",
            "Metal composition domain scratch clone cleans every allocation failure",
            "Metal composition domain scratch stages exact committed evaluations without coefficients",
            "bounded Metal leaf tiles preserve global lifted column indices",
            "bounded Metal leaf tiles match every host Merkle layer across chunk and height boundaries",
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
    const blake3_parent_root = b.createModule(.{
        .root_source_file = b.path("blake3_parent_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_parent_root, core, backend_contracts, prover_api, prover);
    const blake3_parent_tests = b.addTest(.{ .root_module = blake3_parent_root, .filters = &.{"Metal BLAKE3 resident parent chains preserve every layer and arena guards"} });
    linkRuntime(b, blake3_parent_tests);
    b.step("test-blake3-parent-chain", "Compare all resident BLAKE3 parent layers with canonical CPU hashing")
        .dependOn(&b.addRunArtifact(blake3_parent_tests).step);
    const blake3_leaf_root = b.createModule(.{
        .root_source_file = b.path("blake3_leaf_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_leaf_root, core, backend_contracts, prover_api, prover);
    const blake3_leaf_tests = b.addTest(.{ .root_module = blake3_leaf_root });
    linkRuntime(b, blake3_leaf_tests);
    b.step("test-blake3-leaves", "Compare BLAKE3 lifted leaves across block and chunk boundaries")
        .dependOn(&b.addRunArtifact(blake3_leaf_tests).step);
    const blake3_fri_root = b.createModule(.{
        .root_source_file = b.path("blake3_fri_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_fri_root, core, backend_contracts, prover_api, prover);
    const blake3_fri_tests = b.addTest(.{ .root_module = blake3_fri_root });
    linkRuntime(b, blake3_fri_tests);
    b.step("test-blake3-fri-tree", "Compare typed resident FRI commitment trees with CPU")
        .dependOn(&b.addRunArtifact(blake3_fri_tests).step);
    const blake3_staged_root = b.createModule(.{
        .root_source_file = b.path("blake3_staged_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_staged_root, core, backend_contracts, prover_api, prover);
    const blake3_staged_tests = b.addTest(.{ .root_module = blake3_staged_root });
    linkRuntime(b, blake3_staged_tests);
    b.step("test-blake3-staged-leaves", "Verify BLAKE3 chunk state across staged lifted columns")
        .dependOn(&b.addRunArtifact(blake3_staged_tests).step);
    const blake3_staged_tree_root = b.createModule(.{
        .root_source_file = b.path("blake3_staged_tree_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_staged_tree_root, core, backend_contracts, prover_api, prover);
    const blake3_staged_tree_tests = b.addTest(.{ .root_module = blake3_staged_tree_root });
    linkRuntime(b, blake3_staged_tree_tests);
    b.step("test-blake3-staged-tree", "Verify reusable staged BLAKE3 trees in one command epoch")
        .dependOn(&b.addRunArtifact(blake3_staged_tree_tests).step);
    const blake3_heterogeneous_root = b.createModule(.{
        .root_source_file = b.path("blake3_heterogeneous_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_heterogeneous_root, core, backend_contracts, prover_api, prover);
    const blake3_heterogeneous_tests = b.addTest(.{
        .root_module = blake3_heterogeneous_root,
        .filters = &.{ "metal: BLAKE3 heterogeneous commitment matches CPU transforms roots and openings", "metal: backed heterogeneous commit has one submit, one wait, and canonical root" },
    });
    linkRuntime(b, blake3_heterogeneous_tests);
    b.step("test-blake3-heterogeneous-commit", "Verify production heterogeneous BLAKE3 commitment and openings")
        .dependOn(&b.addRunArtifact(blake3_heterogeneous_tests).step);
    const blake3_direct_root = b.createModule(.{
        .root_source_file = b.path("blake3_direct_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_direct_root, core, backend_contracts, prover_api, prover);
    const blake3_direct_tests = b.addTest(.{ .root_module = blake3_direct_root, .filters = &.{"Metal BLAKE3 direct full trees match CPU with wide offset dispatch"} });
    linkRuntime(b, blake3_direct_tests);
    b.step("test-blake3-direct-tree", "Verify BLAKE3 direct commitment with wide offsets")
        .dependOn(&b.addRunArtifact(blake3_direct_tests).step);
    const blake3_uniform_root = b.createModule(.{
        .root_source_file = b.path("blake3_heterogeneous_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_uniform_root, core, backend_contracts, prover_api, prover);
    const blake3_uniform_tests = b.addTest(.{ .root_module = blake3_uniform_root, .filters = &.{
        "metal: BLAKE3 uniform precommits match CPU transforms roots and receipts",
        "metal: uniform owned and polynomial precommits return device receipts",
    } });
    linkRuntime(b, blake3_uniform_tests);
    b.step("test-blake3-uniform-commit", "Verify BLAKE3 uniform transform and commit")
        .dependOn(&b.addRunArtifact(blake3_uniform_tests).step);
    const blake3_transcript_root = b.createModule(.{
        .root_source_file = b.path("blake3_transcript_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_transcript_root, core, backend_contracts, prover_api, prover);
    const blake3_transcript_tests = b.addTest(.{ .root_module = blake3_transcript_root });
    linkRuntime(b, blake3_transcript_tests);
    b.step("test-blake3-transcript", "Verify resident BLAKE3 framing and secure draws")
        .dependOn(&b.addRunArtifact(blake3_transcript_tests).step);
    const blake3_cascade_root = b.createModule(.{
        .root_source_file = b.path("blake3_cascade_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(blake3_cascade_root, core, backend_contracts, prover_api, prover);
    const blake3_cascade_tests = b.addTest(.{ .root_module = blake3_cascade_root, .filters = &.{
        "metal: BLAKE3 FRI cascade preserves roots transcript and folds in one submission",
        "metal: BLAKE3 backend cascade admits resident inverse domains",
        "metal: BLAKE3 circle FRI prover matches CPU commitments and openings",
        "metal: BLAKE3 quotient FRI transaction matches CPU and verifier",
        "metal: BLAKE2s quotient FRI transaction matches CPU and verifier",
        "metal: line FRI cascade preserves every root, challenge, and final value",
        "opening bindings retain canonical shared ABI parameter types",
        "Ethereum AOT profile preserves exact core authority and admits five separate declarations",
        "recursive framework AOT profile preserves core authority and exact declaration coverage",
    } });
    linkRuntime(b, blake3_cascade_tests);
    b.step("test-blake3-fri-cascade", "Verify BLAKE3 roots challenges and folds in one cascade")
        .dependOn(&b.addRunArtifact(blake3_cascade_tests).step);
    const proof_of_work_root = b.createModule(.{
        .root_source_file = b.path("proof_of_work_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(proof_of_work_root, core, backend_contracts, prover_api, prover);
    const proof_of_work_tests = b.addTest(.{
        .root_module = proof_of_work_root,
        .filters = &.{ "metal proof of work returns the canonical Stwo nonce", "metal BLAKE3 proof of work matches canonical nonces with device dispatch" },
    });
    linkRuntime(b, proof_of_work_tests);
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

    const small_lde_root = b.createModule(.{
        .root_source_file = b.path("circle_lde_small_alias_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(small_lde_root, core, backend_contracts, prover_api, prover);
    const small_lde_tests = b.addTest(.{ .root_module = small_lde_root, .filters = &.{"metal small LDE "} });
    linkRuntime(b, small_lde_tests);
    b.step("test-small-circle-lde-alias", "Test adopted small-circle source ownership without a Metal device")
        .dependOn(&b.addRunArtifact(small_lde_tests).step);

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
            "metal: host barycentric staging reuses bounded slab across runs",
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
        // Eight named semantic tests plus the root import closure.
        .filters = &.{
            "Metal quotient internal parity binds two cumulative raw segments and final output",
            "Metal quotient incremental oracle is scheduling independent across four workers",
            "Metal quotient internal parity reports segment component row coordinate mutation",
            "Metal quotient internal parity rejects domain and source-run authority drift",
            "Metal quotient internal parity reports finalized quotient mutation before FRI",
            "Metal quotient internal parity releases every diagnostic allocation",
            "Metal quotient wide source views reject wrap reorder and local overflow",
            "Metal raw quotient wide sources stay segmented despite fragmentation",
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
    if (artifact.root_module != b.modules.get("stwo_metal_backend").?) artifact.addCSourceFile(.{
        .file = b.path("runtime.m"),
        .flags = runtime_source.flags(b, b.pathFromRoot("runtime.m")),
    });
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
