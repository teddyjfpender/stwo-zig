const support = @import("build_support.zig");

pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const core = ctx.core;
    const prover = ctx.prover;
    const prover_api = ctx.prover_api;
    const cpu_backend = ctx.cpu_backend;
    const frontend = ctx.frontend;
    const postcard = ctx.postcard;
    const integration = ctx.integration;
    const segment_v2_leaf_outer_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_leaf_outer_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_leaf_outer_root.addImport("stwo_prover_api", prover_api);
    segment_v2_leaf_outer_root.addImport("stwo_prover_engine", prover);
    const segment_v2_leaf_outer_compile = b.addTest(.{
        .root_module = segment_v2_leaf_outer_root,
    });
    b.step(
        "check-recursive-segment-v2-leaf-outer",
        "Compile the Poseidon2 native-capture to recursive V2 leaf handoff",
    ).dependOn(&segment_v2_leaf_outer_compile.step);
    const segment_v2_leaf_outer_tests = b.addRunArtifact(
        segment_v2_leaf_outer_compile,
    );
    segment_v2_leaf_outer_tests.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-leaf-outer",
        "Run the focused V2 recursive leaf handoff and mutation gates",
    ).dependOn(&segment_v2_leaf_outer_tests.step);
    const segment_v2_noncore_owner_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_noncore_owner_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_noncore_owner_root.addImport("stwo_prover_api", prover_api);
    segment_v2_noncore_owner_root.addImport("stwo_prover_engine", prover);
    const segment_v2_noncore_owner_tests = b.addRunArtifact(b.addTest(.{
        .root_module = segment_v2_noncore_owner_root,
    }));
    segment_v2_noncore_owner_tests.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-noncore-owner",
        "Run the SegmentV2 non-core split-custody owner gate",
    ).dependOn(&segment_v2_noncore_owner_tests.step);
    const segment_v2_poseidon_ingress_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_leaf_outer_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_poseidon_ingress_root.addImport("stwo_prover_api", prover_api);
    segment_v2_poseidon_ingress_root.addImport("stwo_prover_engine", prover);
    segment_v2_poseidon_ingress_root.addImport("interop_postcard", postcard);
    const segment_v2_poseidon_ingress_test_names: []const []const u8 = &.{
        "generic Poseidon2 native V2 capture prepares the owned recursive leaf",
    };
    const segment_v2_poseidon_ingress_compile = b.addTest(.{
        .root_module = segment_v2_poseidon_ingress_root,
        .filters = segment_v2_poseidon_ingress_test_names,
    });
    b.step(
        "check-recursive-segment-v2-poseidon-ingress",
        "Compile the real Poseidon2 native-V2 recursive-ingress proof gate",
    ).dependOn(&segment_v2_poseidon_ingress_compile.step);
    const segment_v2_poseidon_ingress_tests = b.addRunArtifact(
        segment_v2_poseidon_ingress_compile,
    );
    segment_v2_poseidon_ingress_tests.has_side_effects = true;
    const segment_v2_poseidon_ingress_step = b.step(
        "test-recursive-segment-v2-poseidon-ingress",
        "Prove and verify one native V2 segment under the recursion Poseidon2 suite",
    );
    segment_v2_poseidon_ingress_step.dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_poseidon_ingress_tests,
        segment_v2_poseidon_ingress_test_names,
        "native V2 Poseidon recursive-ingress proof identity guard",
    ));
    const segment_v2_poseidon_ingress_runner_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_poseidon_ingress_runner.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_poseidon_ingress_runner_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    segment_v2_poseidon_ingress_runner_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    segment_v2_poseidon_ingress_runner_root.addImport(
        "interop_postcard",
        postcard,
    );
    const segment_v2_poseidon_ingress_runner = b.addExecutable(.{
        .name = "recursive-segment-v2-poseidon-ingress",
        .root_module = segment_v2_poseidon_ingress_runner_root,
    });
    const run_segment_v2_poseidon_ingress = b.addRunArtifact(
        segment_v2_poseidon_ingress_runner,
    );
    run_segment_v2_poseidon_ingress.has_side_effects = true;
    b.step(
        "run-recursive-segment-v2-poseidon-ingress",
        "Run the real V2 recursion ingress through the lean executable loop",
    ).dependOn(&run_segment_v2_poseidon_ingress.step);
    const segment_v2_outer_engine_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_outer_engine.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_outer_engine_root.addImport("stwo_prover_api", prover_api);
    segment_v2_outer_engine_root.addImport("stwo_prover_engine", prover);
    segment_v2_outer_engine_root.addImport("interop_postcard", postcard);
    const segment_v2_outer_engine_compile = b.addTest(.{
        .root_module = segment_v2_outer_engine_root,
        .filters = &.{
            "segment V2 verified-publication engine pins the 39-row three-tree protocol",
        },
    });
    b.step(
        "check-recursive-segment-v2-outer-engine",
        "Compile the verified-publication 39-row V2 outer transaction kernel",
    ).dependOn(&segment_v2_outer_engine_compile.step);
    b.step(
        "test-recursive-segment-v2-outer-engine",
        "Run the verified-publication 39-row V2 outer transaction kernel gate",
    ).dependOn(&b.addRunArtifact(segment_v2_outer_engine_compile).step);
    const segment_v2_verified_artifact_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_verified_artifact_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const segment_v2_verified_artifact_tests = b.addTest(.{
        .root_module = segment_v2_verified_artifact_root,
        .filters = &.{
            "SegmentV2 recursive-witness fixed preflight",
            "SegmentV2 recursive-witness capture preflight",
        },
    });
    b.step(
        "check-recursive-segment-v2-verified-artifact",
        "Compile the fixed verifier-minted SegmentV2 recursive witness",
    ).dependOn(&segment_v2_verified_artifact_tests.step);
    b.step(
        "test-recursive-segment-v2-verified-artifact",
        "Run the SegmentV2 recursive-witness preflight mutation fleet",
    ).dependOn(&b.addRunArtifact(segment_v2_verified_artifact_tests).step);
    const segment_v2_outer_cohort_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_outer_cohort_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_outer_cohort_root.addImport("stwo_prover_api", prover_api);
    segment_v2_outer_cohort_root.addImport("stwo_prover_engine", prover);
    segment_v2_outer_cohort_root.addImport("interop_postcard", postcard);
    const segment_v2_outer_cohort_compile = b.addTest(.{
        .root_module = segment_v2_outer_cohort_root,
    });
    b.step(
        "check-recursive-segment-v2-outer-cohort",
        "Compile the concrete 39-row SegmentV2 cohort and engine contract",
    ).dependOn(&segment_v2_outer_cohort_compile.step);
    b.step(
        "test-recursive-segment-v2-outer-cohort",
        "Run the concrete SegmentV2 cohort ownership and engine-contract gate",
    ).dependOn(&b.addRunArtifact(segment_v2_outer_cohort_compile).step);
    const segment_v2_concrete_outer_proof_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_concrete_outer_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_concrete_outer_proof_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    segment_v2_concrete_outer_proof_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    segment_v2_concrete_outer_proof_root.addImport(
        "interop_postcard",
        postcard,
    );
    const segment_v2_concrete_outer_proof_name =
        "SegmentV2 concrete 39-row outer proof independently verifies all 47 domains";
    const segment_v2_concrete_outer_proof_compile = b.addTest(.{
        .root_module = segment_v2_concrete_outer_proof_root,
        .filters = &.{segment_v2_concrete_outer_proof_name},
    });
    b.step(
        "check-recursive-segment-v2-concrete-outer-proof",
        "Compile the real 39-row SegmentV2 outer proof without executing it",
    ).dependOn(&segment_v2_concrete_outer_proof_compile.step);
    const segment_v2_concrete_outer_proof_tests = b.addRunArtifact(
        segment_v2_concrete_outer_proof_compile,
    );
    segment_v2_concrete_outer_proof_tests.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-concrete-outer-proof",
        "Prove and independently verify the real 39-row SegmentV2 outer AIR",
    ).dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_concrete_outer_proof_tests,
        &.{segment_v2_concrete_outer_proof_name},
        "SegmentV2 concrete outer-proof identity guard",
    ));
    const segment_v2_recorder_row18_name =
        "SegmentV2 finalized heterogeneous recorder evaluates real row18 witness";
    const segment_v2_recorder_row18_compile = b.addTest(.{
        .root_module = segment_v2_concrete_outer_proof_root,
        .filters = &.{segment_v2_recorder_row18_name},
    });
    b.step(
        "check-recursive-segment-v2-recorder-row18",
        "Compile the focused real-child V3 recorder and row-18 runtime gate",
    ).dependOn(&segment_v2_recorder_row18_compile.step);
    const segment_v2_recorder_row18_tests = b.addRunArtifact(
        segment_v2_recorder_row18_compile,
    );
    segment_v2_recorder_row18_tests.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-recorder-row18",
        "Run the focused real-child V3 recorder and row-18 runtime gate",
    ).dependOn(&segment_v2_recorder_row18_tests.step);
    const temporal_parent_real_proof_root = support.createHarnessModule(
        b,
        "recursive_temporal_parent_real_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_parent_real_proof_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    temporal_parent_real_proof_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    temporal_parent_real_proof_root.addImport(
        "interop_postcard",
        postcard,
    );
    const temporal_parent_real_proof_name =
        "real authenticated temporal SegmentV2 2-to-1 parent independently verifies";
    const temporal_parent_real_proof_compile = b.addTest(.{
        .root_module = temporal_parent_real_proof_root,
        .filters = &.{temporal_parent_real_proof_name},
    });
    b.step(
        "check-recursive-temporal-parent-real-proof",
        "Compile the authenticated temporal SegmentV2 2-to-1 parent proof",
    ).dependOn(&temporal_parent_real_proof_compile.step);
    const temporal_parent_real_proof_tests = b.addRunArtifact(
        temporal_parent_real_proof_compile,
    );
    temporal_parent_real_proof_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-parent-real-proof",
        "Prove and independently verify the authenticated temporal 2-to-1 parent",
    ).dependOn(support.ProofTestGuard.add(
        b,
        temporal_parent_real_proof_tests,
        &.{temporal_parent_real_proof_name},
        "Authenticated temporal parent proof identity guard",
    ));
    const temporal_multilevel_real_proof_root = support.createHarnessModule(
        b,
        "recursive_temporal_multilevel_real_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_multilevel_real_proof_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    temporal_multilevel_real_proof_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    temporal_multilevel_real_proof_root.addImport(
        "interop_postcard",
        postcard,
    );
    const temporal_multilevel_real_proof_name =
        "real four-leaf temporal tree authenticates two verified parents";
    const temporal_multilevel_real_proof_compile = b.addTest(.{
        .root_module = temporal_multilevel_real_proof_root,
        .filters = &.{temporal_multilevel_real_proof_name},
    });
    b.step(
        "check-recursive-temporal-multilevel-real-proof",
        "Compile the authenticated four-leaf temporal aggregation gate",
    ).dependOn(&temporal_multilevel_real_proof_compile.step);
    const temporal_multilevel_real_proof_tests = b.addRunArtifact(
        temporal_multilevel_real_proof_compile,
    );
    temporal_multilevel_real_proof_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-multilevel-real-proof",
        "Verify two temporal parents and authenticate their height-2 root",
    ).dependOn(support.ProofTestGuard.add(
        b,
        temporal_multilevel_real_proof_tests,
        &.{temporal_multilevel_real_proof_name},
        "Authenticated multi-level temporal identity guard",
    ));
    const temporal_parent_real_runner_root = support.createHarnessModule(
        b,
        "recursive_temporal_parent_real_proof_runner.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_parent_real_runner_root.addImport("stwo_prover_api", prover_api);
    temporal_parent_real_runner_root.addImport("stwo_prover_engine", prover);
    temporal_parent_real_runner_root.addImport("interop_postcard", postcard);
    const temporal_parent_real_runner = b.addExecutable(.{
        .name = "recursive-temporal-parent-real-proof",
        .root_module = temporal_parent_real_runner_root,
    });
    b.step(
        "check-recursive-temporal-parent-real-proof-runner",
        "Compile the lean authenticated temporal-parent proof runner",
    ).dependOn(&temporal_parent_real_runner.step);
    const run_temporal_parent_real = b.addRunArtifact(
        temporal_parent_real_runner,
    );
    run_temporal_parent_real.has_side_effects = true;
    b.step(
        "run-recursive-temporal-parent-real-proof",
        "Run the authenticated temporal parent through the lean proof loop",
    ).dependOn(&run_temporal_parent_real.step);
    const segment_v2_concrete_outer_runner_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_concrete_outer_proof_runner.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_concrete_outer_runner_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    segment_v2_concrete_outer_runner_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    segment_v2_concrete_outer_runner_root.addImport(
        "interop_postcard",
        postcard,
    );
    const segment_v2_concrete_outer_runner = b.addExecutable(.{
        .name = "recursive-segment-v2-concrete-outer-proof",
        .root_module = segment_v2_concrete_outer_runner_root,
    });
    const run_segment_v2_concrete_outer = b.addRunArtifact(
        segment_v2_concrete_outer_runner,
    );
    run_segment_v2_concrete_outer.has_side_effects = true;
    b.step(
        "run-recursive-segment-v2-concrete-outer-proof",
        "Run the real 39-row SegmentV2 outer proof through the lean loop",
    ).dependOn(&run_segment_v2_concrete_outer.step);
    const segment_v2_outer_proof_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_outer_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const segment_v2_outer_proof_test_names: []const []const u8 = &.{
        "SegmentV2 real outer proof remains explicitly unavailable without a concrete cohort",
        "SegmentV2 outer harness rejects boundary-claim and provider-schedule mutation",
    };
    const segment_v2_outer_proof_compile = b.addTest(.{
        .root_module = segment_v2_outer_proof_root,
        .filters = segment_v2_outer_proof_test_names,
    });
    b.step(
        "check-recursive-segment-v2-outer-proof",
        "Compile the complete 39-row V2 outer-proof harness",
    ).dependOn(&segment_v2_outer_proof_compile.step);
    const segment_v2_outer_proof_tests = b.addRunArtifact(
        segment_v2_outer_proof_compile,
    );
    segment_v2_outer_proof_tests.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-outer-proof",
        "Run the complete V2 outer-proof readiness and mutation gate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_outer_proof_tests,
        segment_v2_outer_proof_test_names,
        "Segment V2 outer harness identity guard",
    ));
    const mutation_tests = b.addRunArtifact(b.addTest(.{
        .root_module = support.createHarnessModule(
            b,
            "guest_precompile_mutation_fleet_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    }));
    const parent_statement_tests = b.addRunArtifact(b.addTest(.{
        .root_module = support.createHarnessModule(
            b,
            "recursive_parent_statement_source_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    }));
    b.step(
        "test-recursive-parent-statement-source",
        "Run the exact VerifiedOuterProofV1 parent-statement custody adapter",
    ).dependOn(&parent_statement_tests.step);

    ctx.test_step.dependOn(&mutation_tests.step);
    ctx.test_step.dependOn(&parent_statement_tests.step);
}
