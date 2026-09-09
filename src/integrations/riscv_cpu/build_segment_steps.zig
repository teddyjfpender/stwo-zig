const support = @import("build_support.zig");

pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const artifact_store = ctx.artifact_store;
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
    const segment_v2_verifier_components_root = support.createHarnessModule(
        b,
        "recursive_segment_v2_verifier_components_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_verifier_components_root.addImport("stwo_prover_engine", prover);
    const segment_v2_verifier_components_names: []const []const u8 = &.{
        "SegmentV2 witness-free verifier owns all39 canonical adapters and untrusted claims",
        "SegmentV2 witness-free verifier rejects malformed admission and inactive or provider claims",
        "SegmentV2 witness-free verifier releases its owner after initial definition allocation failure",
        "SegmentV2 witness-free recording keeps all39 claims and two provider partials symbolic",
    };
    const segment_v2_verifier_components_compile = b.addTest(.{
        .root_module = segment_v2_verifier_components_root,
        .filters = segment_v2_verifier_components_names,
    });
    b.step(
        "check-recursive-segment-v2-witness-free-verifier",
        "Compile the canonical SegmentV2 verifier without native witness owners",
    ).dependOn(&segment_v2_verifier_components_compile.step);
    const segment_v2_verifier_components_run = b.addRunArtifact(segment_v2_verifier_components_compile);
    segment_v2_verifier_components_run.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-witness-free-verifier",
        "Check all39 canonical witness-free adapters, input rejection and allocation cleanup",
    ).dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_verifier_components_run,
        segment_v2_verifier_components_names,
        "SegmentV2 witness-free verifier guard",
    ));
    const segment_v2_public_inputs_names: []const []const u8 = &.{
        "SegmentV2 expected public claim matches the active row36 AIR",
        "SegmentV2 expected public claim rejects changed wire keys manifest and claim",
        "SegmentV2 expected public claim rejects a zero relation denominator",
    };
    const segment_v2_public_inputs_compile = b.addTest(.{
        .root_module = segment_v2_verifier_components_root,
        .filters = segment_v2_public_inputs_names,
    });
    const segment_v2_public_inputs_run = b.addRunArtifact(segment_v2_public_inputs_compile);
    segment_v2_public_inputs_run.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-public-inputs",
        "Bind canonical expected statement and temporal context to the existing row36 claim",
    ).dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_public_inputs_run,
        segment_v2_public_inputs_names,
        "SegmentV2 expected public input guard",
    ));
    const segment_v2_detached_transcript_names: []const []const u8 = &.{
        "SegmentV2 detached fixed projection excludes source seals and pins circuit facts",
        "SegmentV2 detached transcript binds dynamic expected wire without specializing the key",
        "SegmentV2 detached claims share fixed lowering and expected row36 closure",
    };
    const segment_v2_detached_transcript_compile = b.addTest(.{
        .root_module = segment_v2_verifier_components_root,
        .filters = segment_v2_detached_transcript_names,
    });
    const segment_v2_detached_transcript_run = b.addRunArtifact(segment_v2_detached_transcript_compile);
    segment_v2_detached_transcript_run.has_side_effects = true;
    b.step(
        "test-recursive-segment-v2-detached-transcript",
        "Check independently pinned fixed projection and dynamic SegmentV2 statement/claim frames",
    ).dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_detached_transcript_run,
        segment_v2_detached_transcript_names,
        "SegmentV2 detached transcript guard",
    ));
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
    const temporal_height3_real_proof_root = support.createHarnessModule(
        b,
        "recursive_temporal_height3_real_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_height3_real_proof_root.addImport("stwo_prover_api", prover_api);
    temporal_height3_real_proof_root.addImport("stwo_prover_engine", prover);
    temporal_height3_real_proof_root.addImport("interop_postcard", postcard);
    const temporal_height3_real_proof_name =
        "real eight-leaf temporal tree proves and freshly verifies height three";
    const temporal_height3_real_proof_compile = b.addTest(.{
        .root_module = temporal_height3_real_proof_root,
        .filters = &.{temporal_height3_real_proof_name},
    });
    b.step(
        "check-recursive-temporal-height3-real-proof",
        "Compile generic eight-leaf height-3 temporal recursion closure",
    ).dependOn(&temporal_height3_real_proof_compile.step);
    const temporal_height3_real_proof_tests = b.addRunArtifact(
        temporal_height3_real_proof_compile,
    );
    temporal_height3_real_proof_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-height3-real-proof",
        "Prove and freshly verify the generic height-3 temporal root",
    ).dependOn(support.ProofTestGuard.add(
        b,
        temporal_height3_real_proof_tests,
        &.{temporal_height3_real_proof_name},
        "Authenticated height-3 temporal identity guard",
    ));
    const temporal_topology_root = support.createHarnessModule(
        b,
        "recursive_temporal_topology_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_topology_root.addImport("stwo_prover_api", prover_api);
    temporal_topology_root.addImport("stwo_prover_engine", prover);
    temporal_topology_root.addImport("interop_postcard", postcard);
    const temporal_topology_compile = b.addTest(.{
        .root_module = temporal_topology_root,
    });
    b.step(
        "check-recursive-temporal-topology-v1",
        "Compile authenticated leaf-or-empty and 210-to-256 topology authority",
    ).dependOn(&temporal_topology_compile.step);
    b.step(
        "test-recursive-temporal-topology-v1",
        "Run leaf-or-empty mutation and exact height-8 topology gates",
    ).dependOn(&b.addRunArtifact(temporal_topology_compile).step);
    const recursive_node_artifact_root = support.createHarnessModule(
        b,
        "recursive_node_artifact_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_node_artifact_test_names: []const []const u8 = &.{
        "recursive node canonical codec and ordered children",
        "coordinate kind height and empty relabel mutations fail closed",
        "registry rejects circuit profile PCS and layout substitutions",
        "padding parity computes target and rejects every drift class",
        "mock 256-node fold has canonical order and one-leaf ancestor path",
        "parent StageAdapter releases both leases after sealing",
        "parent StageAdapter releases acquired leases on error paths",
        "fixed proof shape is minted from complete expanded cold capture",
        "current concrete shapes remain explicitly unadmitted",
    };
    const recursive_node_artifact_compile = b.addTest(.{
        .root_module = recursive_node_artifact_root,
        .filters = recursive_node_artifact_test_names,
    });
    b.step(
        "test-recursive-node-artifact-v1",
        "Run recursive-node ABI, registry, padding, and stage-adapter gates",
    ).dependOn(&b.addRunArtifact(recursive_node_artifact_compile).step);
    const recursive_field_node_public_root = support.createHarnessModule(
        b,
        "recursive_field_node_public_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_field_node_public_compile = b.addTest(.{
        .root_module = recursive_field_node_public_root,
        .filters = &.{
            "field node public V2 folds ordered children and round trips canonically",
            "field node public V2 rejects source word order and digest mutations",
        },
    });
    b.step(
        "test-recursive-field-node-public-v2",
        "Run field-native recursive public ABI and ordered-fold gates",
    ).dependOn(&b.addRunArtifact(recursive_field_node_public_compile).step);
    const recursive_node_artifact_v2_root = support.createHarnessModule(
        b,
        "recursive_node_artifact_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_node_artifact_v2_compile = b.addTest(.{
        .root_module = recursive_node_artifact_v2_root,
        .filters = &.{
            "recursive node V2 codec binds field public semantics and transport SHA",
            "recursive node V2 rejects SHA as semantics and every authority drift",
        },
    });
    b.step(
        "test-recursive-node-artifact-v2",
        "Run field-native recursive node artifact and transport receipt gates",
    ).dependOn(&b.addRunArtifact(recursive_node_artifact_v2_compile).step);
    const recursive_node_artifact_store_root = support.createHarnessModule(
        b,
        "recursive_node_artifact_store_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_node_artifact_store_test_names: []const []const u8 = &.{
        "recursive artifact store binds Lane C refs to Zig key and manifest goldens",
        "recursive artifact store rejects child kind schema size security and binds order",
        "recursive artifact store transport cold-open detects CAS corruption",
        "recursive artifact store validator receipt remint preserves proof keys",
    };
    const recursive_node_artifact_store_compile = b.addTest(.{
        .root_module = recursive_node_artifact_store_root,
        .filters = recursive_node_artifact_store_test_names,
    });
    b.step(
        "test-recursive-node-artifact-store-v1",
        "Run shared-CAS recursive-node key, manifest, and transport gates",
    ).dependOn(&b.addRunArtifact(recursive_node_artifact_store_compile).step);
    const recursive_node_artifact_store_v2_root = support.createHarnessModule(
        b,
        "recursive_node_artifact_store_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_node_artifact_store_v2_compile = b.addTest(.{
        .root_module = recursive_node_artifact_store_v2_root,
        .filters = &.{
            "field recursive store publishes schema2 keys node and cold manifest",
            "field recursive store binds Poseidon semantics and rejects schema1 children",
        },
    });
    b.step(
        "test-recursive-node-artifact-store-v2",
        "Run field-native recursive CAS key, manifest, and transport gates",
    ).dependOn(&b.addRunArtifact(recursive_node_artifact_store_v2_compile).step);
    const recursive_common_wrapper_root = support.createHarnessModule(
        b,
        "recursive_common_wrapper_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_common_wrapper_test_names: []const []const u8 = &.{
        "common wrapper target requires three cold geometries and never squeezes",
        "common wrapper role contracts keep one fold and lease atomicity",
        "padding AIR enforces prefix count and every inactive column family",
        "NodePublic AIR binds all words identities digest and role authority",
    };
    const recursive_common_wrapper_compile = b.addTest(.{
        .root_module = recursive_common_wrapper_root,
        .filters = recursive_common_wrapper_test_names,
    });
    b.step(
        "test-recursive-common-wrapper-v1",
        "Run common-wrapper geometry, padding, public-ABI, and role gates",
    ).dependOn(&b.addRunArtifact(recursive_common_wrapper_compile).step);
    const recursive_common_wrapper_authority_root = support.createHarnessModule(
        b,
        "recursive_common_wrapper_authority_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_common_wrapper_authority_test_names: []const []const u8 = &.{
        "common wrapper live admission retains exact evidence and rejects capture drift",
        "common fold derives ordered parent NodePublic and rejects coordinate and statement drift",
    };
    const recursive_common_wrapper_authority_compile = b.addTest(.{
        .root_module = recursive_common_wrapper_authority_root,
        .filters = recursive_common_wrapper_authority_test_names,
    });
    b.step(
        "test-recursive-common-wrapper-authority-v1",
        "Run live wrapper admission and ordered common-fold public derivation gates",
    ).dependOn(&b.addRunArtifact(
        recursive_common_wrapper_authority_compile,
    ).step);
    const recursive_common_wrapper_authority_v2_root = support.createHarnessModule(
        b,
        "recursive_common_wrapper_authority_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_common_wrapper_authority_v2_compile = b.addTest(.{
        .root_module = recursive_common_wrapper_authority_v2_root,
        .filters = &.{
            "field wrapper admission requires exact expanded cold proof shape",
            "field wrapper derives the ordered parent without SHA semantics",
            "field common fold input retains two distinct live leases",
        },
    });
    b.step(
        "test-recursive-common-wrapper-authority-v2",
        "Run field-native live wrapper capture and ordered-fold gates",
    ).dependOn(&b.addRunArtifact(
        recursive_common_wrapper_authority_v2_compile,
    ).step);
    const recursive_campaign_padding_v2_root = support.createHarnessModule(
        b,
        "recursive_campaign_padding_v2_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    recursive_campaign_padding_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    recursive_campaign_padding_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    recursive_campaign_padding_v2_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    recursive_campaign_padding_v2_root.addImport(
        "interop_postcard",
        postcard,
    );
    const recursive_campaign_padding_v2_names: []const []const u8 = &.{
        "three cold active roles derive unequal-provider target and only remints mint parity",
        "padding remint rejects clone, active drift, layout drift, and failed cold source",
        "final registry admits campaign-bound artifact through store and worker siblings",
        "campaign Stage103 and Stage104 descriptions are Zig-owned and lease-free",
        "campaign empty source admits exact 13 to 16 range and cold roundtrips",
        "campaign empty source supports another non-eight depth and rejects authority drift",
    };
    const recursive_campaign_padding_v2_compile = b.addTest(.{
        .root_module = recursive_campaign_padding_v2_root,
        .filters = recursive_campaign_padding_v2_names,
    });
    b.step(
        "test-recursive-campaign-padding-v2",
        "Run campaign-bound padding remint, node, store, and empty-source gates",
    ).dependOn(&b.addRunArtifact(
        recursive_campaign_padding_v2_compile,
    ).step);
    const recursive_campaign_prefinal_v2_root = support.createHarnessModule(
        b,
        "recursive_pipeline_campaign_prefinal_v2_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    recursive_campaign_prefinal_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    recursive_campaign_prefinal_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    recursive_campaign_prefinal_v2_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    recursive_campaign_prefinal_v2_root.addImport(
        "interop_postcard",
        postcard,
    );
    const recursive_campaign_prefinal_v2_names: []const []const u8 = &.{
        "pre-final target and three cold remints mint one campaign authority",
        "final transaction rejects target source and final geometry mutation",
        "typed pre-final union preserves nominal roles and fails without cold projection",
        "pre-final union rejects target pointer and role geometry mutation",
        "execution policy saturates configurable cores under both token caps",
        "execution policy is execution-key-bound and rejects oversubscription",
        "runtime campaign scheduler prefers ready parents and respects dual tokens",
        "scheduler topology is runtime-derived across depths and host capacities",
        "scheduler authority and leases have no durable codec",
        "campaign pre-final role0 child is cold-owned and fail-closed on padding",
        "campaign pre-final role2 types retain typed children and no durable node",
        "campaign final role2 family is self-recursive and owns reopened children",
        "Stage102 builder deep-owns every transient admission projection",
        "Stage102 builder authority remains unrouteable and nonserializable",
        "campaign final driver derives nonlegacy topology and exact execution envelope",
        "campaign final composite owns nominal 102 103 104 leases and stays closed",
        "campaign q193 nominal pair plans derive every role from runtime shape",
        "campaign role1 and role2 q193 gates bind ExecutionKey workers and RSS",
        "campaign final live runtime production types close while unavailable",
        "campaign target-native q193 exact bodies compile without running proof",
        "campaign q193 lifecycle plan binds final driver topology and execution envelope",
        "campaign final assembly bound runtime production types close while unavailable",
        "campaign final role2 transitive q193 exact bodies compile while unavailable",
        "genuine three-leaf tree gate exact production leases compile while unavailable",
    };
    const recursive_campaign_prefinal_v2_compile = b.addTest(.{
        .root_module = recursive_campaign_prefinal_v2_root,
        .filters = recursive_campaign_prefinal_v2_names,
    });
    b.step(
        "test-recursive-pipeline-campaign-prefinal-v2",
        "Run non-circular campaign padding, pre-final lease, and scheduler gates",
    ).dependOn(&b.addRunArtifact(
        recursive_campaign_prefinal_v2_compile,
    ).step);
    const recursive_campaign_consumers_v2_root = support.createHarnessModule(
        b,
        "recursive_pipeline_worker_campaign_consumers_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    recursive_campaign_consumers_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    recursive_campaign_consumers_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    const recursive_campaign_consumers_v2_names: []const []const u8 = &.{
        "campaign Stage103 and Stage104 siblings are typed and unrouteable",
        "process-local throughput receipts reject capability and counter drift",
    };
    const recursive_campaign_consumers_v2_compile = b.addTest(.{
        .root_module = recursive_campaign_consumers_v2_root,
        .filters = recursive_campaign_consumers_v2_names,
    });
    b.step(
        "check-recursive-pipeline-campaign-consumers-v2",
        "Compile campaign Stage103/104 and verifier-throughput contracts",
    ).dependOn(&recursive_campaign_consumers_v2_compile.step);
    b.step(
        "test-recursive-pipeline-campaign-consumers-v2",
        "Run campaign consumer and process-local receipt mutation gates",
    ).dependOn(&b.addRunArtifact(
        recursive_campaign_consumers_v2_compile,
    ).step);
    const recursive_campaign_real_leaf_v4_root = support.createHarnessModule(
        b,
        "recursive_pipeline_worker_campaign_real_leaf_v4_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    recursive_campaign_real_leaf_v4_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    recursive_campaign_real_leaf_v4_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    recursive_campaign_real_leaf_v4_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    recursive_campaign_real_leaf_v4_root.addImport(
        "interop_postcard",
        postcard,
    );
    const recursive_campaign_real_leaf_v4_names: []const []const u8 = &.{
        "campaign Stage102 worker fixes one proof dependency and seal-last output",
        "campaign Stage102 generic adapter stays unavailable without authorities",
        "campaign Stage102 real backend and final fold lease type-check separately",
        "campaign two-stage composite keeps the production route unavailable",
        "campaign two-stage composite forwards execution and exact native lease",
        "campaign two-stage tagged lease has no durable capability codec",
        "native Stage101 execution adapter derives one strict bounded request",
        "Stage102 typed semantic options preserve generic key and campaign projection domains",
        "Stage102 worker builder seals a two-leaf CAS inventory then replays it",
        "Stage102 worker builder canonicalizes an out-of-order three-leaf inventory",
        "Stage102 final lifecycle quiesces live leases before immutable admission",
        "Stage102 final lifecycle resumes an incomplete three-leaf seal atomically",
        "Stage102 genuine gate bypasses only release checks across immutable install",
        "final worker bridge exact-matches immutable Stage102 authority and role0 admission",
        "role0 final frontier binds a two-row CAS inventory and policy",
        "role0 final frontier preserves non-power-of-two three-row order",
        "campaign final driver consumes a sealed two-row role0 frontier",
        "campaign final driver preserves a non-power-of-two role0 frontier",
        "live receipt binder admits two sealed role0 worker leases",
        "live receipt binder preserves a non-power-of-two three-row frontier",
        "Stage104 live-build executor contract stays unrouteable and opaque",
        "Stage104 worker failure retains both children and success cold-opens one parent",
        "campaign live-tree executor remains fixture-only and capability opaque",
        "campaign live-tree executes three real plus typed empty to one retained root",
        "campaign live committed-stage adapter borrows exact cold publication",
        "campaign final runtime epoch requires exact installed session and store",
        "campaign final runtime epoch destroys retained leases before lifecycle",
        "owned campaign runtime quiesces leases and returns installed lifecycle",
        "owned campaign runtime rejects atomically and fully tears down in order",
        "campaign runtime guard exact-binds assembly and active sources",
        "campaign assembly guard tears down leases before installed authority",
        "final Stage102 lifecycle emits deterministic two and three row receipts",
        "final Stage102 receipt output remains intact when live validation fails",
        "final Stage102 receipt bridge stays unrouteable and owner stays opaque",
        "genuine three-leaf final-remint fixture rejects non-3-to-4 campaign before q193",
        "genuine three-leaf fixture rejects unauthenticated STWCIT04 refs before q193",
        "genuine 3-to-4 three-cold-proof FinalRemint exact body compiles without q193",
        "role0 transitive genuine gate returns exact production lease and bypasses only release flag",
        "immutable Stage102 session exposes only exact-body role0 gate before activation",
        "authenticated Stage101 owner is runtime-count cold custody, never a codec",
        "authenticated Stage101 publication binds ordered table row and exact keys",
        "authenticated Stage101 table ref pins runtime cardinality before Store access",
    };
    const recursive_campaign_real_leaf_v4_compile = b.addTest(.{
        .root_module = recursive_campaign_real_leaf_v4_root,
        .filters = recursive_campaign_real_leaf_v4_names,
    });
    b.step(
        "test-recursive-pipeline-worker-campaign-real-leaf-v4-structural",
        "Run campaign-native Stage102 worker and cold-fold lease type gates",
    ).dependOn(&b.addRunArtifact(
        recursive_campaign_real_leaf_v4_compile,
    ).step);
    const recursive_common_fold_field_public_v2_root = support.createHarnessModule(
        b,
        "recursive_common_fold_field_public_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_common_fold_field_public_v2_compile = b.addTest(.{
        .root_module = recursive_common_fold_field_public_v2_root,
        .filters = &.{
            "common fold derives exact field parent and 116 Poseidon calls",
            "common fold schedule rejects call child order and coordinate drift",
            "suffix input producer is tuple-derived and policy rejects wrong role",
            "field statement bridge rejects noncanonical limb aliases",
        },
    });
    b.step(
        "test-recursive-common-fold-field-public-v2",
        "Run field-native common-fold parent and Poseidon schedule gates",
    ).dependOn(&b.addRunArtifact(
        recursive_common_fold_field_public_v2_compile,
    ).step);
    const incremental_leaf_field_public_v4_root = support.createHarnessModule(
        b,
        "recursive_common_ethereum_incremental_leaf_v4_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    incremental_leaf_field_public_v4_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    incremental_leaf_field_public_v4_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    incremental_leaf_field_public_v4_root.addImport(
        "interop_postcard",
        postcard,
    );
    const incremental_leaf_field_public_v4_test_names: []const []const u8 = &.{
        "Ethereum cohort replay publication preserves absent and present initial claims",
        "Ethereum cold composition admission rejects altered borrowed graph and ingress",
        "Ethereum native identity nonfinal completion requires explicit admitted program policy",
        "Ethereum native identity nonfinal completion closes real hash consumers exactly",
        "Ethereum composition profile small heterogeneous proof serializes destroys and freshly verifies",
        "Ethereum composition profile small heterogeneous proof rejects inconsistent split admission",
        "Ethereum failed wrapper replay rejects altered custody and success metadata",
        "Ethereum wrapper candidate custody rejects altered metadata path and bytes",
        "Ethereum cold geometry requires admitted split two composition columns",
        "Ethereum transcript prepared program",
        "Ethereum native Tree0 transcript pin rejects changed commitments and preserves source uses",
        "Ethereum symbolic wire boundary matches native constants outputs and changed challenges",
        "Ethereum symbolic wire boundary rejects changed admitted terms and output authority",
        "Ethereum symbolic public boundary matches native and rejects changed words and challenges",
        "Ethereum symbolic public boundary closes all 450 authenticated input sources",
        "Ethereum typed AIR compiled degree inventory",
        "Ethereum typed AIR preflight rejects dropped parameter changes",
        "Ethereum typed AIR nonzero domain and point equations agree",
        "Ethereum typed AIR production composition geometry agrees",
        "Ethereum wrapper composition admission selects only reviewed quotient domains",
        "Ethereum transcript prepared views expose deeply readonly rows and copied metadata",
        "Ethereum secure cohort metadata reads only its immutable admission",
        "Ethereum secure cohort admission rejects changed metadata even with replacement seals",
        "Ethereum public sums program mutation changes same geometry session and cache admission",
        "Ethereum initial secure circuit identities bind exact shape and arithmetic",
        "Ethereum initial secure circuit admission rejects drift and has no custody input",
        "Ethereum wrapper memory estimate handles mixed logs and overflow without allocation",
        "Ethereum tuple reservation preserves untouched capacity and exact initialized records",
        "Ethereum tuple reservation retains allocator ownership through growth and failure",
        "Ethereum public statement boundary exact tuples and negative claim",
        "Ethereum public statement boundary rejects changed public words and claims",
        "Ethereum schema4 frame plan separates dynamic custody from admitted shape",
        "Ethereum schema4 frame plan records exact claim and split-root obligations",
        "Ethereum native identity hashes preserve native digests and typed sources",
        "Ethereum native identity auxiliary bytes remain private with explicit hash custody",
        "Ethereum native identity routing closes exact authority payload and digest tuples",
        "Ethereum native identity routing keeps raw obligations and exact statement coordinates",
        "Ethereum native identity root joins close recorded limbs and public roots",
        "Ethereum native identity root joins reject aliases and reserve only four raw sources",
        "Ethereum control preparation reads immutable rows without revisiting native validation",
        "Ethereum schema4 frame payloads exactly match native recording encodings",
        "Ethereum schema4 metadata excludes custody digests and binds coordinate fields",
        "Ethereum schema4 explicit public IO and completion bind every data field",
        "Ethereum schema4 helper emission propagates sink failure",
        "Ethereum schema4 real admission frames preserve exact legacy schema2 and schema3 bytes",
        "Ethereum completion policy routes consume exact native relay values",
        "Ethereum completion policy publication relays the same native fields",
        "role0 schema3 base claim frames bind exact header and selected input words",
        "role0 secure wrapper policy requires field base claim admission",
        "Ethereum full leaf claim admission versions have fixed identities",
        "Ethereum bounded program admission owns the whole ELF and distinguishes unused bytes",
        "Ethereum bounded completion graph admits every executable PC and rejects field mutations",
        "Ethereum completion polynomial preflight rejects oversized and duplicate PC tables",
        "Ethereum role padding rejects noncanonical zero limbs",
        "Ethereum native publication count derives from operation effects including pow reset",
        "Ethereum role input routing counts only genuine claim consumers and shares publication values",
        "Ethereum nonfinal program profile rejects final halt missing duplicate and misplaced completion",
        "Ethereum role binding proves pointwise memory sources and rejects field-alias rewrites",
        "Ethereum role binding source coordinates remain fixed across input and output counts",
        "Ethereum public sum endpoint matches native cancellation and rejects every claim limb mutation",
        "Ethereum public sum fixed program removes only native program root anchor",
        "Ethereum canonical claim routing closes both composition and public cancellation consumers",
        "ethereum publication hash shared generator matches canonical sponge boundaries",
        "role0 wrapper replay retains bytes after producer destruction",
        "role0 Ethereum detailed claim frames authenticate exact input routing",
        "role0 Ethereum shared claim view preserves native transcript bytes and offsets",
        "role0 Ethereum singleton claim plan preserves native shape and base inputs",
        "role0 transcript clock metadata preserves the canonical statement route",
        "role0 clock input custody copies limbs and rejects malformed coordinates",
        "Ethereum clock routing pins shared AIR and preserves legacy namespaces",
        "Ethereum clock routing closes native sources and matches admitted graph wires",
        "Ethereum raw boundary clock accepts zero and native access bounds",
        "Ethereum raw boundary clock rejects aliases reserved residues and reverse time",
        "Ethereum raw boundary clock binds full u64 span and exact native limit",
        "Ethereum raw boundary clock binds every raw limb and auxiliary bits",
        "Ethereum raw boundary clock preserves private routing and canonical claim tail",
        "Ethereum global projection accepts full u64 positions with unchanged local clocks",
        "Ethereum global projection binds every word endpoint and auxiliary witness",
        "Ethereum global projection rejects overflow reversal aliases and shifted initial leaf",
        "Ethereum global projection full program preserves canonical tail and exact local fanout",
        "Ethereum schema4 frame routes preserve source joins and reject changed witnesses",
        "Ethereum global publication routes the graph value through public and hash boundaries",
        "Ethereum statement byte routing pins shared AIR",
        "Ethereum statement routing closes admitted graph sources and rejects missing duplicate shifted routes",
        "stage102 V4 cold input and field schedule APIs instantiate",
        "stage102 V4 source preimage pins role checkpoint and commitment order",
        "stage102 V4 source binds actual Ethereum completion word and tuple",
        "stage102 V4 schedule is exact 123-call field-native authority",
        "stage102 V4 public source cannot relabel canonical-empty or transport SHA",
        "stage102 V4 manifest admits statement-root physical layout",
        "stage102 V4 bridge projection pins the missing graph authority",
        "stage102 V4 materializer type retains live capture ownership",
        "role0 public sum reservation does not reject an admitted graph",
        "role0 default claim shape builds its complete semantics graph",
        "role0 transcript statement metadata matches the shared AIR input",
        "role0 public logup owners propagate authenticated native view rejection",
        "role0 relation rows preserve both values from each native draw",
        "role0 post-tree1 profile retains every native mix operation",
        "role0 recorded payload preserves legacy layout and constant-word metadata",
        "role0 completion claim consumes actual Ethereum decoded tuple",
        "role0 completion claim does not synthesize program term for halt",
        "schema3 role-aware IO stream is ordered injective and zero padded",
        "schema3 role-aware IO claims share the committed tuple witness",
        "schema3 source binds tuple count capacity and field commitment",
        "schema3 field schedule derives provider geometry from committed stream",
        "campaign provider geometry synthetic two-leaf maximum is checked",
        "campaign provider geometry binds order but not maximum position",
        "campaign provider geometry admits empty active prefixes and rejects forgery",
        "runtime campaign provider geometry admits authenticated non-power-of-two counts",
        "runtime campaign provider geometry binds inventory and rejects duplicate order",
        "runtime campaign subrange preserves coordinates through clone and rejects metadata mutation",
        "runtime campaign clone owns immutable observations after source destruction",
        "child-public binding rejects removed legacy claim hash admission",
        "child-public binding rejects an independently resealed IO hash",
        "child-public source snapshot deep owns IO and rejects changed admission values",
        "child-public source snapshot frees every partial allocation",
        "Ethereum child statement owns source snapshots and rejects changed prepared rows",
        "Ethereum child statement constructor unwinds every allocation failure",
        "row34 geometry binds transcript child IO publication and verifier core",
        "publication boundary receipt cannot mint complete row34 geometry",
        "row34 receipt rejects publication-only authority subdivision",
        "Ethereum prepared transcript and suffix owners hide mutable rows and plans",
        "Ethereum generated interaction audit matches canonical columns and independent cold sums",
        "stage102 role0 transcript cohort tree and tuple APIs instantiate",
        "stage102 role0 transcript rows retain inactive recursion lanes",
        "schema3 role0 cohort exposes exact 36-row closure without proof escalation",
        "role0 statement input allows its authenticated cross-component claim",
        "role0 native core publishes into the nominal universal manifest",
        "fresh composition schedule projection is deterministic across workers",
        "stage102 V4 fresh program custody rejects pointer and identity drift",
        "role0 genuine runtime allocator counts ownership and host workers",
    };
    const incremental_leaf_field_public_v4_compile = b.addTest(.{
        .root_module = incremental_leaf_field_public_v4_root,
        .filters = incremental_leaf_field_public_v4_test_names,
    });
    b.step(
        "test-recursive-common-ethereum-incremental-leaf-field-public-v4",
        "Run versioned real-leaf source, materializer, and public-semantics gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(incremental_leaf_field_public_v4_compile),
        incremental_leaf_field_public_v4_test_names,
        "recursive common Ethereum incremental leaf V4 structural guard",
    ));
    const compact_ledger_names = [_][]const u8{
        "Ethereum compact tuple ledger cleans up provider failures after source sealing",
        "Ethereum compact tuple ledger keeps map allocation failure sticky through cancellation",
        "Ethereum compact tuple ledger matches canonical records and range provider exactly",
        "Ethereum compact tuple ledger preserves cancellation counts without retained records",
        "Ethereum compact tuple ledger rejects malformed range requests before cancellation",
        "Ethereum compact tuple ledger checks initial histogram and source phase exactly",
        "Ethereum compact tuple ledger cleans up every allocation failure",
    };
    const validation_ownership_names: []const []const u8 = &(compact_ledger_names ++ [_][]const u8{
        "Ethereum cohort replay publication preserves absent and present initial claims",
        "Ethereum geometry rejects missing source admission before allocating preparation",
        "Ethereum native prepared projection owns inputs and moves buffers across every allocation failure",
        "schema3 source binds tuple count capacity and field commitment",
        "schema3 field schedule derives provider geometry from committed stream",
        "child-public source snapshot deep owns IO and rejects changed admission values",
        "child-public source snapshot frees every partial allocation",
        "Ethereum child statement owns source snapshots and rejects changed prepared rows",
        "Ethereum child statement constructor unwinds every allocation failure",
        "Ethereum prepared transcript and suffix owners hide mutable rows and plans",
        "Ethereum generated interaction audit matches canonical columns and independent cold sums",
        "runtime campaign clone owns immutable observations after source destruction",
        "stage102 role0 transcript cohort tree and tuple APIs instantiate",
        "schema3 role0 cohort exposes exact 36-row closure without proof escalation",
    });
    const compact_ledger = support.createHarnessModule(b, "recursive_compact_tuple_ledger_v1_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    compact_ledger.addImport("stwo_prover_engine", prover);
    compact_ledger.addImport("stwo_prover_api", prover_api);
    compact_ledger.addImport("interop_postcard", postcard);
    const compact_ledger_test = b.addTest(.{ .root_module = compact_ledger, .filters = &compact_ledger_names });
    b.step("test-recursive-compact-tuple-ledger", "Check exact ledger parity, provider phases and allocation failures").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(compact_ledger_test), &compact_ledger_names, "Recursive compact tuple ledger guard"));
    const validation_ownership = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = validation_ownership_names });
    b.step("test-ethereum-validation-ownership", "Check immutable preparation ownership, generated/cold audit parity and allocation rollback").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(validation_ownership), validation_ownership_names, "Ethereum validation ownership guard"));
    const witness_free_names: []const []const u8 = &.{
        "Ethereum fold fixed namespace excludes public custody and binds complete key",
        "Ethereum fold fixed transcript shares namespace and preserves legacy constructor",
        "Ethereum fold engine replay consumes admitted key and preserves legacy fallback",
        "Ethereum grouped tree storage keeps logical columns and stable physical runs",
        "Ethereum grouped tree storage adopts coefficients with actual PCS root parity",
        "Ethereum witness-free verifier owns all36 components and survives external mutation",
        "Ethereum witness-free verifier rejects malformed admission and provider claims",
        "Ethereum witness-free verifier releases partial AIR construction on allocation failure",
        "Ethereum root key rejects malformed fixed admission",
        "Ethereum fixed field namespace excludes custody and binds root parameters anchors and profile",
        "Ethereum root key independently pinned transport owns decoded anchors",
        "Ethereum root wire closure uses shared constant and output signs",
        "Ethereum root detached transcript matches native semantic frames",
        "Ethereum detached field admission preserves session projection without custody",
        "Ethereum detached transcript dynamic frames match public wire and provider emitters",
        "Ethereum child fixed shape matches native component masks and split2 geometry",
        "Ethereum child fixed shape ignores compression and rejects raw slot mutations",
        "Ethereum child fixed shape owns key geometry and rejects changed admission",
        "Ethereum field fold derives selected wire dimensions from admitted manifest",
        "Ethereum field fold rejects wrong selected shape before proof parsing",
        "Ethereum root execution endpoint rejects canonical empty before proof decoding",
        "Ethereum native Tree0 admission derives once and rejects fixed shape mutations",
        "Ethereum native Tree0 fixed bridge selectors change actual PCS commitment",
        "Ethereum native verification scoped workers preserve actual FFT and Merkle roots",
        "Ethereum native bundle worker option is explicit and bounded",
        "Ethereum Tree0 preparation requires authenticated runtime before allocation",
    };
    const witness_free_root = support.createHarnessModule(b, "ethereum_wrapper_verifier_components_v1_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    witness_free_root.strip = ctx.ethereum_proof_strip;
    witness_free_root.addImport("stwo_prover_api", prover_api);
    witness_free_root.addImport("stwo_prover_engine", prover);
    witness_free_root.addImport("interop_postcard", postcard);
    const witness_free = b.addTest(.{ .root_module = witness_free_root, .filters = witness_free_names });
    b.step("test-ethereum-witness-free-verifier", "Construct all Ethereum verifier components from admitted circuit data without witness owners").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(witness_free), witness_free_names, "Ethereum witness-free verifier guard"));
    const initial_root_names: []const []const u8 = &.{
        "Ethereum witness-free verifier owns all36 components and survives external mutation",
        "Ethereum witness-free verifier rejects malformed admission and provider claims",
        "Ethereum witness-free verifier releases partial AIR construction on allocation failure",
        "Ethereum initial verifier owns38 typed components in exact claim order",
        "Ethereum fixed field namespace excludes custody and binds root parameters anchors and profile",
        "Ethereum root key rejects malformed fixed admission",
        "Ethereum root key independently pinned transport owns decoded anchors",
        "Ethereum root wire closure uses shared constant and output signs",
        "Ethereum root detached transcript matches native semantic frames",
        "Ethereum root execution endpoint rejects canonical empty before proof decoding",
        "Ethereum initial root transport pins38 key and owns exact child geometry",
        "Ethereum root transport selects initial mode only from explicit argument",
        "Ethereum root transport shares bundle location ownership across admitted profiles",
        "Ethereum child fixed shape matches native component masks and split2 geometry",
        "Ethereum child fixed shape ignores compression and rejects raw slot mutations",
        "Ethereum child fixed shape owns key geometry and rejects changed admission",
    };
    const initial_root = b.addTest(.{ .root_module = witness_free_root, .filters = initial_root_names });
    b.step("test-ethereum-initial-root-admission", "Check explicit initial38 verifier transport and unchanged ordinary36 admission").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(initial_root), initial_root_names, "Ethereum initial root admission guard"));
    const fixed_program_names: []const []const u8 = &.{
        "Ethereum fixed program admission pins whole ELF independently of compatibility root",
        "Ethereum fixed program table binds actual PCS root and preserves decoded columns",
        "Ethereum fixed program recursive Tree0 admission binds whole ELF beyond identical roots",
        "Ethereum completion opening authenticates every admitted raw and decoded leaf",
        "Ethereum completion opening preserves independent whole ELF and explicit opt in",
        "Ethereum completion opening rejects padded indices independently of hash equality",
    };
    const fixed_program = b.addTest(.{ .root_module = witness_free_root, .filters = fixed_program_names });
    b.step("test-ethereum-fixed-program-admission", "Check independently pinned ELF table and actual fixed-column PCS binding").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(fixed_program), fixed_program_names, "Ethereum fixed program admission guard"));
    const fixed_program_native_names: []const []const u8 = &.{"Ethereum fixed program native leaves destroy producer and freshly verify admitted ELF"};
    const fixed_program_native = b.addTest(.{ .root_module = witness_free_root, .filters = fixed_program_native_names });
    b.step("test-ethereum-fixed-program-native", "Prove two native fixed-program leaves and cold verify using independent ELF admission").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(fixed_program_native), fixed_program_native_names, "Ethereum fixed program native guard"));
    const fold_namespace_names: []const []const u8 = &.{
        "Ethereum fold fixed namespace excludes public custody and binds complete key",
        "Ethereum fold fixed transcript shares namespace and preserves legacy constructor",
        "Ethereum fold engine replay consumes admitted key and preserves legacy fallback",
        "Ethereum fixed field namespace excludes custody and binds root parameters anchors and profile",
        "Ethereum field fold derives selected wire dimensions from admitted manifest",
        "Ethereum field fold rejects wrong selected shape before proof parsing",
        "common-fold verifier transport authenticates key and rejects version drift",
    };
    const fold_namespace = b.addTest(.{ .root_module = witness_free_root, .filters = fold_namespace_names });
    b.step("test-ethereum-fold-fixed-namespace", "Check explicit fixed-root Ethereum fold IDs and unchanged legacy namespaces").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(fold_namespace), fold_namespace_names, "Ethereum fold fixed namespace guard"));
    const grouped_storage_names: []const []const u8 = &.{
        "Ethereum grouped tree storage keeps logical columns and stable physical runs",
        "Ethereum grouped tree storage adopts coefficients with actual PCS root parity",
    };
    const grouped_storage = b.addTest(.{ .root_module = witness_free_root, .filters = grouped_storage_names });
    b.step("test-ethereum-grouped-tree-storage", "Check stable physical height grouping and real PCS coefficient arena adoption").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(grouped_storage), grouped_storage_names, "Ethereum grouped tree storage guard"));
    const child_shape_names: []const []const u8 = &.{
        "Ethereum child fixed shape matches native component masks and split2 geometry",
        "Ethereum child fixed shape ignores compression and rejects raw slot mutations",
        "Ethereum child fixed shape owns key geometry and rejects changed admission",
    };
    const child_shape = b.addTest(.{ .root_module = witness_free_root, .filters = child_shape_names });
    b.step("test-ethereum-child-shape", "Derive fixed field9 child dimensions from admitted key and native sample masks").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(child_shape), child_shape_names, "Ethereum child shape guard"));
    const detached_fold_names: []const []const u8 = &.{
        "Ethereum field fold derives selected wire dimensions from admitted manifest",
        "Ethereum field fold rejects wrong selected shape before proof parsing",
    };
    const detached_fold = b.addTest(.{ .root_module = witness_free_root, .filters = detached_fold_names });
    b.step("test-ethereum-detached-field-fold", "Check the fixed-shape Ethereum adapter to existing fold AIR without activating fold admission").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_fold), detached_fold_names, "Ethereum detached field fold guard"));
    const detached_field_names: []const []const u8 = &.{"Ethereum detached transcript replays independently pinned field9 proof after input destruction"};
    const detached_field_root = support.createHarnessModule(b, "ethereum_wrapper_verifier_components_v1_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_field_root.strip = ctx.ethereum_proof_strip;
    detached_field_root.addImport("stwo_prover_api", prover_api);
    detached_field_root.addImport("stwo_prover_engine", prover);
    detached_field_root.addImport("interop_postcard", postcard);
    const detached_field = b.addTest(.{ .root_module = detached_field_root, .filters = detached_field_names });
    b.step("compile-ethereum-detached-field-transcript", "Compile the complete detached field9 replay and symbolic composition gate without requiring an artifact").dependOn(&detached_field.step);
    b.step("test-ethereum-detached-field-transcript", "Replay an independently pinned field9 wrapper as a recursive transcript witness without native children").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_field), detached_field_names, "Ethereum detached field transcript guard"));
    const prepared_wrapper_names: []const []const u8 = &.{
        "Ethereum cold composition admission rejects altered borrowed graph and ingress",
        "Ethereum cold proof immutable metadata reads require no source hierarchy",
        "Ethereum cold proof rejects resealed external source identity",
        "Ethereum public sums program mutation changes same geometry session and cache admission",
        "Ethereum initial secure circuit identities bind exact shape and arithmetic",
        "Ethereum initial secure circuit admission rejects drift and has no custody input",
        "Ethereum field transcript native emitters match explicit program frames",
        "Ethereum field transcript requires explicit admission and preserves legacy kind tags",
    };
    const prepared_wrapper = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = prepared_wrapper_names });
    b.step("test-ethereum-prepared-wrapper-boundary", "Check immutable cold proof views and explicit field transcript admission").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(prepared_wrapper), prepared_wrapper_names, "Ethereum prepared wrapper boundary guard"));
    const native_root_routing_names: []const []const u8 = &.{
        "Ethereum native continuation routing separates snapshot words and authenticates exact graph uses",
        "Ethereum native identity routing closes exact authority payload and digest tuples",
        "Ethereum native identity routing keeps raw obligations and exact statement coordinates",
        "Ethereum native identity root joins close recorded limbs and public roots",
        "Ethereum native identity root joins reject aliases and reserve only four raw sources",
        "Ethereum schema4 frame plan separates dynamic custody from admitted shape",
        "Ethereum schema4 frame plan records exact claim and split-root obligations",
        "Ethereum schema4 frame routes preserve source joins and reject changed witnesses",
    };
    const native_root_routing = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = native_root_routing_names });
    b.step("test-ethereum-native-root-routing", "Check canonical native root publication, distinct snapshot bindings and exact frame closure").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(native_root_routing), native_root_routing_names, "Ethereum native root routing guard"));
    const raw_clock_names: []const []const u8 = &.{
        "Ethereum raw boundary clock accepts zero and native access bounds",
        "Ethereum raw boundary clock rejects aliases reserved residues and reverse time",
        "Ethereum raw boundary clock binds full u64 span and exact native limit",
        "Ethereum raw boundary clock binds every raw limb and auxiliary bits",
        "Ethereum raw boundary clock preserves private routing and canonical claim tail",
        "Ethereum global projection accepts full u64 positions with unchanged local clocks",
        "Ethereum global projection binds every word endpoint and auxiliary witness",
        "Ethereum global projection rejects overflow reversal aliases and shifted initial leaf",
        "Ethereum global projection full program preserves canonical tail and exact local fanout",
    };
    const raw_clock = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = raw_clock_names });
    b.step("test-ethereum-raw-clock-boundary", "Check canonical register clocks, checked native cycle bounds and exact input routing").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(raw_clock), raw_clock_names, "Ethereum raw clock boundary guard"));
    const public_boundary_names: []const []const u8 = &.{
        "Ethereum wrapper candidate custody rejects altered metadata path and bytes",
        "Ethereum cold geometry requires admitted split two composition columns",
        "Ethereum transcript prepared program",
        "Ethereum symbolic wire boundary matches native constants outputs and changed challenges",
        "Ethereum symbolic wire boundary rejects changed admitted terms and output authority",
        "Ethereum symbolic public boundary matches native and rejects changed words and challenges",
        "Ethereum symbolic public boundary closes all 450 authenticated input sources",
        "Ethereum public sum endpoint matches native cancellation and rejects every claim limb mutation",
        "Ethereum public sum fixed program removes only native program root anchor",
    };
    const public_boundary = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = public_boundary_names });
    b.step("test-ethereum-symbolic-public-boundary", "Check native and symbolic public sums, exact sources and changed input rejection").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(public_boundary), public_boundary_names, "Ethereum symbolic public boundary guard"));
    const small_composition_names: []const []const u8 = &.{ "Ethereum composition profile small heterogeneous proof serializes destroys and freshly verifies", "Ethereum composition profile small heterogeneous proof rejects inconsistent split admission", "Ethereum composition profile mapped proof preserves bytes after scratch destruction" };
    const small_composition = b.addTest(.{ .root_module = incremental_leaf_field_public_v4_root, .filters = small_composition_names });
    b.step("test-ethereum-small-composition-proof", "Prove mixed quotient degrees, serialize, destroy producer state and independently verify").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(small_composition), small_composition_names, "Ethereum small composition proof guard"));
    const air_profile_names: []const []const u8 = &.{
        "Ethereum typed AIR compiled degree inventory",
        "Ethereum typed AIR preflight rejects dropped parameter changes",
        "Ethereum typed AIR nonzero domain and point equations agree",
        "Ethereum typed AIR production composition geometry agrees",
        "Ethereum wrapper composition admission selects only reviewed quotient domains",
    };
    const air_profile = b.addTest(.{
        .root_module = incremental_leaf_field_public_v4_root,
        .filters = air_profile_names,
    });
    b.step("test-ethereum-air-profile-preflight", "Inspect compiled typed AIR degrees and parameter invariants before loading proofs").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(air_profile), air_profile_names, "Ethereum AIR profile preflight guard"));
    const incremental_leaf_universal_proof_v4_root = support.createHarnessModule(
        b,
        "recursive_common_ethereum_incremental_leaf_universal_proof_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    incremental_leaf_universal_proof_v4_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    incremental_leaf_universal_proof_v4_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    incremental_leaf_universal_proof_v4_root.addImport(
        "interop_postcard",
        postcard,
    );
    const incremental_leaf_universal_proof_v4_names: []const []const u8 = &.{
        "role0 q193 cold owner and fold-child contracts instantiate",
        "role0 fold child is the typed schema4 real branch",
    };
    const incremental_leaf_universal_proof_v4_compile = b.addTest(.{
        .root_module = incremental_leaf_universal_proof_v4_root,
        .filters = incremental_leaf_universal_proof_v4_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-universal-proof-v4-structural",
        "Run the role0 q193 cold-owner and typed fold-child structure gates",
    ).dependOn(&b.addRunArtifact(
        incremental_leaf_universal_proof_v4_compile,
    ).step);
    const incremental_leaf_universal_genuine_compile_root =
        support.createHarnessModule(
            b,
            "recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        );
    incremental_leaf_universal_genuine_compile_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    incremental_leaf_universal_genuine_compile_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    incremental_leaf_universal_genuine_compile_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    incremental_leaf_universal_genuine_compile_root.addImport(
        "interop_postcard",
        postcard,
    );
    incremental_leaf_universal_genuine_compile_root.strip = ctx.ethereum_proof_strip;
    const incremental_leaf_universal_genuine_compile_names: []const []const u8 = &.{
        "role0 genuine two-leaf q193 proof cold-opens into neutral real child",
    };
    const incremental_leaf_universal_genuine_compile = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = incremental_leaf_universal_genuine_compile_names,
    });
    b.step(
        "check-ethereum-incremental-leaf-universal-proof-v4-genuine",
        "Compile the genuine two-segment role0 q193 transaction",
    ).dependOn(&incremental_leaf_universal_genuine_compile.step);
    const program_admission_names: []const []const u8 = &.{
        "role0 retained corpus records and reopens its whole program admission",
        "Ethereum bounded program admission owns the whole ELF and distinguishes unused bytes",
        "Ethereum bounded completion graph admits every executable PC and rejects field mutations",
        "Ethereum completion polynomial preflight rejects oversized and duplicate PC tables",
    };
    const program_admission_test = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = program_admission_names,
    });
    const program_admission_run = b.addRunArtifact(program_admission_test);
    program_admission_run.has_side_effects = true; // The retained corpus is an external input and output.
    b.step("test-ethereum-program-admission", "Retain whole-program admission material and test completion constraints").dependOn(support.ProofTestGuard.add(b, program_admission_run, program_admission_names, "Ethereum whole-program admission guard"));
    const native_base_bound_names: []const []const u8 = &.{
        "role0 schema3 native pair serializes destroys producer and freshly verifies",
    };
    const native_base_bound = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = native_base_bound_names,
    });
    const native_base_bound_run = b.addRunArtifact(native_base_bound);
    native_base_bound_run.has_side_effects = true; // Regenerate and reopen the requested external corpus every time.
    b.step("test-ethereum-native-base-bound-producer", "Produce versioned native Ethereum proof fixtures and verify after producer destruction").dependOn(support.ProofTestGuard.add(
        b,
        native_base_bound_run,
        native_base_bound_names,
        "schema3 native Ethereum proof lifecycle guard",
    ));
    const native_field_names: []const []const u8 = &.{"role0 field native pair serializes destroys producer and freshly verifies"};
    const native_field = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = native_field_names });
    const native_field_run = b.addRunArtifact(native_field);
    native_field_run.has_side_effects = true;
    b.step("test-ethereum-native-field-producer", "Retain field-authority native proofs and global metadata, destroy producer and freshly verify").dependOn(support.ProofTestGuard.add(b, native_field_run, native_field_names, "field native Ethereum proof lifecycle guard"));
    const statement_root_replay_names: []const []const u8 = &.{
        "role0 saved Stage101 proof binds dynamic statement roots",
    };
    const statement_root_replay = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = statement_root_replay_names,
    });
    b.step("test-ethereum-statement-root-replay", "Replay the genuine native capture under a root-independent graph and reject changed roots").dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(statement_root_replay),
        statement_root_replay_names,
        "saved Ethereum statement-root admission guard",
    ));
    const materialize_replay_names: []const []const u8 = &.{
        "role0 saved Stage101 proof replays VM composition",
    };
    const materialize_replay = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = materialize_replay_names,
    });
    b.step(
        "check-ethereum-incremental-leaf-materialize-v4-replay",
        "Compile the saved Stage101 VM composition replay",
    ).dependOn(&materialize_replay.step);
    b.step(
        "test-ethereum-incremental-leaf-materialize-v4-replay",
        "Cold-verify a pinned saved Stage101 leaf and replay its VM composition",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(materialize_replay),
        materialize_replay_names,
        "saved Ethereum leaf composition replay guard",
    ));

    b.step(
        "test-ethereum-incremental-leaf-universal-proof-v4-genuine",
        "Prove two native leaves and the genuine role0 q193 wrapper",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(incremental_leaf_universal_genuine_compile),
        incremental_leaf_universal_genuine_compile_names,
        "genuine two-segment Ethereum incremental role0 proof guard",
    ));
    const transcript_replay_names: []const []const u8 = &.{
        "role0 saved Stage101 proof replays transcript geometry",
    };
    const transcript_replay = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = transcript_replay_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-transcript-v4-replay",
        "Cold-verify a pinned Stage101 leaf and check transcript geometry before wrapper allocation",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(transcript_replay),
        transcript_replay_names,
        "saved Ethereum transcript geometry replay guard",
    ));
    const independent_input_names: []const []const u8 = &.{
        "role0 saved Stage101 pair destroys producer before rebuilding verifier inputs",
    };
    const independent_inputs = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = independent_input_names,
    });
    const independent_inputs_run = b.addRunArtifact(independent_inputs);
    independent_inputs_run.has_side_effects = true; // Reopen the current external corpus on every invocation.
    b.step("test-ethereum-independent-inputs-replay", "Destroy all producer input state and reconstruct verifier preparation from retained bytes").dependOn(support.ProofTestGuard.add(b, independent_inputs_run, independent_input_names, "Ethereum independent input reconstruction guard"));
    const complete_proof_names: []const []const u8 = &.{
        "role0 retained corpus records and reopens its whole program admission",
        "role0 saved Stage101 label input commitment is rejected",
        "role0 saved Stage101 pair replays recursive wrapper",
    };
    const geometry_preflight_names: []const []const u8 = &.{
        "role0 saved Stage101 pair checks wrapper geometry against pinned child key",
        "Ethereum wrapper geometry gate rejects every incompatible wire dimension",
    };
    const geometry_preflight = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = geometry_preflight_names });
    const geometry_preflight_run = b.addRunArtifact(geometry_preflight);
    geometry_preflight_run.has_side_effects = true;
    b.step("test-ethereum-wrapper-geometry", "Compare a retained wrapper candidate against an independently pinned child key before AIR row scans, ledger or PCS").dependOn(support.ProofTestGuard.add(b, geometry_preflight_run, geometry_preflight_names, "Ethereum wrapper geometry compatibility guard"));
    const air_preflight_names: []const []const u8 = &.{"role0 saved Stage101 pair checks typed AIR parameters before PCS"};
    const claim_replay_names: []const []const u8 = &.{"Ethereum retained real claim isolates snapshot and continuation semantics"};
    const claim_replay = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = claim_replay_names });
    const claim_replay_run = b.addRunArtifact(claim_replay);
    claim_replay_run.has_side_effects = true;
    b.step("test-ethereum-real-claim-boundary", "Replay the retained real claim boundary without native proving or wrapper construction").dependOn(support.ProofTestGuard.add(b, claim_replay_run, claim_replay_names, "Ethereum real claim boundary guard"));
    const air_preflight = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = air_preflight_names });
    const air_preflight_run = b.addRunArtifact(air_preflight);
    air_preflight_run.has_side_effects = true;
    b.step("test-ethereum-air-preflight", "Check real transcript and public AIR parameter rows before ledger and PCS allocations").dependOn(support.ProofTestGuard.add(b, air_preflight_run, air_preflight_names, "Ethereum genuine AIR preflight guard"));
    const native_allocator_names: []const []const u8 = &.{"role0 saved Stage101 pair compares native cold-open allocators"};
    const native_allocator = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = native_allocator_names });
    const native_allocator_run = b.addRunArtifact(native_allocator);
    native_allocator_run.has_side_effects = true;
    b.step("test-ethereum-native-cold-allocator", "Compare native cold-open allocators on the same retained pair with both captures alive").dependOn(support.ProofTestGuard.add(b, native_allocator_run, native_allocator_names, "Ethereum native cold allocator probe guard"));
    const complete_proof = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = complete_proof_names,
    });
    const complete_proof_run = b.addRunArtifact(complete_proof);
    complete_proof_run.has_side_effects = true; // A cached pass cannot attest to current retained input bytes.
    b.step("test-ethereum-complete-proof", "Run retained failure regression, prove, serialize, destroy producer state and independently verify").dependOn(support.ProofTestGuard.add(b, complete_proof_run, complete_proof_names, "Ethereum complete proof lifecycle guard"));
    b.step("check-ethereum-complete-proof", "Compile the complete Ethereum proof lifecycle and retained failure gate").dependOn(&complete_proof.step);
    const root_production_names: []const []const u8 = &.{
        "role0 retained corpus records and reopens its whole program admission",
        "role0 saved Stage101 label input commitment is rejected",
        "role0 saved Stage101 pair produces a durable root and independently verifies after destruction",
    };
    const root_production = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = root_production_names });
    const root_production_run = b.addRunArtifact(root_production);
    root_production_run.has_side_effects = true; // Produce and independently reopen the current external root candidate.
    b.step("test-ethereum-root-production", "Prove the complete ordinary Ethereum root, retain durable bytes, destroy producer state and independently verify exact public inputs").dependOn(support.ProofTestGuard.add(b, root_production_run, root_production_names, "Ethereum root production lifecycle guard"));
    b.step("check-ethereum-root-production", "Compile the complete ordinary Ethereum root production lifecycle and retained failure gate").dependOn(&root_production.step);
    const candidate_replay_names: []const []const u8 = &.{"role0 retained wrapper candidate cold verifies from pinned inputs without proving"};
    const candidate_replay = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = candidate_replay_names });
    const candidate_replay_run = b.addRunArtifact(candidate_replay);
    candidate_replay_run.has_side_effects = true;
    b.step("test-ethereum-wrapper-candidate-replay", "Cold verify a retained canonical wrapper candidate without proving again").dependOn(support.ProofTestGuard.add(b, candidate_replay_run, candidate_replay_names, "Ethereum wrapper candidate replay guard"));
    b.step("check-ethereum-wrapper-candidate-replay", "Compile retained wrapper replay without requiring a candidate file").dependOn(&candidate_replay.step);
    const failed_wrapper_names: []const []const u8 = &.{"role0 retained failed wrapper independently reproduces OODS rejection"};
    const failed_wrapper = b.addTest(.{ .root_module = incremental_leaf_universal_genuine_compile_root, .filters = failed_wrapper_names });
    const failed_wrapper_run = b.addRunArtifact(failed_wrapper);
    failed_wrapper_run.has_side_effects = true;
    b.step("test-ethereum-failed-wrapper-replay", "Reopen a retained failed proof and independently reproduce its OODS rejection").dependOn(support.ProofTestGuard.add(b, failed_wrapper_run, failed_wrapper_names, "Ethereum failed wrapper replay guard"));
    b.step("check-ethereum-failed-wrapper-replay", "Compile independent failed-wrapper replay without requiring an existing failed proof").dependOn(&failed_wrapper.step);
    const retained_wrapper_names: []const []const u8 = &.{
        "role0 retained wrapper verifies from disk without producer state",
    };
    const retained_wrapper = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = retained_wrapper_names,
    });
    const retained_wrapper_run = b.addRunArtifact(retained_wrapper);
    retained_wrapper_run.has_side_effects = true;
    b.step("test-ethereum-wrapper-replay", "Independently verify a retained wrapper and its native inputs from disk").dependOn(support.ProofTestGuard.add(b, retained_wrapper_run, retained_wrapper_names, "Ethereum retained wrapper verification guard"));
    b.step("check-ethereum-wrapper-replay", "Compile independent retained-wrapper verification").dependOn(&retained_wrapper.step);
    const rejected_input_names: []const []const u8 = &.{
        "role0 saved Stage101 label input commitment is rejected",
    };
    const rejected_input = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = rejected_input_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-rejected-input-v4-replay",
        "Cold-verify the original Stage101 proof and reject its label input commitment",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(rejected_input),
        rejected_input_names,
        "saved Ethereum label input commitment rejection guard",
    ));
    const root_cohort_names: []const []const u8 = &.{
        "Ethereum cohort replay publication preserves absent and present initial claims",
        "role0 saved Stage101 pair closes the complete statement-root cohort",
    };
    const root_cohort = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = root_cohort_names,
    });
    const root_cohort_run = b.addRunArtifact(root_cohort);
    root_cohort_run.has_side_effects = true; // Reopen the pinned external corpus on every invocation.
    b.step("test-ethereum-statement-root-cohort-replay", "Generate complete Ethereum Tree2, destroy the producer, and independently replay exact closure without PCS").dependOn(support.ProofTestGuard.add(b, root_cohort_run, root_cohort_names, "saved Ethereum complete root cohort guard"));
    const wrapper_replay_names: []const []const u8 = &.{
        "role0 saved Stage101 pair replays recursive wrapper",
    };
    const wrapper_replay = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = wrapper_replay_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-wrapper-v4-replay",
        "Cold-verify both pinned Stage101 children and run the genuine wrapper proof gate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(wrapper_replay),
        wrapper_replay_names,
        "saved Ethereum pair recursive wrapper replay guard",
    ));
    const custody_replay_names: []const []const u8 = &.{
        "role0 saved Stage101 pair validates retained materializer custody",
    };
    const custody_replay = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_compile_root,
        .filters = custody_replay_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-materializer-custody-v4-replay",
        "Cold-verify the pinned pair, check retained campaign custody and mutations, then destroy materialization",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(custody_replay),
        custody_replay_names,
        "saved Ethereum materializer custody guard",
    ));
    const incremental_leaf_recipe_v4_root = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_leaf_recipe_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    incremental_leaf_recipe_v4_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    const incremental_leaf_recipe_v4_compile = b.addTest(.{
        .root_module = incremental_leaf_recipe_v4_root,
        .filters = &.{
            "stage101 recipe is canonical and binds every leaf-local input",
            "stage101 recipe rejects coordinate codec and reseal mutations",
        },
    });
    b.step(
        "test-recursive-pipeline-incremental-leaf-recipe-v4",
        "Run the canonical incremental-leaf replay recipe gates",
    ).dependOn(&b.addRunArtifact(
        incremental_leaf_recipe_v4_compile,
    ).step);
    const canonical_empty_universal_v2_root = support.createHarnessModule(
        b,
        "recursive_common_canonical_empty_universal_proof_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    canonical_empty_universal_v2_root.addImport("stwo_prover_api", prover_api);
    canonical_empty_universal_v2_root.addImport("stwo_prover_engine", prover);
    canonical_empty_universal_v2_root.addImport("interop_postcard", postcard);
    const canonical_empty_universal_v2_structural_names: []const []const u8 = &.{
        "canonical-empty universal source selects exact q193 cohort",
        "VerifiedReplay separates statement audit from cohort custody identity",
        "output-less universal fixture never grants registry admission",
    };
    const canonical_empty_universal_v2_structural = b.addTest(.{
        .root_module = canonical_empty_universal_v2_root,
        .filters = canonical_empty_universal_v2_structural_names,
    });
    b.step(
        "test-recursive-common-canonical-empty-universal-v2-structural",
        "Run field-native canonical-empty universal structure gates",
    ).dependOn(&b.addRunArtifact(
        canonical_empty_universal_v2_structural,
    ).step);
    const canonical_empty_universal_v2_proof_names: []const []const u8 = &.{
        "canonical-empty q193 proof survives retained cold reopen and rejects mutation",
    };
    const canonical_empty_universal_v2_proof_compile = b.addTest(.{
        .root_module = canonical_empty_universal_v2_root,
        .filters = canonical_empty_universal_v2_proof_names,
    });
    b.step(
        "check-recursive-common-canonical-empty-universal-v2-proof",
        "Compile the field-native canonical-empty q193 retained-proof gate",
    ).dependOn(&canonical_empty_universal_v2_proof_compile.step);
    const canonical_empty_universal_v2_proof_run = b.addRunArtifact(
        canonical_empty_universal_v2_proof_compile,
    );
    canonical_empty_universal_v2_proof_run.has_side_effects = true;
    b.step(
        "test-recursive-common-canonical-empty-universal-v2-proof",
        "Prove, retain, decode, and cold-verify one canonical-empty wrapper",
    ).dependOn(support.ProofTestGuard.add(
        b,
        canonical_empty_universal_v2_proof_run,
        canonical_empty_universal_v2_proof_names,
        "Canonical-empty universal q193 proof identity guard",
    ));
    const campaign_empty_universal_v2_root = support.createHarnessModule(
        b,
        "recursive_common_canonical_empty_campaign_universal_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    campaign_empty_universal_v2_root.addImport("stwo_prover_api", prover_api);
    campaign_empty_universal_v2_root.addImport("stwo_prover_engine", prover);
    campaign_empty_universal_v2_root.addImport("interop_postcard", postcard);
    campaign_empty_universal_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    const campaign_empty_universal_v2_names: []const []const u8 = &.{
        "campaign canonical-empty structural q193 family is distinct and unrouteable",
        "campaign canonical-empty schedule binds runtime shape and rejects legacy session range",
        "campaign q193 entrypoint fails closed before proof without final remint",
    };
    const campaign_empty_universal_v2_compile = b.addTest(.{
        .root_module = campaign_empty_universal_v2_root,
        .filters = campaign_empty_universal_v2_names,
    });
    b.step(
        "check-recursive-common-canonical-empty-campaign-v2",
        "Compile the runtime-shape campaign canonical-empty q193 family",
    ).dependOn(&campaign_empty_universal_v2_compile.step);
    b.step(
        "test-recursive-common-canonical-empty-campaign-v2",
        "Run campaign canonical-empty source, schedule, and session gates",
    ).dependOn(&b.addRunArtifact(
        campaign_empty_universal_v2_compile,
    ).step);
    const common_fold_q193_bootstrap_v2_root = support.createHarnessModule(
        b,
        "recursive_common_fold_q193_bootstrap_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    common_fold_q193_bootstrap_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    common_fold_q193_bootstrap_v2_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    common_fold_q193_bootstrap_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    common_fold_q193_bootstrap_v2_root.addImport(
        "interop_postcard",
        postcard,
    );
    const common_fold_q193_bootstrap_v2_names: []const []const u8 = &.{
        "nonproduction common-fold q193 bootstrap preserves canonical child artifact ownership",
    };
    const common_fold_q193_bootstrap_v2_compile = b.addTest(.{
        .root_module = common_fold_q193_bootstrap_v2_root,
        .filters = common_fold_q193_bootstrap_v2_names,
    });
    b.step(
        "check-recursive-common-fold-q193-bootstrap-v2",
        "Compile the isolated nonproduction common-fold q193 bootstrap",
    ).dependOn(&common_fold_q193_bootstrap_v2_compile.step);
    const common_fold_q193_bootstrap_v2_run = b.addRunArtifact(
        common_fold_q193_bootstrap_v2_compile,
    );
    common_fold_q193_bootstrap_v2_run.has_side_effects = true;
    b.step(
        "test-recursive-common-fold-q193-bootstrap-v2",
        "Prove and independently cold-remint the unrouteable common fold",
    ).dependOn(support.ProofTestGuard.add(
        b,
        common_fold_q193_bootstrap_v2_run,
        common_fold_q193_bootstrap_v2_names,
        "Nonproduction common-fold q193 bootstrap identity guard",
    ));
    const common_fold_transcript_names: []const []const u8 = &.{
        "common-fold q193 transcript program matches the cold verifier",
    };
    const common_fold_transcript_compile = b.addTest(.{
        .root_module = common_fold_q193_bootstrap_v2_root,
        .filters = common_fold_transcript_names,
    });
    const common_fold_transcript_run = b.addRunArtifact(common_fold_transcript_compile);
    common_fold_transcript_run.has_side_effects = true;
    b.step(
        "test-recursive-common-fold-transcript-program-v1",
        "Check the recursive transcript program against a cold-opened common fold",
    ).dependOn(support.ProofTestGuard.add(
        b,
        common_fold_transcript_run,
        common_fold_transcript_names,
        "Common-fold transcript program proof identity guard",
    ));
    const ethereum_bundle_verifier = support.createHarnessModule(b, "ethereum_full_leaf_bundle_verifier_v1.zig", target, optimize, core, cpu_backend, frontend, integration);
    ethereum_bundle_verifier.addImport("stwo_prover_engine", prover);
    ethereum_bundle_verifier.addImport("stwo_prover_api", prover_api);
    ethereum_bundle_verifier.addImport("interop_postcard", postcard);
    ethereum_bundle_verifier.strip = ctx.ethereum_proof_strip;
    const selected_fixed_names: []const []const u8 = &.{"Ethereum native bundle worker option is explicit and bounded"};
    const selected_fixed_test = b.addTest(.{ .root_module = ethereum_bundle_verifier, .filters = selected_fixed_names });
    b.step("test-ethereum-selected-fixed-program-verifier", "Check explicit fixed ELF native verifier admission and unchanged legacy CLI").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(selected_fixed_test), selected_fixed_names, "Ethereum selected fixed program verifier guard"));
    const fixed_bundle_names: []const []const u8 = &.{"Ethereum fixed program bundle verifies retained pair and exact coverage"};
    const fixed_bundle_test = b.addTest(.{ .root_module = ethereum_bundle_verifier, .filters = fixed_bundle_names });
    const fixed_bundle_run = b.addRunArtifact(fixed_bundle_test);
    fixed_bundle_run.has_side_effects = true;
    b.step("test-ethereum-fixed-program-bundle-verifier", "Verify the pinned real schema5 pair and reject incomplete or broken continuation").dependOn(support.ProofTestGuard.add(b, fixed_bundle_run, fixed_bundle_names, "Ethereum fixed program genuine bundle verifier guard"));
    const ethereum_bundle_exe = b.addExecutable(.{ .name = "ethereum-full-leaf-bundle-verify-v1", .root_module = ethereum_bundle_verifier });
    const ethereum_bundle_install = b.addInstallArtifact(ethereum_bundle_exe, .{});
    b.step("build-ethereum-full-leaf-bundle-verifier", "Build sequential native full-leaf proof bundle verification").dependOn(&ethereum_bundle_install.step);
    b.step("build-ethereum-selected-leaf-verifier", "Build independent native selected-leaf verification from pinned materialization").dependOn(&ethereum_bundle_install.step);
    const ethereum_bundle_run = b.addRunArtifact(ethereum_bundle_exe);
    if (b.args) |args| ethereum_bundle_run.addArgs(args);
    b.step("run-ethereum-full-leaf-bundle-verifier", "Freshly verify every STWIEF04 proof and exact whole-execution coverage and continuation").dependOn(&ethereum_bundle_run.step);
    const ethereum_selected_run = b.addRunArtifact(ethereum_bundle_exe);
    ethereum_selected_run.addArg("verify-leaf");
    if (b.args) |args| ethereum_selected_run.addArgs(args);
    b.step("run-ethereum-selected-leaf-verifier", "Freshly verify one native proof against an independently pinned materialization and selected metadata").dependOn(&ethereum_selected_run.step);
    const selected_fixed_run = b.addRunArtifact(ethereum_bundle_exe);
    selected_fixed_run.addArg("verify-leaf-fixed-program-v5");
    if (b.args) |args| selected_fixed_run.addArgs(args);
    b.step("run-ethereum-selected-fixed-program-leaf-verifier", "Freshly verify a schema5 native proof with independent retained ELF admission").dependOn(&selected_fixed_run.step);
    const detached_command = support.createHarnessModule(b, "recursive_segment_v2_verifier_components_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_command.addImport("stwo_prover_engine", prover);
    detached_command.addImport("stwo_prover_api", prover_api);
    detached_command.addImport("interop_postcard", postcard);
    const detached_command_names: []const []const u8 = &.{
        "detached parent producer requires explicit profile and independent child and parent pins",
        "SegmentV2 detached command requires separate circuit and statement authority",
        "SegmentV2 detached command owns and canonically admits expected wire",
        "SegmentV2 detached command rejects unsupported claims version and empty proof",
    };
    const detached_command_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_command_names });
    b.step("test-recursive-segment-v2-detached-command", "Check bounded detached transport and independent public-input admission").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_command_tests), detached_command_names, "SegmentV2 detached transport guard"));
    const detached_child_names: []const []const u8 = &.{"SegmentV2 detached child owns genuine capture and exact recorded transcript"};
    const detached_parent_capture_names: []const []const u8 = &.{"detached parent capture replays genuine sparse cohort after input destruction"};
    const detached_parent_capture_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_parent_capture_names });
    b.step("test-recursive-segment-v2-detached-parent-capture", "Verify a retained parent and replay its recorded composition and PCS for the next recursive consumer").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_parent_capture_tests), detached_parent_capture_names, "Detached parent recursive capture guard"));
    const detached_child_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_child_names });
    b.step("test-recursive-segment-v2-detached-child", "Replay a pinned real child proof for recursion after caller input destruction").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_child_tests), detached_child_names, "SegmentV2 detached child guard"));
    const detached_boundary_names: []const []const u8 = &.{"SegmentV2 expected boundary shares native hashes and keeps dynamic values out of graph"};
    const detached_boundary_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_boundary_names });
    b.step("test-recursive-segment-v2-detached-boundary", "Check authenticated expected-boundary arithmetic before proving").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_boundary_tests), detached_boundary_names, "SegmentV2 detached boundary guard"));
    const detached_parent_statement_names: []const []const u8 = &.{"SegmentV2 detached parent folds actual child projections and constrains complete root"};
    const detached_parent_statement_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_parent_statement_names });
    b.step("test-recursive-segment-v2-detached-parent-statement", "Check actual child projections, continuation and complete root arithmetic").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_parent_statement_tests), detached_parent_statement_names, "SegmentV2 detached parent statement guard"));
    const detached_routing_names: []const []const u8 = &.{"SegmentV2 detached routing preserves exact source and graph export multiplicities"};
    const detached_routing_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_routing_names });
    b.step("test-recursive-segment-v2-detached-routing", "Check typed source routing and exact cross-circuit wire counts").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_routing_tests), detached_routing_names, "SegmentV2 detached routing guard"));
    const detached_parent_prepare_names: []const []const u8 = &.{ "detached parent prepares two genuine children with one exact routing plan", "detached parent snapshots typed rows and rejects mutable ingress and inactive claims" };
    const detached_parent_prepare_tests = b.addTest(.{ .root_module = detached_command, .filters = detached_parent_prepare_names });
    b.step("test-recursive-segment-v2-detached-parent-prepare", "Admit two genuine children and exact parent rows before proving").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(detached_parent_prepare_tests), detached_parent_prepare_names, "SegmentV2 detached parent preparation guard"));
    const detached_runner = support.createHarnessModule(b, "recursive_segment_v2_detached_verifier_runner.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_runner.addImport("stwo_prover_engine", prover);
    detached_runner.addImport("stwo_prover_api", prover_api);
    detached_runner.addImport("interop_postcard", postcard);
    const detached_exe = b.addExecutable(.{ .name = "recursive-segment-v2-detached-verify", .root_module = detached_runner });
    b.step("build-recursive-segment-v2-detached-verifier", "Build SegmentV2 verification without native preparation").dependOn(&b.addInstallArtifact(detached_exe, .{}).step);
    const detached_run = b.addRunArtifact(detached_exe);
    if (b.args) |args| detached_run.addArgs(args);
    b.step("run-recursive-segment-v2-detached-verifier", "Verify DIRECTORY KEY_SHA256 EXPECTED_WIRE_JSON").dependOn(&detached_run.step);
    const detached_parent_producer = support.createHarnessModule(b, "recursive_segment_v2_detached_parent_producer_runner.zig", target, optimize, core, cpu_backend, frontend, integration);
    const detached_parent_producer_exe = b.addExecutable(.{ .name = "recursive-segment-v2-detached-parent-prove", .root_module = detached_parent_producer });
    b.step("build-recursive-segment-v2-detached-parent-producer", "Build the explicit tiny two-child parent producer").dependOn(&b.addInstallArtifact(detached_parent_producer_exe, .{}).step);
    const detached_parent_verifier = support.createHarnessModule(b, "recursive_segment_v2_detached_parent_verifier_runner.zig", target, optimize, core, cpu_backend, frontend, integration);
    const detached_parent_verifier_exe = b.addExecutable(.{ .name = "recursive-segment-v2-detached-parent-verify", .root_module = detached_parent_verifier });
    b.step("build-recursive-segment-v2-detached-parent-verifier", "Build independent detached parent verification").dependOn(&b.addInstallArtifact(detached_parent_verifier_exe, .{}).step);
    const ethereum_root_verifier = support.createHarnessModule(b, "ethereum_wrapper_root_command_v1.zig", target, optimize, core, cpu_backend, frontend, integration);
    ethereum_root_verifier.addImport("stwo_prover_engine", prover);
    ethereum_root_verifier.addImport("stwo_prover_api", prover_api);
    ethereum_root_verifier.addImport("interop_postcard", postcard);
    const ethereum_root_exe = b.addExecutable(.{ .name = "ethereum-wrapper-root-verify-v1", .root_module = ethereum_root_verifier });
    b.step("build-ethereum-wrapper-root-verifier", "Build the independent Ethereum field wrapper verifier").dependOn(&b.addInstallArtifact(ethereum_root_exe, .{}).step);
    const ethereum_root_run = b.addRunArtifact(ethereum_root_exe);
    if (b.args) |args| ethereum_root_run.addArgs(args);
    b.step("run-ethereum-wrapper-root-verifier", "Verify from durable root proof/public inputs and independently supplied key hash").dependOn(&ethereum_root_run.step);
    const root_rejections_module = support.createHarnessModule(b, "ethereum_wrapper_root_rejections_v1.zig", target, optimize, core, cpu_backend, frontend, integration);
    root_rejections_module.addImport("stwo_prover_engine", prover);
    root_rejections_module.addImport("stwo_prover_api", prover_api);
    root_rejections_module.addImport("interop_postcard", postcard);
    const root_rejections_exe = b.addExecutable(.{ .name = "ethereum-wrapper-root-rejections-v1", .root_module = root_rejections_module });
    b.step("build-ethereum-wrapper-root-rejections", "Build canonical rejection fixture export for an existing independently pinned root candidate").dependOn(&b.addInstallArtifact(root_rejections_exe, .{}).step);
    const root_rejections_names: []const []const u8 = &.{"Ethereum root rejection fixtures preserve canonical statements and exact candidate custody"};
    const root_rejections_test = b.addTest(.{ .root_module = root_rejections_module, .filters = root_rejections_names });
    b.step("test-ethereum-wrapper-root-rejections", "Check canonical hostile root inputs, alternate circuit admission and create-only transport custody").dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(root_rejections_test), root_rejections_names, "Ethereum root rejection fixture guard"));
    const saved_real_parent_root = support.createHarnessModule(b, "ethereum_wrapper_saved_real_parent_v1_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    saved_real_parent_root.addImport("stwo_artifact_store", artifact_store);
    saved_real_parent_root.addImport("stwo_prover_engine", prover);
    saved_real_parent_root.addImport("stwo_prover_api", prover_api);
    saved_real_parent_root.addImport("interop_postcard", postcard);
    saved_real_parent_root.strip = ctx.ethereum_proof_strip;
    const saved_real_parent_names: []const []const u8 = &.{"Ethereum saved real wrapper siblings prove and verify after destruction"};
    const saved_real_parent_test = b.addTest(.{ .root_module = saved_real_parent_root, .filters = saved_real_parent_names });
    b.step("check-ethereum-saved-real-parent", "Compile the saved Ethereum wrapper sibling-to-parent proof route").dependOn(&saved_real_parent_test.step);
    const saved_real_parent_run = b.addRunArtifact(saved_real_parent_test);
    saved_real_parent_run.has_side_effects = true; // Reopen pinned external children and freshly verify the produced parent.
    b.step("test-ethereum-saved-real-parent", "Prove saved wrapper siblings 2 and 3 and verify their parent after producer destruction").dependOn(support.ProofTestGuard.add(b, saved_real_parent_run, saved_real_parent_names, "Ethereum saved real parent proof guard"));
    const detached_verifier_root = support.createHarnessModule(b, "recursive_common_fold_verifier_command_v2.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_verifier_root.addImport("stwo_prover_engine", prover);
    detached_verifier_root.addImport("stwo_prover_api", prover_api);
    detached_verifier_root.addImport("interop_postcard", postcard);
    const detached_verifier_exe = b.addExecutable(.{ .name = "recursive-common-fold-verify-v2", .root_module = detached_verifier_root });
    b.step("build-recursive-common-fold-verifier-v2", "Build the verifier that accepts durable public inputs and an explicit key").dependOn(&b.addInstallArtifact(detached_verifier_exe, .{}).step);
    const detached_verifier_run = b.addRunArtifact(detached_verifier_exe);
    if (b.args) |args| detached_verifier_run.addArgs(args);
    detached_verifier_run.has_side_effects = true;
    b.step("run-recursive-common-fold-verifier-v2", "Verify a common-fold proof with no child-artifact inputs").dependOn(&detached_verifier_run.step);
    const detached_transport_test = b.addTest(.{ .root_module = detached_verifier_root, .filters = &.{"common-fold verifier transport authenticates key and rejects version drift"} });
    b.step("test-recursive-common-fold-verifier-transport-v2", "Check bounded verifier input transport and key identity rejection").dependOn(&b.addRunArtifact(detached_transport_test).step);
    const detached_transcript_root = support.createHarnessModule(b, "recursive_common_fold_detached_transcript_v2.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_transcript_root.addImport("stwo_prover_engine", prover);
    detached_transcript_root.addImport("stwo_prover_api", prover_api);
    detached_transcript_root.addImport("interop_postcard", postcard);
    const detached_transcript_test = b.addTest(.{ .root_module = detached_transcript_root, .filters = &.{"detached common-fold transcript reconstructs verified challenges and query words"} });
    const detached_transcript_run = b.addRunArtifact(detached_transcript_test);
    detached_transcript_run.has_side_effects = true;
    b.step("test-recursive-common-fold-detached-transcript-v2", "Verify a saved proof and prepare its transcript AIR without grandchildren").dependOn(&detached_transcript_run.step);
    const detached_parent_root = support.createHarnessModule(b, "recursive_common_fold_detached_parent_v2.zig", target, optimize, core, cpu_backend, frontend, integration);
    detached_parent_root.addImport("stwo_prover_engine", prover);
    detached_parent_root.addImport("stwo_prover_api", prover_api);
    detached_parent_root.addImport("interop_postcard", postcard);
    const detached_parent_test = b.addTest(.{ .root_module = detached_parent_root, .filters = &.{"detached fold siblings close the actual parent constraint source"} });
    const detached_parent_run = b.addRunArtifact(detached_parent_test);
    detached_parent_run.has_side_effects = true;
    b.step("test-recursive-common-fold-detached-parent-source-v2", "Check the complete parent constraint source from two saved fold proofs").dependOn(&detached_parent_run.step);
    const detached_parent_proof_test = b.addTest(.{ .root_module = detached_parent_root, .filters = &.{"detached fold siblings prove a parent and verify after producer destruction"} });
    const detached_parent_proof_run = b.addRunArtifact(detached_parent_proof_test);
    detached_parent_proof_run.has_side_effects = true;
    b.step("test-recursive-common-fold-detached-parent-proof-v2", "Prove two actual fold children and independently verify their parent").dependOn(&detached_parent_proof_run.step);
    const common_fold_replay_names: []const []const u8 = &.{
        "retained common-fold proof replays through the current cold verifier",
    };
    const common_fold_setup_names: []const []const u8 = &.{"common-fold setup matches across independent canonical child statements"};
    const common_fold_inputs_compile = b.addTest(.{ .root_module = common_fold_q193_bootstrap_v2_root, .filters = &.{"bootstrap sibling input selection validates padding and replay coordinates"} });
    b.step("test-recursive-common-fold-bootstrap-inputs-v2", "Check bootstrap sibling coordinates and checkpoint input recovery").dependOn(&b.addRunArtifact(common_fold_inputs_compile).step);
    const common_fold_setup_compile = b.addTest(.{ .root_module = common_fold_q193_bootstrap_v2_root, .filters = common_fold_setup_names });
    const common_fold_setup_run = b.addRunArtifact(common_fold_setup_compile);
    common_fold_setup_run.has_side_effects = true;
    b.step("test-recursive-common-fold-setup-v2", "Rebuild setup from different children and check the pinned public key").dependOn(support.ProofTestGuard.add(b, common_fold_setup_run, common_fold_setup_names, "Common-fold independent setup comparison guard"));
    const common_fold_replay_compile = b.addTest(.{
        .root_module = common_fold_q193_bootstrap_v2_root,
        .filters = common_fold_replay_names,
    });
    b.step(
        "check-recursive-common-fold-transcript-replay-v1",
        "Compile the retained common-fold cold verifier and transcript AIR checks",
    ).dependOn(&common_fold_replay_compile.step);
    const common_fold_replay_run = b.addRunArtifact(common_fold_replay_compile);
    common_fold_replay_run.has_side_effects = true;
    b.step(
        "test-recursive-common-fold-transcript-replay-v1",
        "Cold-verify a retained CAS proof and check its transcript AIR without proving another fold",
    ).dependOn(support.ProofTestGuard.add(
        b,
        common_fold_replay_run,
        common_fold_replay_names,
        "Common-fold retained proof replay guard",
    ));
    const common_fold_source_names: []const []const u8 = &.{
        "common-fold parent owns both child transcript lanes",
    };
    const common_fold_source_compile = b.addTest(.{
        .root_module = common_fold_q193_bootstrap_v2_root,
        .filters = common_fold_source_names,
    });
    const common_fold_source_run = b.addRunArtifact(common_fold_source_compile);
    common_fold_source_run.has_side_effects = true;
    b.step(
        "test-recursive-common-fold-transcript-source-v1",
        "Check parent transcript custody and physical rows without proving a common fold",
    ).dependOn(support.ProofTestGuard.add(
        b,
        common_fold_source_run,
        common_fold_source_names,
        "Common-fold parent transcript source guard",
    ));
    const common_fold_child_capability_v2_root = support.createHarnessModule(
        b,
        "recursive_common_fold_child_capability_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    common_fold_child_capability_v2_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    common_fold_child_capability_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    common_fold_child_capability_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    common_fold_child_capability_v2_root.addImport(
        "interop_postcard",
        postcard,
    );
    const common_fold_child_capability_v2_names: []const []const u8 = &.{
        "schema4 child capability is typed role-neutral and production closed",
        "unavailable real branch cannot mint a fold child",
        "projection carries no serializable freshness or nominal child",
    };
    const common_fold_child_capability_v2_compile = b.addTest(.{
        .root_module = common_fold_child_capability_v2_root,
        .filters = common_fold_child_capability_v2_names,
    });
    b.step(
        "test-recursive-common-fold-child-capability-v2",
        "Run typed schema-4 fold-child projection and fail-closed role gates",
    ).dependOn(&b.addRunArtifact(
        common_fold_child_capability_v2_compile,
    ).step);
    const recursive_pipeline_worker_composite_v2_root =
        support.createHarnessModule(
            b,
            "recursive_pipeline_worker_composite_v2_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        );
    recursive_pipeline_worker_composite_v2_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    recursive_pipeline_worker_composite_v2_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    recursive_pipeline_worker_composite_v2_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    recursive_pipeline_worker_composite_v2_root.addImport(
        "interop_postcard",
        postcard,
    );
    const recursive_pipeline_worker_composite_v2_names: []const []const u8 = &.{
        "composite contract pins stage codes and typed CAS outputs",
        "stage101 and stage103 route while composite production stays closed",
        "lease union owns nominal payloads and has no durable codec",
        "generic lease ownership releases exactly once by active stage",
    };
    const recursive_pipeline_worker_composite_v2_compile = b.addTest(.{
        .root_module = recursive_pipeline_worker_composite_v2_root,
        .filters = recursive_pipeline_worker_composite_v2_names,
    });
    b.step(
        "test-recursive-pipeline-worker-composite-v2",
        "Run static stage-101-through-104 lease and CAS contract gates",
    ).dependOn(&b.addRunArtifact(
        recursive_pipeline_worker_composite_v2_compile,
    ).step);
    const recursive_common_fold_input_root = support.createHarnessModule(
        b,
        "recursive_common_fold_input_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const recursive_common_fold_input_test_names: []const []const u8 = &.{
        "common fold input retains two fresh captures and derives exact empty parent",
        "common fold input rejects alias order registry and sealed identity drift",
    };
    const recursive_common_fold_input_compile = b.addTest(.{
        .root_module = recursive_common_fold_input_root,
        .filters = recursive_common_fold_input_test_names,
    });
    b.step(
        "test-recursive-common-fold-input-v1",
        "Run verifier-owned common-fold input and mutation gates",
    ).dependOn(&b.addRunArtifact(
        recursive_common_fold_input_compile,
    ).step);
    const incremental_boundary_v3_root = support.createHarnessModule(
        b,
        "ethereum_incremental_boundary_authority_v3_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const incremental_boundary_v3_test_names: []const []const u8 = &.{
        "incremental boundary V3 keeps raw Merkle words while deriving memory multiplicity",
        "incremental boundary V3 authenticates final output and completion links",
        "incremental boundary V3 rejects role segment and completion drift",
        "incremental boundary V3 rejects inventory and clock mutations",
        "incremental boundary V3 rejects caller-mutated policy and multiplicity",
        "incremental boundary V3 rejects layout and full-root drift",
        "incremental native profile readiness is immutable and fail closed",
    };
    const incremental_boundary_v3_compile = b.addTest(.{
        .root_module = incremental_boundary_v3_root,
        .filters = incremental_boundary_v3_test_names,
    });
    b.step(
        "test-ethereum-incremental-boundary-authority-v3",
        "Run full-state incremental boundary and readiness contract gates",
    ).dependOn(&b.addRunArtifact(incremental_boundary_v3_compile).step);
    const incremental_boundary_artifact_v3_root = support.createHarnessModule(
        b,
        "ethereum_incremental_boundary_artifact_v3_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const incremental_boundary_artifact_v3_test_names: []const []const u8 = &.{
        "STWIMT03 round trips and coldly derives a public-input role",
        "STWIMT03 rejects raw corruption and resealed reserved bytes",
        "STWIMT03 rejects a resealed entry-clock mutation",
        "STWIMT03 binds ordered clocks to the V2 touched-word order",
        "STWIMT03 rejects public-wire identity and backing-word mutations",
        "STWIMT03 rejects resealed root drift against nested STWIMT02",
        "STWIMT03 derives public values and rejects caller-side raw IO drift",
    };
    const incremental_boundary_artifact_v3_compile = b.addTest(.{
        .root_module = incremental_boundary_artifact_v3_root,
        .filters = incremental_boundary_artifact_v3_test_names,
    });
    b.step(
        "test-ethereum-incremental-boundary-artifact-v3",
        "Run canonical STWIMT03 codec and cold-reconstruction mutation gates",
    ).dependOn(&b.addRunArtifact(incremental_boundary_artifact_v3_compile).step);
    const incremental_boundary_v4_root = support.createHarnessModule(
        b,
        "ethereum_incremental_boundary_authority_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const incremental_boundary_v4_test_names: []const []const u8 = &.{
        "incremental boundary V4 keeps raw Merkle words while deriving memory multiplicity",
        "incremental boundary V4 authenticates final output and completion links",
        "incremental boundary V4 rejects role segment and completion drift",
        "incremental boundary V4 admits untouched public input and rejects clock drift",
        "incremental boundary V4 rejects caller-mutated policy and multiplicity",
        "incremental boundary V4 rejects layout and full-root drift",
        "policy 2 untouched public input closes public LogUp without an opcode row",
        "legacy WordState golden still suppresses untouched public-input final row",
        "validated V4 authority scans a large input inventory exactly once",
    };
    const incremental_boundary_v4_compile = b.addTest(.{
        .root_module = incremental_boundary_v4_root,
        .filters = incremental_boundary_v4_test_names,
    });
    b.step(
        "test-ethereum-incremental-boundary-authority-v4",
        "Run policy-2 untouched-public-input boundary and LogUp gates",
    ).dependOn(&b.addRunArtifact(incremental_boundary_v4_compile).step);
    const incremental_boundary_artifact_v4_root = support.createHarnessModule(
        b,
        "ethereum_incremental_boundary_artifact_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const incremental_boundary_artifact_v4_test_names: []const []const u8 = &.{
        "STWIMT04 round trips and coldly derives touched and sparse-zero public inputs",
        "STWIMT02 sparse parents retain exact topology across cold reopen",
        "STWIMT04 binds policy 2 and rejects resealed reserved bytes",
        "STWIMT04 rejects a resealed entry-clock mutation",
        "STWIMT04 binds ordered clocks to the V2 touched-word order",
        "STWIMT04 rejects public-wire identity and backing-word mutations",
        "STWIMT04 rejects resealed root drift against nested STWIMT02",
        "STWIMT04 derives public values and rejects caller-side raw IO drift",
        "STWIMT04 sparse-zero merge rejects nonzero ABI clock and value drift",
    };
    const incremental_boundary_artifact_v4_compile = b.addTest(.{
        .root_module = incremental_boundary_artifact_v4_root,
        .filters = incremental_boundary_artifact_v4_test_names,
    });
    b.step(
        "test-ethereum-incremental-boundary-artifact-v4",
        "Run canonical STWIMT04 policy-2 sparse reconstruction gates",
    ).dependOn(&b.addRunArtifact(incremental_boundary_artifact_v4_compile).step);
    const incremental_native_leaf_profile_v3_root = support.createHarnessModule(
        b,
        "ethereum_incremental_native_leaf_profile_v3_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const incremental_native_leaf_profile_v3_test_names: []const []const u8 = &.{
        "incremental native leaf profile is cold-derived and q193 exact",
        "incremental native leaf profile rejects field, geometry, and protocol drift",
        "incremental native leaf profile reopens artifact and exact base wire",
        "incremental native leaf transcript order is exact before both trees",
    };
    const incremental_native_leaf_profile_v3_compile = b.addTest(.{
        .root_module = incremental_native_leaf_profile_v3_root,
        .filters = incremental_native_leaf_profile_v3_test_names,
    });
    b.step(
        "test-ethereum-incremental-native-leaf-profile-v3",
        "Run cold-derived incremental native leaf profile and transcript gates",
    ).dependOn(&b.addRunArtifact(
        incremental_native_leaf_profile_v3_compile,
    ).step);
    const real_omitted_wrapper_input_root = support.createHarnessModule(
        b,
        "recursive_common_real_omitted_leaf_input_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    real_omitted_wrapper_input_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    real_omitted_wrapper_input_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    real_omitted_wrapper_input_root.addImport(
        "interop_postcard",
        postcard,
    );
    const real_omitted_wrapper_input_test_names: []const []const u8 = &.{
        "real omitted wrapper cold-open API type instantiates",
        "real omitted wrapper remains unavailable before q193 cold proof",
    };
    const real_omitted_wrapper_input_compile = b.addTest(.{
        .root_module = real_omitted_wrapper_input_root,
        .filters = real_omitted_wrapper_input_test_names,
    });
    b.step(
        "test-recursive-common-real-omitted-leaf-input-v1",
        "Run omitted-leaf wrapper cold-input type and availability gates",
    ).dependOn(&b.addRunArtifact(real_omitted_wrapper_input_compile).step);
    const ethereum_poseidon_h1_ingress_root = support.createHarnessModule(
        b,
        "recursive_temporal_ethereum_poseidon_h1_ingress_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    ethereum_poseidon_h1_ingress_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    ethereum_poseidon_h1_ingress_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    ethereum_poseidon_h1_ingress_root.addImport(
        "interop_postcard",
        postcard,
    );
    const ethereum_poseidon_h1_ingress_test_names: []const []const u8 = &.{
        "Ethereum Poseidon h1 custody round-trips but cannot publish",
        "Ethereum Poseidon h1 custody rejects resealed semantic mutations",
        "Ethereum Poseidon h1 canonical decoder rejects byte mutations",
        "Ethereum Poseidon h1 structural cohort binds twelve placements",
        "Ethereum Poseidon h1 structural mutations fail after resealing",
        "Ethereum Poseidon h1 proof plumbing owns exact twelve-placement trees",
        "Ethereum Poseidon h1 boundary cannot relabel statement as secure wire",
        "Ethereum Poseidon h1 cohort satisfies secure q193 engine contract",
    };
    const ethereum_poseidon_h1_ingress_compile = b.addTest(.{
        .root_module = ethereum_poseidon_h1_ingress_root,
        .filters = ethereum_poseidon_h1_ingress_test_names,
    });
    const ethereum_poseidon_h1_ingress_tests = b.addRunArtifact(
        ethereum_poseidon_h1_ingress_compile,
    );
    ethereum_poseidon_h1_ingress_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-ethereum-poseidon-h1-ingress-v1",
        "Run full-Ethereum verifier-minted h1 ingress custody gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_poseidon_h1_ingress_tests,
        ethereum_poseidon_h1_ingress_test_names,
        "Full-Ethereum Poseidon h1 ingress test identity guard",
    ));
    const ethereum_poseidon_h1_batch_root = support.createHarnessModule(
        b,
        "recursive_temporal_ethereum_poseidon_h1_batch_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    ethereum_poseidon_h1_batch_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    ethereum_poseidon_h1_batch_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    ethereum_poseidon_h1_batch_root.addImport(
        "interop_postcard",
        postcard,
    );
    const ethereum_poseidon_h1_batch_test_names: []const []const u8 = &.{
        "H1 batch audits exact 105 real pairs inside 210-to-256 topology",
        "H1 batch pair and ordered admission reject identity and arm mutations",
        "H1 canonical product remains custody until cold verifier readmission",
    };
    const ethereum_poseidon_h1_batch_compile = b.addTest(.{
        .root_module = ethereum_poseidon_h1_batch_root,
        .filters = ethereum_poseidon_h1_batch_test_names,
    });
    b.step(
        "check-recursive-temporal-ethereum-poseidon-h1-batch-v1",
        "Compile the 210-leaf H1 batch and canonical product boundary",
    ).dependOn(&ethereum_poseidon_h1_batch_compile.step);
    const ethereum_poseidon_h1_batch_tests = b.addRunArtifact(
        ethereum_poseidon_h1_batch_compile,
    );
    ethereum_poseidon_h1_batch_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-ethereum-poseidon-h1-batch-v1",
        "Run H1 batch topology, admission, and artifact mutation gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_poseidon_h1_batch_tests,
        ethereum_poseidon_h1_batch_test_names,
        "Full-Ethereum Poseidon H1 batch/product identity guard",
    ));
    const secure_tree_tail_root = support.createHarnessModule(
        b,
        "recursive_temporal_secure_tree_tail_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    secure_tree_tail_root.addImport("stwo_prover_api", prover_api);
    secure_tree_tail_root.addImport("stwo_prover_engine", prover);
    secure_tree_tail_root.addImport("interop_postcard", postcard);
    const secure_tree_tail_test_names: []const []const u8 = &.{
        "secure tree tail audits exact 23 empty H1 and 127 upper products",
        "secure tree tail product schedule rejects order kind and capture mutations",
        "empty H1 admission is task bound and remains nonproduction",
    };
    const secure_tree_tail_compile = b.addTest(.{
        .root_module = secure_tree_tail_root,
        .filters = secure_tree_tail_test_names,
    });
    b.step(
        "check-recursive-temporal-secure-tree-tail-v1",
        "Compile the exact empty-H1 and secure upper product schedule",
    ).dependOn(&secure_tree_tail_compile.step);
    const secure_tree_tail_tests = b.addRunArtifact(
        secure_tree_tail_compile,
    );
    secure_tree_tail_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-secure-tree-tail-v1",
        "Run empty-H1 and upper secure product schedule mutation gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        secure_tree_tail_tests,
        secure_tree_tail_test_names,
        "Secure temporal tree tail test identity guard",
    ));
    const secure_child_composition_root = support.createHarnessModule(
        b,
        "recursive_temporal_secure_child_composition_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    secure_child_composition_root.addImport("stwo_prover_api", prover_api);
    secure_child_composition_root.addImport("stwo_prover_engine", prover);
    secure_child_composition_root.addImport("interop_postcard", postcard);
    const secure_child_composition_test_names: []const []const u8 = &.{
        "secure child H1 graph mint plan has exact nonlegacy claim geometry",
        "secure child H1 graph mint plan rejects claim geometry mutations",
        "secure child H1 graph mint plan rejects custody and sample mutations",
        "secure child H1 claim policy binds 12 physical and two partial claims",
        "secure child H1 claim policy rejects provider and unused-slot mutations",
        "ordinary H1 session retains three shapes and exact cohort callback",
        "ordinary H1 and canonical Empty retain separate capture custody",
        "ordinary H1 and canonical Empty reject detached program custody",
        "ordinary H1 session rejects provider sample and cross-shape mutations",
        "ordinary H1 session rejects Empty logs and H1 manifest custody drift",
    };
    const secure_child_composition_compile = b.addTest(.{
        .root_module = secure_child_composition_root,
        .filters = secure_child_composition_test_names,
    });
    b.step(
        "check-recursive-temporal-secure-child-composition-v1",
        "Compile the typed secure-child verifier reconstruction contract",
    ).dependOn(&secure_child_composition_compile.step);
    const secure_child_composition_tests = b.addRunArtifact(
        secure_child_composition_compile,
    );
    secure_child_composition_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-secure-child-composition-v1",
        "Run secure-child H1 graph-mint shape and mutation gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        secure_child_composition_tests,
        secure_child_composition_test_names,
        "Secure child composition source-contract identity guard",
    ));
    const ethereum_poseidon_h1_secure_root = support.createHarnessModule(
        b,
        "recursive_temporal_ethereum_poseidon_h1_secure_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    ethereum_poseidon_h1_secure_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    ethereum_poseidon_h1_secure_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    ethereum_poseidon_h1_secure_root.addImport(
        "interop_postcard",
        postcard,
    );
    const ethereum_poseidon_h1_secure_test_names: []const []const u8 = &.{
        "Ethereum Poseidon h1 two verified leaves retain secure q193 cold proof",
    };
    const ethereum_poseidon_h1_secure_compile = b.addTest(.{
        .root_module = ethereum_poseidon_h1_secure_root,
        .filters = ethereum_poseidon_h1_secure_test_names,
    });
    b.step(
        "check-recursive-temporal-ethereum-poseidon-h1-secure-proof-v1",
        "Compile the secure Ethereum h1 retained-proof gate",
    ).dependOn(&ethereum_poseidon_h1_secure_compile.step);
    const ethereum_poseidon_h1_secure_tests = b.addRunArtifact(
        ethereum_poseidon_h1_secure_compile,
    );
    ethereum_poseidon_h1_secure_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-ethereum-poseidon-h1-secure-proof-v1",
        "Prove, retain, decode, and cold-verify the secure Ethereum h1 parent",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_poseidon_h1_secure_tests,
        ethereum_poseidon_h1_secure_test_names,
        "Secure full-Ethereum Poseidon h1 proof test identity guard",
    ));
    const secure_parent_v1_root = support.createHarnessModule(
        b,
        "recursive_temporal_secure_parent_native_engine_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    secure_parent_v1_root.addImport("stwo_prover_api", prover_api);
    secure_parent_v1_root.addImport("stwo_prover_engine", prover);
    secure_parent_v1_root.addImport("interop_postcard", postcard);
    const secure_parent_v1_test_names: []const []const u8 = &.{
        "secure parent artifact round-trips as custody only",
        "secure parent q193 proof bytes cold fresh-verify",
        "secure parent cold verifier rejects context and proof mutations",
    };
    const secure_parent_v1_compile = b.addTest(.{
        .root_module = secure_parent_v1_root,
        .filters = secure_parent_v1_test_names,
    });
    const secure_parent_v1_tests = b.addRunArtifact(
        secure_parent_v1_compile,
    );
    secure_parent_v1_tests.has_side_effects = true;
    b.step(
        "test-recursive-temporal-secure-parent-v1",
        "Run secure q193 parent proof retention and cold-verifier gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        secure_parent_v1_tests,
        secure_parent_v1_test_names,
        "Secure q193 temporal-parent proof identity guard",
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
    // Export the same lean driver for the Metal dependency-boundary shim.
    // CPU products retain no dependency on the Metal backend or frameworks.
    const segment_v2_concrete_outer_runner_root = b.addModule("stwo_riscv_cpu_small_recursion_runner", .{
        .root_source_file = b.path("recursive_segment_v2_concrete_outer_proof_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    segment_v2_concrete_outer_runner_root.addImport("stwo_core", core);
    segment_v2_concrete_outer_runner_root.addImport("stwo_cpu_backend", cpu_backend);
    segment_v2_concrete_outer_runner_root.addImport("stwo_riscv_frontend", frontend);
    segment_v2_concrete_outer_runner_root.addImport("stwo_riscv_cpu_integration", integration);
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
    const segment_workload_root = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_workload_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    segment_workload_root.addImport("stwo_core", core);
    segment_workload_root.addImport("stwo_riscv_frontend", frontend);
    const segment_workload = b.addExecutable(.{
        .name = "recursive-segment-v2-workload",
        .root_module = segment_workload_root,
    });
    b.step("build-recursive-segment-v2-workload", "Install the execution-only segment ladder and expected-input exporter")
        .dependOn(&b.addInstallArtifact(segment_workload, .{}).step);
    const run_segment_workload = b.addRunArtifact(segment_workload);
    run_segment_workload.has_side_effects = true;
    if (b.args) |args| run_segment_workload.addArgs(args);
    b.step("run-recursive-segment-v2-workload", "Check 2/4/8 segment execution or export expected inputs without compiling a prover")
        .dependOn(&run_segment_workload.step);
    const segment_v2_concrete_outer_runner = b.addExecutable(.{
        .name = "recursive-segment-v2-concrete-outer-proof",
        .root_module = segment_v2_concrete_outer_runner_root,
    });
    b.step(
        "build-recursive-segment-v2-concrete-outer-proof",
        "Install the small complete-proof runner for fresh-process development checks",
    ).dependOn(&b.addInstallArtifact(segment_v2_concrete_outer_runner, .{}).step);
    const run_segment_v2_concrete_outer = b.addRunArtifact(
        segment_v2_concrete_outer_runner,
    );
    run_segment_v2_concrete_outer.has_side_effects = true;
    if (b.args) |args| run_segment_v2_concrete_outer.addArgs(args);
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
    const prepared_execution_v4_root = support.createHarnessModule(
        b,
        "ethereum_incremental_full_leaf_prepared_execution_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    prepared_execution_v4_root.addImport("stwo_prover_api", prover_api);
    prepared_execution_v4_root.addImport("stwo_prover_engine", prover);
    prepared_execution_v4_root.addImport("interop_postcard", postcard);
    const prepared_execution_v4_names: []const []const u8 = &.{
        "prepared transaction pins one construction of every expensive owner",
        "prepared transaction token rejects pointer identity and seal drift",
        "prepared transaction explicit program constructor has no legacy fallback",
        "prepared process token allocation releases every partial owner",
        "Stage101 execution policy admits strict worker counts one through eighteen",
        "Stage101 resource receipt binds CPU utilization RSS and leaf throughput",
        "Stage101 worker sweep is host-derived ordered and generic",
        "Stage101 scheduling comparison requires byte-identical q193 cold result",
        "prepared program commitment deep owns exact ELF and validates borrowed prefix",
        "prepared program leaf rows retain only multiplicities and exact work receipt",
        "prepared program leaf rows reject address and instruction drift",
        "prepared commitment witness builder preserves table order and work receipt",
        "prepared program commitment rejects copied owner and borrowed pointer drift",
        "prepared program commitment cold validation rejects retained root and call mutation",
    };
    const prepared_execution_v4_compile = b.addTest(.{
        .root_module = prepared_execution_v4_root,
        .filters = prepared_execution_v4_names,
    });
    b.step(
        "test-ethereum-incremental-full-leaf-prepared-execution-v4",
        "Run one-pass Stage101 preparation and generic host execution gates",
    ).dependOn(&b.addRunArtifact(prepared_execution_v4_compile).step);
    const prepared_parity_v4_root = support.createHarnessModule(
        b,
        "ethereum_incremental_full_leaf_prepared_authority_parity_v4_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    prepared_parity_v4_root.addImport("stwo_prover_api", prover_api);
    prepared_parity_v4_root.addImport("stwo_prover_engine", prover);
    prepared_parity_v4_root.addImport("interop_postcard", postcard);
    const prepared_parity_v4_compile = b.addTest(.{
        .root_module = prepared_parity_v4_root,
        .filters = &.{
            "Stage101 prepared parity live API type-instantiates",
            "Stage101 prepared and legacy authority snapshots compare exactly",
            "Stage101 prepared parity reports every authority class mutation",
            "Stage101 prepared parity receipt rejects count and identity drift",
        },
    });
    b.step(
        "test-ethereum-incremental-full-leaf-prepared-authority-parity-v4",
        "Run Stage101 prepared-versus-legacy authority identity tests",
    ).dependOn(&b.addRunArtifact(prepared_parity_v4_compile).step);
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
