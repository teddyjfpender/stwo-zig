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
        "stage102 V4 cold input and field schedule APIs instantiate",
        "stage102 V4 source preimage pins role checkpoint and commitment order",
        "stage102 V4 source binds actual Ethereum completion word and tuple",
        "stage102 V4 schedule is exact 123-call field-native authority",
        "stage102 V4 public source cannot relabel canonical-empty or transport SHA",
        "stage102 V4 manifest preserves universal physical layout",
        "stage102 V4 bridge projection pins the missing graph authority",
        "stage102 V4 materializer type retains live capture ownership",
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
        "child-public binding rejects a resealed claim-hash drift",
        "child-public binding rejects an independently resealed IO hash",
        "row34 geometry binds transcript child hashes publication and verifier core",
        "publication boundary receipt cannot mint complete row34 geometry",
        "row34 receipt rejects publication-only authority subdivision",
        "stage102 role0 transcript cohort tree and tuple APIs instantiate",
        "stage102 role0 transcript rows retain inactive recursion lanes",
        "schema3 role0 cohort exposes exact 36-row closure without proof escalation",
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

    const incremental_leaf_universal_genuine_root =
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
    incremental_leaf_universal_genuine_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    incremental_leaf_universal_genuine_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    incremental_leaf_universal_genuine_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    incremental_leaf_universal_genuine_root.addImport(
        "interop_postcard",
        postcard,
    );
    const incremental_leaf_universal_genuine_names: []const []const u8 = &.{
        "role0 genuine two-leaf q193 proof cold-opens into neutral real child",
    };
    const incremental_leaf_universal_genuine_compile_and_run = b.addTest(.{
        .root_module = incremental_leaf_universal_genuine_root,
        .filters = incremental_leaf_universal_genuine_names,
    });
    b.step(
        "test-ethereum-incremental-leaf-universal-proof-v4-genuine",
        "Prove two native leaves and the genuine role0 q193 wrapper",
    ).dependOn(support.ProofTestGuard.add(
        b,
        b.addRunArtifact(incremental_leaf_universal_genuine_compile_and_run),
        incremental_leaf_universal_genuine_names,
        "genuine two-segment Ethereum incremental role0 proof guard",
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
