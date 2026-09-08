//! Bounded Ethereum leaf, provider, and commitment development commands.
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
    const ethereum_node_root = support.createHarnessModule(b, "ethereum_node_proof_v1_runner.zig", target, optimize, core, cpu_backend, frontend, integration);
    const ethereum_node_run = b.addRunArtifact(b.addExecutable(.{ .name = "ethereum-node-proof-v1", .root_module = ethereum_node_root }));
    if (b.args) |args| ethereum_node_run.addArgs(args);
    ethereum_node_run.has_side_effects = true;
    b.step("run-ethereum-node-proof-v1", "Prove full-output Ethereum nodes and freshly verify their serialized proof").dependOn(&ethereum_node_run.step);
    const candidate_provider_batch_root = support.createHarnessModule(
        b,
        "ethereum_candidate_degree5_provider_batch_v1_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    candidate_provider_batch_root.addImport("stwo_prover_engine", prover);
    const candidate_provider_batch_test_names: []const []const u8 = &.{
        "candidate D5 batch accounts retained log18 owners and rejects oversized log16",
        "candidate D5 batch authority rejects CPU RSS and plan mutation",
        "candidate D5 batch host admission is machine-generic",
        "candidate D5 validated call authority is pointer closed and rejects descriptor mutation",
        "candidate D5 prepared and proof batch declarations compile",
    };
    const candidate_provider_batch_compile = b.addTest(.{
        .root_module = candidate_provider_batch_root,
        .filters = candidate_provider_batch_test_names,
    });
    const candidate_provider_batch_tests = b.addRunArtifact(
        candidate_provider_batch_compile,
    );
    candidate_provider_batch_tests.has_side_effects = true;
    b.step(
        "test-ethereum-candidate-degree5-provider-batch-v1",
        "Validate runtime-authorized D5 provider batch topology and owners",
    ).dependOn(support.ProofTestGuard.add(
        b,
        candidate_provider_batch_tests,
        candidate_provider_batch_test_names,
        "candidate D5 provider batch identity guard",
    ));
    const omitted_transcript_root = support.createHarnessModule(
        b,
        "ethereum_incremental_omitted_provider_transcript_v1_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    omitted_transcript_root.addImport("stwo_prover_engine", prover);
    const omitted_transcript_test_names: []const []const u8 = &.{
        "omitted provider transcript v1: route bindings admit exactly the recomputed authorities",
        "omitted provider transcript v1: route bindings reject every mutated field",
        "omitted provider transcript v1: route bindings reject a mutated recomputed authority",
        "omitted provider transcript v1: replayShared reproduces the hand-built channel",
        "omitted provider transcript v1: replay refuses a frame bound to another projection",
        "omitted provider transcript v1: local prefix is the ordinary frame plus the leaf omission frame",
        "omitted provider transcript v1: leaf provider statement binds the omission digest",
        "omitted provider transcript v1: retype helpers guard transcript types and preserve identity",
        "omitted provider transcript v1: module stays research only",
        "omitted provider transcript v1: route source binds the real V4 profile",
        "omitted provider transcript v1 declarations compile",
    };
    const omitted_transcript_compile = b.addTest(.{
        .root_module = omitted_transcript_root,
        .filters = omitted_transcript_test_names,
    });
    b.step(
        "check-ethereum-incremental-omitted-provider-transcript-v1",
        "Compile the omitted-provider shared shard transcript source",
    ).dependOn(&omitted_transcript_compile.step);
    const omitted_transcript_tests = b.addRunArtifact(
        omitted_transcript_compile,
    );
    omitted_transcript_tests.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-omitted-provider-transcript-v1",
        "Pin the omitted-provider shard transcript order, bindings, and retypes",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omitted_transcript_tests,
        omitted_transcript_test_names,
        "omitted-provider shard transcript identity guard",
    ));
    const shared_batch_root = support.createHarnessModule(
        b,
        "ethereum_candidate_degree5_provider_shared_batch_v1_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    shared_batch_root.addImport("stwo_prover_engine", prover);
    shared_batch_root.addImport("interop_postcard", postcard);
    const shared_batch_test_names: []const []const u8 = &.{
        "shared D5 provider batch: a canonical batch admits its own shards",
        "shared D5 provider batch: canonical validation rejects every mutated field",
        "shared D5 provider batch: leaf statement wrapping binds this leaf",
        "shared D5 provider batch: shard artifacts stay under the canonical cap",
        "shared D5 provider batch: fresh claims must report the shared context",
        "shared D5 provider batch: custody surfaces stay byte only and leaf bound",
        "shared D5 provider batch declarations compile",
    };
    const shared_batch_compile = b.addTest(.{
        .root_module = shared_batch_root,
        .filters = shared_batch_test_names,
    });
    b.step(
        "check-ethereum-candidate-degree5-provider-shared-batch-v1",
        "Compile the shared-transcript D5 provider batch prover and verifier",
    ).dependOn(&shared_batch_compile.step);
    const shared_batch_tests = b.addRunArtifact(shared_batch_compile);
    shared_batch_tests.has_side_effects = true;
    b.step(
        "test-ethereum-candidate-degree5-provider-shared-batch-v1",
        "Pin shared D5 shard custody, leaf statement binding, and byte caps",
    ).dependOn(support.ProofTestGuard.add(
        b,
        shared_batch_tests,
        shared_batch_test_names,
        "shared D5 provider batch custody guard",
    ));
    const omitted_envelope_root = support.createHarnessModule(
        b,
        "ethereum_incremental_omitted_leaf_proof_artifact_v1_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    omitted_envelope_root.addImport("stwo_prover_engine", prover);
    omitted_envelope_root.addImport("interop_postcard", postcard);
    const omitted_envelope_test_names: []const []const u8 = &.{
        "STWIOL01 envelope: framing round-trips fixed sections and shard artifacts",
        "STWIOL01 envelope: seal, length and magic tampering are refused",
        "STWIOL01 envelope: STWIEF04 and STWIOL01 decoders reject each other",
        "STWIOL01 envelope: omission section round-trips and readmits every field",
        "STWIOL01 envelope: every mutated omission field is rejected",
        "STWIOL01 envelope: header shard count must match the omission section",
        "STWIOL01 envelope: typed encoder and decoders instantiate on the q193 CPU engine",
        "STWIOL01 envelope declarations compile",
    };
    const omitted_envelope_compile = b.addTest(.{
        .root_module = omitted_envelope_root,
        .filters = omitted_envelope_test_names,
    });
    b.step(
        "check-ethereum-incremental-omitted-leaf-proof-artifact-v1",
        "Compile the STWIOL01 omitted-leaf proof envelope codec",
    ).dependOn(&omitted_envelope_compile.step);
    const omitted_envelope_tests = b.addRunArtifact(omitted_envelope_compile);
    omitted_envelope_tests.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-omitted-leaf-proof-artifact-v1",
        "Pin STWIOL01 framing, omission-section readmission, and cross-magic refusal",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omitted_envelope_tests,
        omitted_envelope_test_names,
        "STWIOL01 omitted-leaf envelope custody guard",
    ));
    const omitted_route_body_root = support.createHarnessModule(
        b,
        "ethereum_incremental_omitted_leaf_route_v1_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    omitted_route_body_root.addImport("stwo_prover_api", prover_api);
    omitted_route_body_root.addImport("stwo_prover_engine", prover);
    omitted_route_body_root.addImport("interop_postcard", postcard);
    omitted_route_body_root.addImport("stwo_artifact_store", ctx.artifact_store);
    const omitted_route_body_test_names: []const []const u8 = &.{
        "Stage101 D5 route body instantiates on the q193 CPU engine",
        "Stage101 D5 route strips only its own flag and rejects unknown route values",
        "Stage101 D5 route budget maps stage A into the proof-core window",
        "Stage101 D5 route receipt rejects unshared relation context and non-zero closure",
        "Stage101 D5 route pins equal the sweep's retained request",
        "Stage101 D5 route declarations compile",
    };
    const omitted_route_body_compile = b.addTest(.{
        .root_module = omitted_route_body_root,
        .filters = omitted_route_body_test_names,
    });
    b.step(
        "check-ethereum-incremental-omitted-leaf-route-v1",
        "Analyse the engine-generic Stage101 D5 provider route body on the q193 CPU engine",
    ).dependOn(&omitted_route_body_compile.step);
    const omitted_route_body_tests = b.addRunArtifact(omitted_route_body_compile);
    omitted_route_body_tests.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-omitted-leaf-route-v1",
        "Pin the Stage101 D5 route dispatch, budget, receipt matrix and comptime pins",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omitted_route_body_tests,
        omitted_route_body_test_names,
        "Stage101 D5 provider route body guard",
    ));
    const candidate_leaf_root = support.createHarnessModule(
        b,
        "ethereum_candidate_leaf_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    candidate_leaf_root.addImport("stwo_prover_api", prover_api);
    candidate_leaf_root.addImport("stwo_prover_engine", prover);
    candidate_leaf_root.addImport("interop_postcard", postcard);
    const candidate_leaf_test_names: []const []const u8 = &.{
        "combined candidate leaf postcards, cold verifies, and closes degree-five providers",
    };
    const candidate_leaf_compile = b.addTest(.{
        .root_module = candidate_leaf_root,
        .filters = candidate_leaf_test_names,
    });
    b.step(
        "build-riscv-ethereum-candidate-leaf-proof",
        "Compile the combined candidate plus runtime D5 provider batch gate",
    ).dependOn(&candidate_leaf_compile.step);
    const candidate_leaf_tests = b.addRunArtifact(candidate_leaf_compile);
    candidate_leaf_tests.has_side_effects = true;
    b.step(
        "test-riscv-ethereum-candidate-leaf-proof",
        "Prove and cold fresh-verify the combined candidate plus d5 providers",
    ).dependOn(support.ProofTestGuard.add(
        b,
        candidate_leaf_tests,
        candidate_leaf_test_names,
        "combined candidate leaf terminal proof identity guard",
    ));
    const omitted_leaf_bundle_root = support.createHarnessModule(
        b,
        "ethereum_provider_omitted_leaf_bundle_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    omitted_leaf_bundle_root.addImport("stwo_prover_api", prover_api);
    omitted_leaf_bundle_root.addImport("stwo_prover_engine", prover);
    omitted_leaf_bundle_root.addImport("interop_postcard", postcard);
    const omitted_leaf_bundle_test_names: []const []const u8 = &.{
        "ordinary omitted-provider bundle frozen APIs type instantiate",
        "ordinary omitted-provider framing rejects canonical order and identity mutations",
        "ordinary omitted-provider capture custody rejects identity and ordinal mutations",
    };
    const omitted_leaf_bundle_compile = b.addTest(.{
        .root_module = omitted_leaf_bundle_root,
        .filters = omitted_leaf_bundle_test_names,
    });
    const omitted_leaf_bundle_tests = b.addRunArtifact(
        omitted_leaf_bundle_compile,
    );
    omitted_leaf_bundle_tests.has_side_effects = true;
    b.step(
        "test-riscv-ethereum-provider-omitted-leaf-bundle",
        "Type-check omitted-provider custody and validate its canonical envelope",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omitted_leaf_bundle_tests,
        omitted_leaf_bundle_test_names,
        "ordinary omitted-provider cold bundle identity guard",
    ));
    const incremental_native_leaf_root = support.createHarnessModule(
        b,
        "ethereum_incremental_native_leaf_proof_v3_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    incremental_native_leaf_root.addImport("stwo_prover_api", prover_api);
    incremental_native_leaf_root.addImport("stwo_prover_engine", prover);
    incremental_native_leaf_root.addImport("interop_postcard", postcard);
    const incremental_native_leaf_test_names: []const []const u8 = &.{
        "incremental native V3 proof cold-decodes and freshly captures q193 PCS",
    };
    const incremental_native_leaf_compile = b.addTest(.{
        .root_module = incremental_native_leaf_root,
        .filters = incremental_native_leaf_test_names,
    });
    const incremental_native_leaf_tests = b.addRunArtifact(
        incremental_native_leaf_compile,
    );
    incremental_native_leaf_tests.has_side_effects = true;
    b.step(
        "test-riscv-ethereum-incremental-native-leaf-proof-v3",
        "Prove, cold-decode, and freshly verify one incremental native V3 leaf",
    ).dependOn(support.ProofTestGuard.add(
        b,
        incremental_native_leaf_tests,
        incremental_native_leaf_test_names,
        "incremental native V3 terminal proof identity guard",
    ));
    const incremental_full_leaf_root = support.createHarnessModule(
        b,
        "ethereum_incremental_full_leaf_proof_v4_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    incremental_full_leaf_root.addImport("stwo_prover_api", prover_api);
    incremental_full_leaf_root.addImport("stwo_prover_engine", prover);
    incremental_full_leaf_root.addImport("interop_postcard", postcard);
    const incremental_full_leaf_test_names: []const []const u8 = &.{
        "full Ethereum incremental V4 proof coldly verifies q193 capture",
    };
    const incremental_full_leaf_compile = b.addTest(.{
        .root_module = incremental_full_leaf_root,
        .filters = incremental_full_leaf_test_names,
    });
    const incremental_full_leaf_tests = b.addRunArtifact(
        incremental_full_leaf_compile,
    );
    incremental_full_leaf_tests.has_side_effects = true;
    b.step(
        "test-riscv-ethereum-incremental-full-leaf-proof-v4",
        "Prove, cold-decode, and fresh-verify Ethereum plus V4 memory",
    ).dependOn(support.ProofTestGuard.add(
        b,
        incremental_full_leaf_tests,
        incremental_full_leaf_test_names,
        "incremental Ethereum V4 terminal proof identity guard",
    ));
    const incremental_full_leaf_replay_producer_root =
        support.createHarnessModule(
            b,
            "ethereum_incremental_full_leaf_replay_producer_v4_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        );
    incremental_full_leaf_replay_producer_root.addImport(
        "stwo_prover_api",
        prover_api,
    );
    incremental_full_leaf_replay_producer_root.addImport(
        "stwo_prover_engine",
        prover,
    );
    incremental_full_leaf_replay_producer_root.addImport(
        "interop_postcard",
        postcard,
    );
    const incremental_full_leaf_replay_producer_test_names: []const []const u8 = &.{
        "VM-free incremental full-leaf producer API type instantiates",
        "leaf-local completion consumes the actual declared program word",
        "validated lease copies sources and records one trust boundary",
        "retained statement decode moves one lease into fresh public custody",
        "validated lease releases every partial allocation",
        "validated authority surface stays process-local and exposes lease paths",
    };
    const incremental_full_leaf_replay_producer_compile = b.addTest(.{
        .root_module = incremental_full_leaf_replay_producer_root,
        .filters = incremental_full_leaf_replay_producer_test_names,
    });
    const incremental_full_leaf_replay_producer_tests = b.addRunArtifact(
        incremental_full_leaf_replay_producer_compile,
    );
    incremental_full_leaf_replay_producer_tests.has_side_effects = true;
    b.step(
        "test-riscv-ethereum-incremental-full-leaf-replay-producer-v4",
        "Type-check the VM-free Ethereum incremental leaf producer",
    ).dependOn(support.ProofTestGuard.add(
        b,
        incremental_full_leaf_replay_producer_tests,
        incremental_full_leaf_replay_producer_test_names,
        "incremental Ethereum V4 VM-free producer type guard",
    ));
    const main_witness_poseidon2_root = support.createHarnessModule(
        b,
        "split_pcs_prepare_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    main_witness_poseidon2_root.addImport("stwo_prover_api", prover_api);
    main_witness_poseidon2_root.addImport("stwo_prover_engine", prover);
    const main_witness_poseidon2_test_names: []const []const u8 = &.{
        "P-003 Poseidon2 extension base producer publishes exact main-witness receipt",
    };
    const main_witness_poseidon2_compile = b.addTest(.{
        .root_module = main_witness_poseidon2_root,
        .filters = main_witness_poseidon2_test_names,
    });
    const main_witness_poseidon2_tests = b.addRunArtifact(
        main_witness_poseidon2_compile,
    );
    main_witness_poseidon2_tests.has_side_effects = true;
    b.step(
        "test-main-witness-poseidon2-receipt",
        "Run the exact Poseidon2 extension main-witness receipt gate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        main_witness_poseidon2_tests,
        main_witness_poseidon2_test_names,
        "Poseidon2 extension main-witness receipt identity guard",
    ));
    const split_pcs_prepare_tests = b.addRunArtifact(b.addTest(.{
        .root_module = main_witness_poseidon2_root,
        .filters = &.{"R-008 actual CPU"},
    }));
    b.step(
        "test-split-pcs-prepare",
        "Run only the split PCS caller/provider proof gates",
    ).dependOn(&split_pcs_prepare_tests.step);
    const combined_main_witness_root = support.createHarnessModule(
        b,
        "guest_precompile_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    combined_main_witness_root.addImport("stwo_prover_api", prover_api);
    combined_main_witness_root.addImport("stwo_prover_engine", prover);
    const combined_main_witness_test_names: []const []const u8 = &.{
        "P-003 combined Poseidon2 producer publishes main-witness work",
    };
    const combined_main_witness_compile = b.addTest(.{
        .root_module = combined_main_witness_root,
        .filters = combined_main_witness_test_names,
    });
    const combined_main_witness_tests = b.addRunArtifact(
        combined_main_witness_compile,
    );
    combined_main_witness_tests.has_side_effects = true;
    b.step(
        "test-main-witness-poseidon2-combined-receipt",
        "Run the combined Poseidon2 prover main-witness receipt gate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        combined_main_witness_tests,
        combined_main_witness_test_names,
        "combined Poseidon2 main-witness receipt identity guard",
    ));
}
