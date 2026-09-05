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
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    const stack_swap_root = support.createHarnessModule(
        b,
        "stack_swap_candidate_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    stack_swap_root.addImport("stwo_prover_engine", prover);
    stack_swap_root.addImport("interop_postcard", postcard);
    const stack_swap_test_names: []const []const u8 = &.{
        "stack swap runner trace proves, postcards, and cold fresh verifies",
        "stack swap proof selectors are current-only and power-of-two traces pad",
    };
    const stack_swap_compile = b.addTest(.{
        .root_module = stack_swap_root,
        .filters = stack_swap_test_names,
    });
    const stack_swap_tests = b.addRunArtifact(stack_swap_compile);
    stack_swap_tests.has_side_effects = true;
    b.step(
        "test-riscv-stack-swap-proof",
        "Prove and cold fresh-verify the nonproduction U256 swap candidate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        stack_swap_tests,
        stack_swap_test_names,
        "atomic U256 swap proof identity guard",
    ));
    const stack_swap_vm_root = support.createHarnessModule(
        b,
        "stack_swap_vm_integration_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const stack_swap_vm_test_names: []const []const u8 = &.{
        "stack swap VM private authority mints one exact declared program root",
        "stack swap VM component profile is appended and mutation closed",
        "stack swap VM cancellation requires the exact external base context",
    };
    const stack_swap_vm_compile = b.addTest(.{
        .root_module = stack_swap_vm_root,
        .filters = stack_swap_vm_test_names,
    });
    const stack_swap_vm_tests = b.addRunArtifact(stack_swap_vm_compile);
    stack_swap_vm_tests.has_side_effects = true;
    b.step(
        "test-riscv-stack-swap-vm-integration",
        "Validate the inactive private U256 swap full-VM boundary",
    ).dependOn(support.ProofTestGuard.add(
        b,
        stack_swap_vm_tests,
        stack_swap_vm_test_names,
        "private U256 swap VM integration guard",
    ));
    const degree5_provider_root = support.createHarnessModule(
        b,
        "degree5_provider_proof_v1_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    degree5_provider_root.addImport("stwo_prover_api", prover_api);
    degree5_provider_root.addImport("stwo_prover_engine", prover);
    degree5_provider_root.addImport("interop_postcard", postcard);
    const degree5_provider_test_names: []const []const u8 = &.{
        "degree-five retained provider program and N4 profile are cold and fail closed",
        "degree-five retained provider log16 postcard cold fresh verifies",
    };
    const degree5_provider_compile = b.addTest(.{
        .root_module = degree5_provider_root,
        .filters = degree5_provider_test_names,
    });
    const degree5_provider_tests = b.addRunArtifact(degree5_provider_compile);
    degree5_provider_tests.has_side_effects = true;
    b.step(
        "test-riscv-degree5-provider-proof",
        "Prove and cold fresh-verify one retained degree-five provider shard",
    ).dependOn(support.ProofTestGuard.add(
        b,
        degree5_provider_tests,
        degree5_provider_test_names,
        "degree-five retained provider proof identity guard",
    ));
    const degree5_provider_order_root = support.createHarnessModule(
        b,
        "degree5_provider_order_proof_v2_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    degree5_provider_order_root.addImport("stwo_prover_api", prover_api);
    degree5_provider_order_root.addImport("stwo_prover_engine", prover);
    degree5_provider_order_root.addImport("interop_postcard", postcard);
    const degree5_provider_order_test_names: []const []const u8 = &.{
        "degree-five ordered provider program binds its compiler projection",
        "degree-five ordered provider log16 postcard cold fresh verifies",
    };
    const degree5_provider_order_compile = b.addTest(.{
        .root_module = degree5_provider_order_root,
        .filters = degree5_provider_order_test_names,
    });
    const degree5_provider_order_tests = b.addRunArtifact(
        degree5_provider_order_compile,
    );
    degree5_provider_order_tests.has_side_effects = true;
    b.step(
        "test-riscv-degree5-provider-order-proof",
        "Prove and cold fresh-verify one ordered degree-five provider shard",
    ).dependOn(support.ProofTestGuard.add(
        b,
        degree5_provider_order_tests,
        degree5_provider_order_test_names,
        "degree-five ordered provider proof identity guard",
    ));
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
    const recursion_proof_root = b.createModule(.{
        .root_source_file = b.path("universal_typed_component_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(
        recursion_proof_root,
        core,
        prover_api,
        prover,
        cpu_backend,
        frontend,
    );
    const recursion_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = recursion_proof_root,
    }));
    // The guard reads the test-name table produced by this invocation. A cache
    // hit does not populate that table, so the proof evidence must run rather
    // than merely reuse a successful exit code from an older binary.
    recursion_proof_tests.has_side_effects = true;
    const recursion_proof_step = b.step(
        "test-recursion-air-proof",
        "Prove and independently verify typed universal recursion adapters",
    );
    recursion_proof_step.dependOn(support.ProofTestGuard.add(
        b,
        recursion_proof_tests,
        &.{
            "R-012 active FRI Merkle leaf adapter proves and independently verifies",
            "R-012 active FRI Merkle node adapter proves and independently verifies",
            "R-012 manifest-driven rows 29 and 33 prove and independently verify",
        },
        "R-012 narrow native recursion proof identity guard",
    ));

    const keccakf_proof_root = b.createModule(.{
        .root_source_file = b.path("keccakf_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(
        keccakf_proof_root,
        core,
        prover_api,
        prover,
        cpu_backend,
        frontend,
    );
    keccakf_proof_root.addImport(
        "keccakf_proof_harness",
        ctx.keccakf_proof_harness,
    );
    const keccakf_proof_compile = b.addTest(.{
        .root_module = keccakf_proof_root,
        .filters = &.{"Keccak-f typed shard and lookup tables prove and independently verify"},
    });
    b.step(
        "check-keccakf-precompile-proof",
        "Compile the typed Keccak-f native proof gate without executing it",
    ).dependOn(&keccakf_proof_compile.step);
    const keccakf_proof_tests = b.addRunArtifact(keccakf_proof_compile);
    keccakf_proof_tests.has_side_effects = true;
    b.step(
        "test-keccakf-precompile-proof",
        "Prove and independently verify the typed Keccak-f shard and lookup tables",
    ).dependOn(support.ProofTestGuard.add(
        b,
        keccakf_proof_tests,
        &.{"Keccak-f typed shard and lookup tables prove and independently verify"},
        "Keccak-f native proof identity guard",
    ));

    const secp256k1_proof_root = b.createModule(.{
        .root_source_file = b.path("secp256k1_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(
        secp256k1_proof_root,
        core,
        prover_api,
        prover,
        cpu_backend,
        frontend,
    );
    secp256k1_proof_root.addImport(
        "secp256k1_proof_harness",
        ctx.secp256k1_proof_harness,
    );
    const secp256k1_proof_name =
        "secp256k1 typed ECDSA bundle proves and independently verifies";
    const secp256k1_proof_compile = b.addTest(.{
        .root_module = secp256k1_proof_root,
        .filters = &.{secp256k1_proof_name},
    });
    b.step(
        "check-secp256k1-precompile-proof",
        "Compile the compact typed secp256k1 native proof gate",
    ).dependOn(&secp256k1_proof_compile.step);
    const secp256k1_proof_tests = b.addRunArtifact(secp256k1_proof_compile);
    secp256k1_proof_tests.has_side_effects = true;
    b.step(
        "test-secp256k1-precompile-proof",
        "Prove and independently verify compact typed secp256k1 ECDSA",
    ).dependOn(support.ProofTestGuard.add(
        b,
        secp256k1_proof_tests,
        &.{secp256k1_proof_name},
        "secp256k1 native proof identity guard",
    ));

    const ethereum_proof_root = b.createModule(.{
        .root_source_file = b.path("ethereum_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(
        ethereum_proof_root,
        core,
        prover_api,
        prover,
        cpu_backend,
        frontend,
    );
    const ethereum_proof_name =
        "Ethereum base Keccak and signer recovery prove and independently verify on CPU";
    const ethereum_proof_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_proof_name},
    });
    b.step(
        "check-ethereum-precompile-proof",
        "Compile the joined Ethereum leaf proof and independent-verifier gate",
    ).dependOn(&ethereum_proof_compile.step);
    const ethereum_proof_tests = b.addRunArtifact(ethereum_proof_compile);
    ethereum_proof_tests.has_side_effects = true;
    b.step(
        "test-ethereum-precompile-proof",
        "Prove and independently verify base plus Keccak plus signer recovery",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_proof_tests,
        &.{ethereum_proof_name},
        "Ethereum joined leaf proof identity guard",
    ));
    const ethereum_zero_name =
        "Ethereum zero-family segment preserves fourteen slots and independently verifies";
    const ethereum_zero_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_zero_name},
    });
    b.step(
        "check-ethereum-zero-family-proof",
        "Compile the canonical all-empty Ethereum extension segment proof",
    ).dependOn(&ethereum_zero_compile.step);
    const ethereum_zero_tests = b.addRunArtifact(ethereum_zero_compile);
    ethereum_zero_tests.has_side_effects = true;
    b.step(
        "test-ethereum-zero-family-proof",
        "Prove and independently verify an all-empty Ethereum extension segment",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_zero_tests,
        &.{ethereum_zero_name},
        "Ethereum zero-family proof identity guard",
    ));
    const ethereum_segment_zero_name =
        "Ethereum nonfinal SegmentV2 zero-extension leaf proves and verifies";
    const ethereum_segment_zero_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_segment_zero_name},
    });
    b.step(
        "check-ethereum-segment-v2-zero-proof",
        "Compile the non-final Ethereum SegmentV2 zero-extension proof gate",
    ).dependOn(&ethereum_segment_zero_compile.step);
    const ethereum_segment_zero_tests = b.addRunArtifact(
        ethereum_segment_zero_compile,
    );
    ethereum_segment_zero_tests.has_side_effects = true;
    b.step(
        "test-ethereum-segment-v2-zero-proof",
        "Prove and verify one non-final Ethereum SegmentV2 zero-extension leaf",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_segment_zero_tests,
        &.{ethereum_segment_zero_name},
        "Ethereum SegmentV2 zero-extension proof identity guard",
    ));
    const ethereum_segment_signer_name =
        "Ethereum nonfinal SegmentV2 signer leaf proves and verifies";
    const ethereum_segment_signer_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_segment_signer_name},
    });
    b.step(
        "check-ethereum-segment-v2-signer-proof",
        "Compile the non-final Ethereum SegmentV2 signer proof gate",
    ).dependOn(&ethereum_segment_signer_compile.step);
    const ethereum_segment_signer_tests = b.addRunArtifact(
        ethereum_segment_signer_compile,
    );
    ethereum_segment_signer_tests.has_side_effects = true;
    b.step(
        "test-ethereum-segment-v2-signer-proof",
        "Prove and verify one non-final Ethereum SegmentV2 signer leaf",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_segment_signer_tests,
        &.{ethereum_segment_signer_name},
        "Ethereum SegmentV2 signer proof identity guard",
    ));
    const ethereum_segment_capture_name =
        "Ethereum SegmentV3 capture seals count-sensitive extension sidecars";
    const ethereum_segment_capture_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_segment_capture_name},
    });
    b.step(
        "check-ethereum-segment-v3-capture-proof",
        "Compile the full dynamic Ethereum SegmentV3 verifier capture gate",
    ).dependOn(&ethereum_segment_capture_compile.step);
    const ethereum_segment_capture_tests = b.addRunArtifact(
        ethereum_segment_capture_compile,
    );
    ethereum_segment_capture_tests.has_side_effects = true;
    b.step(
        "test-ethereum-segment-v3-capture-proof",
        "Verify dynamic Ethereum capture and count-sensitive sidecar binding",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_segment_capture_tests,
        &.{ethereum_segment_capture_name},
        "Ethereum SegmentV3 full capture identity guard",
    ));
    const ethereum_segment_extension_name =
        "Ethereum SegmentV2 extended transcript binds dynamic provider shard count";
    const ethereum_segment_extension_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_segment_extension_name},
    });
    b.step(
        "check-ethereum-segment-transcript-extension",
        "Compile the additive Ethereum SegmentV2/V3 transcript extension",
    ).dependOn(&ethereum_segment_extension_compile.step);
    const ethereum_segment_extension_tests = b.addRunArtifact(
        ethereum_segment_extension_compile,
    );
    ethereum_segment_extension_tests.has_side_effects = true;
    b.step(
        "test-ethereum-segment-transcript-extension",
        "Prove and freshly verify the additive Ethereum segment transcript",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_segment_extension_tests,
        &.{ethereum_segment_extension_name},
        "Ethereum SegmentV2/V3 transcript-extension identity guard",
    ));
    const omit_validated_parity_name =
        "Ethereum omitted provider validated and unvalidated routes agree bit for bit";
    const omit_validated_parity_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{omit_validated_parity_name},
    });
    b.step(
        "check-ethereum-omit-validated-parity-v1",
        "Compile the validated-vs-unvalidated omission-route parity gate",
    ).dependOn(&omit_validated_parity_compile.step);
    const omit_validated_parity_tests = b.addRunArtifact(
        omit_validated_parity_compile,
    );
    omit_validated_parity_tests.has_side_effects = true;
    b.step(
        "test-ethereum-omit-validated-parity-v1",
        "Prove both omission routes and require identical outputs",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omit_validated_parity_tests,
        &.{omit_validated_parity_name},
        "Ethereum omitted-provider validated-route parity guard",
    ));

    const omitted_route_instantiation_name =
        "Ethereum omitted-provider V4 route instantiates against the q193 CPU engine";
    const omitted_route_instantiation_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{omitted_route_instantiation_name},
    });
    b.step(
        "check-ethereum-incremental-omitted-route-v4",
        "Analyse the omitted-provider V4 prover and cold verifier on the q193 CPU engine",
    ).dependOn(&omitted_route_instantiation_compile.step);
    const omitted_route_instantiation_tests = b.addRunArtifact(
        omitted_route_instantiation_compile,
    );
    omitted_route_instantiation_tests.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-omitted-route-v4",
        "Run the omitted-provider V4 route instantiation and activation-guard gate",
    ).dependOn(support.ProofTestGuard.add(
        b,
        omitted_route_instantiation_tests,
        &.{omitted_route_instantiation_name},
        "Ethereum omitted-provider V4 route instantiation guard",
    ));

    const ethereum_poseidon_artifact_name =
        "Ethereum Poseidon2 SegmentV3 artifact verifies full dynamic capture";
    const ethereum_poseidon_artifact_compile = b.addTest(.{
        .root_module = ethereum_proof_root,
        .filters = &.{ethereum_poseidon_artifact_name},
    });
    b.step(
        "check-ethereum-poseidon-segment-artifact",
        "Compile the Poseidon2 Ethereum SegmentV3 artifact round trip",
    ).dependOn(&ethereum_poseidon_artifact_compile.step);
    const ethereum_poseidon_artifact_test = b.addRunArtifact(
        ethereum_poseidon_artifact_compile,
    );
    ethereum_poseidon_artifact_test.has_side_effects = true;
    b.step(
        "test-ethereum-poseidon-segment-artifact",
        "Prove, serialize, and verify a Poseidon2 Ethereum SegmentV3 leaf",
    ).dependOn(support.ProofTestGuard.add(
        b,
        ethereum_poseidon_artifact_test,
        &.{ethereum_poseidon_artifact_name},
        "Poseidon2 Ethereum SegmentV3 artifact identity guard",
    ));

    const full_recursion_proof_root = b.createModule(.{
        .root_source_file = b.path("universal_recursive_air_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(
        full_recursion_proof_root,
        core,
        prover_api,
        prover,
        cpu_backend,
        frontend,
    );
    full_recursion_proof_root.addImport("interop_postcard", postcard);
    const full_recursion_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = full_recursion_proof_root,
    }));
    full_recursion_proof_tests.has_side_effects = true;
    const full_recursion_proof_step = b.step(
        "test-recursion-full-air-proof",
        "Prove and independently verify the complete 36-row recursion AIR",
    );
    full_recursion_proof_step.dependOn(support.ProofTestGuard.add(
        b,
        full_recursion_proof_tests,
        &.{
            "R-012 full 36-row universal recursion AIR proves and independently verifies",
        },
        "R-012 full native recursion proof identity guard",
    ));
    const segment_closure_root = support.createHarnessModule(
        b,
        "recursive_fri_outer.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_closure_root.addImport("stwo_prover_api", prover_api);
    segment_closure_root.addImport("stwo_prover_engine", prover);
    const segment_closure_test_names: []const []const u8 = &.{
        "native SegmentV2 core owner API is compile-complete",
        "recursion Poseidon2 native leaf segment closure rejects cross-domain cancellation",
        "recursion Poseidon2 native leaf segment closure receipt mutations and atomicity",
    };
    const segment_closure_compile = b.addTest(.{
        .root_module = segment_closure_root,
        .filters = &.{"segment global closure:"},
    });
    b.step(
        "check-recursive-segment-global-closure",
        "Compile the exact verifier-side 36-row/47-domain closure receipt",
    ).dependOn(&segment_closure_compile.step);
    const segment_closure_tests = b.addRunArtifact(segment_closure_compile);
    segment_closure_tests.has_side_effects = true;
    const segment_closure_step = b.step(
        "test-recursive-segment-global-closure",
        "Run the segment closure cross-domain and fail-atomic mutation gate",
    );
    segment_closure_step.dependOn(support.ProofTestGuard.add(
        b,
        segment_closure_tests,
        segment_closure_test_names,
        "segment global-closure receipt identity guard",
    ));
    const segment_v2_native_root = support.createHarnessModule(
        b,
        "segment_v2_native_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    segment_v2_native_root.addImport("stwo_prover_api", prover_api);
    segment_v2_native_root.addImport("stwo_prover_engine", prover);
    segment_v2_native_root.addImport("interop_postcard", postcard);
    const segment_v2_native_test_names: []const []const u8 = &.{
        "native V2 proves and independently verifies real nonfinal and final segments",
        "native V2 proves a rebased leaf-local V3 segment without widening the AIR",
    };
    const segment_v2_native_compile = b.addTest(.{
        .root_module = segment_v2_native_root,
        .filters = segment_v2_native_test_names,
    });
    b.step(
        "check-riscv-segment-v2-native-proof",
        "Compile the real non-final/final native V2 segment proof gate",
    ).dependOn(&segment_v2_native_compile.step);
    const segment_v2_native_tests = b.addRunArtifact(segment_v2_native_compile);
    segment_v2_native_tests.has_side_effects = true;
    const segment_v2_native_step = b.step(
        "test-riscv-segment-v2-native-proof",
        "Prove and independently verify real non-final/final V2 segments",
    );
    segment_v2_native_step.dependOn(support.ProofTestGuard.add(
        b,
        segment_v2_native_tests,
        segment_v2_native_test_names,
        "native V2 segment proof identity guard",
    ));
    const lookup_v2_native_root = support.createHarnessModule(
        b,
        "lookup_v2_native_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    lookup_v2_native_root.addImport("stwo_prover_api", prover_api);
    lookup_v2_native_root.addImport("stwo_prover_engine", prover);
    lookup_v2_native_root.addImport("interop_postcard", postcard);
    const lookup_v2_test_backend = b.createModule(.{
        .root_source_file = b.path("lookup_v2_cpu_test_backend.zig"),
        .target = target,
        .optimize = optimize,
    });
    lookup_v2_test_backend.addImport("stwo_cpu_backend", cpu_backend);
    lookup_v2_test_backend.addImport("stwo_riscv_frontend", frontend);
    lookup_v2_native_root.addImport(
        "lookup_v2_test_backend",
        lookup_v2_test_backend,
    );
    const lookup_v2_native_test_names: []const []const u8 = &.{
        "authenticated lookup V2 proves, independently verifies, and rejects compatibility replay",
    };
    const lookup_v2_native_compile = b.addTest(.{
        .root_module = lookup_v2_native_root,
        .filters = lookup_v2_native_test_names,
    });
    b.step(
        "check-riscv-lookup-v2-native-proof",
        "Compile authenticated lookup V2 real-proof acceptance",
    ).dependOn(&lookup_v2_native_compile.step);
    const lookup_v2_native_tests = b.addRunArtifact(lookup_v2_native_compile);
    lookup_v2_native_tests.has_side_effects = true;
    const lookup_v2_native_step = b.step(
        "test-riscv-lookup-v2-native-proof",
        "Compare, prove, and independently verify authenticated lookup V2",
    );
    lookup_v2_native_step.dependOn(support.ProofTestGuard.add(
        b,
        lookup_v2_native_tests,
        lookup_v2_native_test_names,
        "authenticated lookup V2 real-proof identity guard",
    ));
    const generated_composition_root = support.createHarnessModule(
        b,
        "generated_composition_native_proof_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    generated_composition_root.addImport("stwo_prover_api", prover_api);
    generated_composition_root.addImport("stwo_prover_engine", prover);
    generated_composition_root.addImport("interop_postcard", postcard);
    const generated_composition_test_names: []const []const u8 = &.{
        "A-013 generated full-cohort composition is proof-byte and transcript exact",
    };
    const generated_composition_compile = b.addTest(.{
        .root_module = generated_composition_root,
        .filters = generated_composition_test_names,
    });
    b.step(
        "check-riscv-generated-composition-native-proof",
        "Compile A-013 generated-composition real-proof equivalence",
    ).dependOn(&generated_composition_compile.step);
    const generated_composition_tests = b.addRunArtifact(
        generated_composition_compile,
    );
    generated_composition_tests.has_side_effects = true;
    b.step(
        "test-riscv-generated-composition-native-proof",
        "Prove exact A-013 generated/reference composition equivalence",
    ).dependOn(support.ProofTestGuard.add(
        b,
        generated_composition_tests,
        generated_composition_test_names,
        "A-013 generated-composition real-proof identity guard",
    ));

    ctx.test_step.dependOn(&tests.step);
    ctx.test_step.dependOn(recursion_proof_step);
    ctx.test_step.dependOn(full_recursion_proof_step);
    ctx.test_step.dependOn(segment_closure_step);
}
