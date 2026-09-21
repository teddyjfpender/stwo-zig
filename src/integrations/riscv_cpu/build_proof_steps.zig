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
    @import("build_ethereum_leaf_steps.zig").add(ctx);
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
    const csp_ecdsa_gate = b.addTest(.{
        .root_module = secp256k1_proof_root,
        .filters = &.{"CSP ECDSA guest proves caller memory and result at canonical security"},
    });
    const csp_ecdsa_run = b.addRunArtifact(csp_ecdsa_gate);
    csp_ecdsa_run.has_side_effects = true;
    b.step("test-csp-ecdsa-guest-proof", "Prove and freshly verify full CSP ECDSA precompile guest").dependOn(&csp_ecdsa_run.step);

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

    const keccak_scaling_root = b.createModule(.{
        .root_source_file = b.path("ethereum_keccak_scaling_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    support.addImports(keccak_scaling_root, core, prover_api, prover, cpu_backend, frontend);
    const keccak_scaling_names: []const []const u8 = &.{
        "complete RV Keccak one call serializes destroys producer and freshly verifies",
        "complete RV Keccak four calls serialize destroy producer and freshly verify",
        "complete RV Keccak sixteen calls serialize destroy producer and freshly verify",
    };
    inline for (.{ .{ "one", 1 }, .{ "scaling", 3 } }) |selection| {
        const selected_names = keccak_scaling_names[0..selection[1]];
        const compiled = b.addTest(.{ .root_module = keccak_scaling_root, .filters = selected_names });
        b.step("check-riscv-keccak-" ++ selection[0] ++ "-proof", "Compile the focused complete VM Keccak lifecycle").dependOn(&compiled.step);
        const run = b.addRunArtifact(compiled);
        run.has_side_effects = true;
        b.step("test-riscv-keccak-" ++ selection[0] ++ "-proof", "Serialize a full VM Keccak proof, destroy producer and freshly verify").dependOn(support.ProofTestGuard.add(
            b,
            run,
            selected_names,
            "complete VM Keccak " ++ selection[0] ++ " lifecycle identity guard",
        ));
    }

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
