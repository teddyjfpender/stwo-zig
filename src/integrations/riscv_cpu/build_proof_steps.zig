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
