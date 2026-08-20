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
    const binary_outer_root = support.createHarnessModule(
        b,
        "recursive_binary_outer_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    binary_outer_root.addImport("stwo_prover_api", prover_api);
    binary_outer_root.addImport("stwo_prover_engine", prover);
    binary_outer_root.addImport("interop_postcard", postcard);
    const binary_outer_tests = b.addRunArtifact(b.addTest(.{
        .root_module = binary_outer_root,
    }));
    b.step(
        "test-recursive-binary-outer",
        "Run only the authenticated binary-parent CPU proof kernel",
    ).dependOn(&binary_outer_tests.step);
    const binary_publication_root = support.createHarnessModule(
        b,
        "recursive_binary_verified_publication_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    const binary_publication_test_names: []const []const u8 = &.{
        "binary verifier publication owns exact closure without capability escalation",
        "binary verifier canonical proof identity is chunk-boundary invariant",
        "binary verifier publication rejects input mutation fleet atomically",
        "binary verifier publication rejects output capability and context mutation fleet",
        "binary verifier publication rejects destination alias before validation",
    };
    const binary_publication_compile = b.addTest(.{
        .root_module = binary_publication_root,
        .filters = binary_publication_test_names,
    });
    b.step(
        "check-recursive-binary-verified-publication",
        "Compile the successful binary-verifier publication boundary",
    ).dependOn(&binary_publication_compile.step);
    const binary_publication_tests = b.addRunArtifact(binary_publication_compile);
    binary_publication_tests.has_side_effects = true;
    b.step(
        "test-recursive-binary-verified-publication",
        "Run the successful binary-verifier publication mutation fleet",
    ).dependOn(support.ProofTestGuard.add(
        b,
        binary_publication_tests,
        binary_publication_test_names,
        "binary verifier publication identity guard",
    ));
    const binary_cohort_root = support.createHarnessModule(
        b,
        // Use the evidence file itself as the test root. A wrapper `test {}`
        // becomes an extra anonymous test in Zig's metadata and defeats the
        // exact-name guard on filtered audit/proof loops.
        "recursive_binary_outer_cohort_test.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    binary_cohort_root.addImport("stwo_prover_api", prover_api);
    binary_cohort_root.addImport("stwo_prover_engine", prover);
    binary_cohort_root.addImport("interop_postcard", postcard);
    const binary_cohort_test_names: []const []const u8 = &.{
        "binary outer cohort exposes the complete proof-kernel contract",
        "binary outer cohort declarations remain analyzable",
        "binary outer cohort closes all 47 domains before proving",
        "binary outer cohort proves and independently verifies all 36 rows",
        "binary outer cohort authority mismatch is capture-fail-atomic",
        "binary outer cohort rejects aliased transaction outputs before work",
    };
    const binary_cohort_compile = b.addTest(.{
        .root_module = binary_cohort_root,
        // Imported source modules intentionally retain their own unit tests.
        // Keep this evidence gate pinned to the six cohort acceptance tests
        // instead of making it depend on incidental transitive test counts.
        .filters = binary_cohort_test_names,
    });
    b.step(
        "check-recursive-binary-cohort",
        "Compile the exact 36-row binary-parent cohort without running its proof",
    ).dependOn(&binary_cohort_compile.step);
    const binary_cohort_audit_compile = b.addTest(.{
        .root_module = binary_cohort_root,
        .filters = &.{"binary outer cohort closes all 47 domains before proving"},
    });
    const binary_cohort_audit = b.addRunArtifact(binary_cohort_audit_compile);
    binary_cohort_audit.has_side_effects = true;
    const binary_cohort_audit_step = b.step(
        "audit-recursive-binary-cohort",
        "Run only the challenge-independent 47-domain binary closure audit",
    );
    binary_cohort_audit_step.dependOn(support.ProofTestGuard.add(
        b,
        binary_cohort_audit,
        &.{"binary outer cohort closes all 47 domains before proving"},
        "binary outer cohort closure-audit identity guard",
    ));
    const binary_transaction_test_names: []const []const u8 = &.{
        "binary outer cohort authority mismatch is capture-fail-atomic",
        "binary outer cohort rejects aliased transaction outputs before work",
    };
    const binary_transaction_compile = b.addTest(.{
        .root_module = binary_cohort_root,
        .filters = binary_transaction_test_names,
    });
    const binary_transaction_tests = b.addRunArtifact(binary_transaction_compile);
    binary_transaction_tests.has_side_effects = true;
    b.step(
        "test-recursive-binary-transaction-atomicity",
        "Run binary verifier output atomicity without proving",
    ).dependOn(support.ProofTestGuard.add(
        b,
        binary_transaction_tests,
        binary_transaction_test_names,
        "binary verifier transaction atomicity identity guard",
    ));
    const binary_cohort_proof_compile = b.addTest(.{
        .root_module = binary_cohort_root,
        .filters = &.{
            "binary outer cohort proves and independently verifies all 36 rows",
        },
    });
    const binary_cohort_proof = b.addRunArtifact(binary_cohort_proof_compile);
    binary_cohort_proof.has_side_effects = true;
    const binary_cohort_proof_step = b.step(
        "prove-recursive-binary-cohort",
        "Run only the exact 36-row proof and independent verification",
    );
    binary_cohort_proof_step.dependOn(support.ProofTestGuard.add(
        b,
        binary_cohort_proof,
        &.{
            "binary outer cohort proves and independently verifies all 36 rows",
        },
        "binary outer cohort full-proof identity guard",
    ));
    const binary_cohort_worker_parity_compile = b.addTest(.{
        .root_module = binary_cohort_root,
        .filters = &.{
            "binary outer cohort canonical proof identity is worker-count invariant",
        },
    });
    const binary_cohort_worker_parity = b.addRunArtifact(
        binary_cohort_worker_parity_compile,
    );
    binary_cohort_worker_parity.has_side_effects = true;
    const binary_cohort_worker_parity_step = b.step(
        "prove-recursive-binary-worker-parity",
        "Prove exact 36-row byte identity with one and four workers",
    );
    binary_cohort_worker_parity_step.dependOn(support.ProofTestGuard.add(
        b,
        binary_cohort_worker_parity,
        &.{
            "binary outer cohort canonical proof identity is worker-count invariant",
        },
        "binary outer cohort worker-parity identity guard",
    ));
    const binary_cohort_tests = b.addRunArtifact(binary_cohort_compile);
    binary_cohort_tests.has_side_effects = true;
    const binary_cohort_step = b.step(
        "test-recursive-binary-cohort",
        "Run only the exact 36-row binary-parent cohort proof",
    );
    binary_cohort_step.dependOn(support.ProofTestGuard.add(
        b,
        binary_cohort_tests,
        binary_cohort_test_names,
        "binary outer cohort proof identity guard",
    ));
    const binary_composition_root = support.createHarnessModule(
        b,
        "recursive_binary_composition_authority_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    binary_composition_root.addImport("stwo_prover_api", prover_api);
    binary_composition_root.addImport("stwo_prover_engine", prover);
    const binary_composition_tests = b.addRunArtifact(b.addTest(.{
        .root_module = binary_composition_root,
    }));
    b.step(
        "test-recursive-binary-composition",
        "Run the verifier-custody bridge into exact 36-row binary composition",
    ).dependOn(&binary_composition_tests.step);
    const binary_segment_v2_profile_root = support.createHarnessModule(
        b,
        "recursive_binary_segment_v2_composition_profile_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    binary_segment_v2_profile_root.addImport("stwo_prover_api", prover_api);
    binary_segment_v2_profile_root.addImport("stwo_prover_engine", prover);
    const binary_segment_v2_profile_compile = b.addTest(.{
        .root_module = binary_segment_v2_profile_root,
    });
    b.step(
        "check-recursive-binary-segment-v2-composition-profile",
        "Compile the exact SegmentV2-to-V3 recorder bridge and profile gate",
    ).dependOn(&binary_segment_v2_profile_compile.step);
    const binary_segment_v2_profile_tests = b.addRunArtifact(
        binary_segment_v2_profile_compile,
    );
    b.step(
        "test-recursive-binary-segment-v2-composition-profile",
        "Run the exact 39+2 SegmentV2 composition-profile mutation gate",
    ).dependOn(&binary_segment_v2_profile_tests.step);
    const temporal_child_root = support.createHarnessModule(
        b,
        "recursive_temporal_child_authority_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_child_root.addImport("stwo_prover_api", prover_api);
    temporal_child_root.addImport("stwo_prover_engine", prover);
    const temporal_child_tests = b.addRunArtifact(b.addTest(.{
        .root_module = temporal_child_root,
    }));
    b.step(
        "test-recursive-temporal-child-authority",
        "Run the fail-closed outer-proof and V2 temporal-publication custody gate",
    ).dependOn(&temporal_child_tests.step);
    const temporal_pair_perf_root = support.createHarnessModule(
        b,
        "recursive_temporal_pair_prepared_perf_evidence_test_root.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_pair_perf_root.addImport("stwo_prover_api", prover_api);
    temporal_pair_perf_root.addImport("stwo_prover_engine", prover);
    const temporal_pair_perf_compile = b.addTest(.{
        .root_module = temporal_pair_perf_root,
    });
    b.step(
        "check-recursive-temporal-pair-prepared-perf",
        "Compile the real-source temporal pair prepared-performance evidence",
    ).dependOn(&temporal_pair_perf_compile.step);
    const temporal_pair_perf_tests = b.addRunArtifact(
        temporal_pair_perf_compile,
    );
    b.step(
        "test-recursive-temporal-pair-prepared-perf",
        "Run exact old/new temporal pair work receipts and mutation parity",
    ).dependOn(&temporal_pair_perf_tests.step);
    const temporal_nonfri_root = support.createHarnessModule(
        b,
        "recursive_temporal_nonfri_source_v2.zig",
        target,
        optimize,
        core,
        cpu_backend,
        frontend,
        integration,
    );
    temporal_nonfri_root.addImport("stwo_prover_api", prover_api);
    temporal_nonfri_root.addImport("stwo_prover_engine", prover);
    const temporal_nonfri_compile = b.addTest(.{
        .root_module = temporal_nonfri_root,
    });
    b.step(
        "check-recursive-temporal-nonfri-v2",
        "Compile exact SegmentV2 transcript replay and temporal rows 10 through 17",
    ).dependOn(&temporal_nonfri_compile.step);
    const temporal_nonfri_tests = b.addRunArtifact(temporal_nonfri_compile);
    b.step(
        "test-recursive-temporal-nonfri-v2",
        "Run the focused SegmentV2 transcript replay and temporal non-FRI gate",
    ).dependOn(&temporal_nonfri_tests.step);
}
