//! Core proof transaction for any complete native binary-outer cohort.
//!
//! This is the publication-independent part of the recursive outer engine. It
//! constructs prover and verifier cohorts independently, commits the same
//! three manifest trees, replays the complete transcript and global closure,
//! and returns only after the resulting STARK has been independently
//! verified. A higher-level publication capability is deliberately not
//! fabricated for cohorts whose recursive child envelope is still separate.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");

const contract = @import("recursive_binary_outer_contract.zig");
const support = @import("recursive_binary_outer_support.zig");
const fri_outer_diagnostic = @import("recursive_fri_outer.zig");
const temporal_transcript_prefix =
    @import("recursive_temporal_parent_transcript_prefix_v1.zig");

const recursion = frontend.recursion;
const air = recursion.air;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const poseidon2_channel = recursion.poseidon2_channel;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const ExecutionOptions = contract.ExecutionOptions;
const Receipt = contract.Receipt;
const OUTER_CONFIG = contract.OUTER_CONFIG;
const CANONICAL_PROOF_SERIALIZATION_PASSES =
    contract.CANONICAL_PROOF_SERIALIZATION_PASSES;
const RETAINED_CANONICAL_PROOF_BYTES = contract.RETAINED_CANONICAL_PROOF_BYTES;
const canonicalProofIdentity = support.canonicalProofIdentity;
const ProofExecutionPool = support.ProofExecutionPool;
const moveOwnedForVerifier = support.moveOwnedForVerifier;
const commitVerifierTreeForManifest = support.commitVerifierTreeForManifest;
const TreeStorageForManifest = support.TreeStorageForManifest;

pub fn NativeCoreEngineKernelForManifest(
    comptime Cohort: type,
    comptime manifest_contract: type,
) type {
    assertCoreCohortContract(Cohort);
    support.assertManifestContract(manifest_contract);
    return struct {
        const ManifestContract = manifest_contract;
        const TreeStorage = TreeStorageForManifest(ManifestContract);

        pub fn proveAndVerify(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
        ) !Receipt {
            return proveAndVerifyWithExecution(
                allocator,
                authority_inputs,
                .{},
            );
        }

        pub fn proveAndVerifyWithExecution(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
        ) !Receipt {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);

            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.worker_count);
            defer execution_pool.deinit();
            const effective_worker_count =
                try execution_pool.visibleWorkerCount();

            var prover = try Cohort.init(allocator, authority_inputs);
            defer prover.deinit();
            try prover.validate();
            const manifest = prover.manifest();
            const preprocessed_columns = std.math.cast(
                u32,
                manifest.total_preprocessed_columns,
            ) orelse return error.ArithmeticOverflow;
            const main_columns = std.math.cast(
                u32,
                manifest.total_main_columns,
            ) orelse return error.ArithmeticOverflow;
            const interaction_columns = std.math.cast(
                u32,
                manifest.total_interaction_columns,
            ) orelse return error.ArithmeticOverflow;

            var prove_timer = try std.time.Timer.start();
            var proof_bundle = try prove(allocator, &prover);
            var proof_owned = true;
            defer if (proof_owned) proof_bundle.proof.deinit(allocator);
            const prove_ns = prove_timer.read();
            const proof_size = proof_bundle.proof.sizeEstimate();

            var canonical_timer = try std.time.Timer.start();
            const proof_identity = try canonicalProofIdentity(
                proof_bundle.proof,
            );
            const proof_canonicalize_ns = canonical_timer.read();

            var verifier = try Cohort.init(allocator, authority_inputs);
            defer verifier.deinit();
            try verifier.validate();
            var verify_timer = try std.time.Timer.start();
            const verifier_receipt = try verify(
                allocator,
                &verifier,
                &proof_bundle.proof,
                &proof_owned,
            );
            std.debug.assert(!proof_owned);
            const verify_ns = verify_timer.read();
            const canonical_proof_bytes: usize = proof_identity.byte_count;
            const canonical_proof_streamed_bytes = try std.math.mul(
                usize,
                canonical_proof_bytes,
                CANONICAL_PROOF_SERIALIZATION_PASSES,
            );
            return .{
                .proof_size_estimate = proof_size,
                .canonical_proof_bytes = canonical_proof_bytes,
                .canonical_proof_streamed_bytes = canonical_proof_streamed_bytes,
                .canonical_proof_serialization_passes = CANONICAL_PROOF_SERIALIZATION_PASSES,
                .canonical_proof_retained_bytes = RETAINED_CANONICAL_PROOF_BYTES,
                .canonical_proof_id = proof_identity.proof_id,
                .canonical_proof_sha256 = proof_identity.canonical_proof_sha_id,
                .canonical_proof_id_poseidon_permutations = poseidon2_channel.bytePermutationCount(canonical_proof_bytes),
                .proof_canonicalize_ns = proof_canonicalize_ns,
                .prove_ns = prove_ns,
                .verify_ns = verify_ns,
                .pair_authority_prepare_ns = 0,
                .publication_ns = 0,
                .pair_authentication_poseidon_permutations = Cohort.PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS,
                .cohort_authority_sha256 = verifier_receipt.cohort_authority_sha_id,
                .closure_receipt_sha256 = verifier_receipt.closure_receipt_sha_id,
                .transcript_draws = proof_bundle.transcript_draws,
                .preprocessed_columns = preprocessed_columns,
                .main_columns = main_columns,
                .interaction_columns = interaction_columns,
                .roster_count = manifest.roster_count,
                .worker_count = effective_worker_count,
            };
        }

        const ProofBundle = struct {
            proof: recursion.engine.Proof,
            transcript_draws: usize,
        };

        const CoreVerifierReceipt = struct {
            cohort_authority_sha_id: [32]u8,
            closure_receipt_sha_id: [32]u8,
        };

        fn prove(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
        ) !ProofBundle {
            const manifest = cohort.manifest();
            try manifest.validate();
            if (manifest.roster_count != ManifestContract.COMPONENT_COUNT)
                return error.CohortContractViolation;

            const composition_diagnostic_enabled =
                std.process.hasEnvVarConstant(
                    fri_outer_diagnostic.COMPOSITION_DIAGNOSTIC_ENV,
                );
            var scheme = try Engine.init(allocator, OUTER_CONFIG);
            scheme.setCoefficientRetentionPolicy(
                if (composition_diagnostic_enabled) .always else .never,
            );
            var scheme_moved = false;
            defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
            var channel = Engine.Channel{};

            var preprocessed = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
            );
            defer preprocessed.deinit();
            try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
            try preprocessed.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);

            var main = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            try cohort.fillMainInto(manifest, main.columns);
            try main.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);

            try manifest.mixStatementPrefix(&channel);
            try cohort.mixAuthority(&channel);
            const relations = try universal.UniversalRelations.draw(
                allocator,
                &channel,
            );
            const provider_relations =
                try shared_provider.SharedProviderRelations.init(&relations);

            var interaction = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.INTERACTION_TREE_INDEX,
            );
            defer interaction.deinit();
            const generated = try cohort.fillInteractionInto(
                manifest,
                &relations,
                &provider_relations,
                interaction.columns,
            );
            try cohort.validateGenerated(
                &generated,
                &relations,
                &provider_relations,
            );
            var claims = try cohort.claimVector(&generated);
            try claims.validate(manifest);
            const audited = try cohort.auditGlobalClosureV2(
                &generated,
                &claims,
                &relations,
                &provider_relations,
            );
            try claims.mixInteractionClaims(manifest, &channel);
            try temporal_transcript_prefix.mixWireBoundaryEvidence(
                &channel,
                audited.wire_boundary,
            );
            try interaction.commit(&scheme, &channel);

            var components = try cohort.initComponents(
                &generated,
                &relations,
                &provider_relations,
            );
            defer components.deinit();
            var gate = try ManifestContract.ProofGate.init(manifest);
            try components.appendToGate(manifest, &gate);
            try gate.sealGate(manifest);

            if (composition_diagnostic_enabled) {
                try Engine.flushPendingCommit(&scheme, allocator, &channel);
                try fri_outer_diagnostic.diagnoseCompositionComponents(
                    allocator,
                    &scheme,
                    try gate.proverSlice(),
                    try gate.verifierSlice(),
                    manifest.total_preprocessed_columns,
                );
            }

            scheme_moved = true;
            var extended = try Engine.prove(
                allocator,
                try gate.proverSlice(),
                &channel,
                scheme,
                .{},
            );
            defer extended.aux.deinit(allocator);
            const proof = extended.proof;
            extended.proof = undefined;
            return .{
                .proof = proof,
                .transcript_draws = channel.n_draws,
            };
        }

        fn verify(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            proof_in: *recursion.engine.Proof,
            proof_owned: *bool,
        ) !CoreVerifierReceipt {
            if (!proof_owned.*) return error.ProofAlreadyConsumed;
            const manifest = cohort.manifest();
            try manifest.validate();
            const commitments =
                proof_in.commitment_scheme_proof.commitments.items;
            if (commitments.len != ManifestContract.TREE_COUNT + 1)
                return error.InvalidProofShape;
            try assertPreprocessedRoot(
                allocator,
                cohort,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
            );

            var scheme = try VerifierScheme.init(allocator, OUTER_CONFIG);
            defer scheme.deinit(allocator);
            var channel = Engine.Channel{};
            try commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
                &channel,
            );
            try commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.MAIN_TREE_INDEX,
                commitments[ManifestContract.MAIN_TREE_INDEX],
                &channel,
            );
            try manifest.mixStatementPrefix(&channel);
            try cohort.mixAuthority(&channel);
            const relations = try universal.UniversalRelations.draw(
                allocator,
                &channel,
            );
            const provider_relations =
                try shared_provider.SharedProviderRelations.init(&relations);
            const generated = try cohort.rebuildGeneratedInteractions(
                &relations,
                &provider_relations,
            );
            try cohort.validateGenerated(
                &generated,
                &relations,
                &provider_relations,
            );
            var claims = try cohort.claimVector(&generated);
            try claims.validate(manifest);
            const audited = try cohort.auditGlobalClosureV2(
                &generated,
                &claims,
                &relations,
                &provider_relations,
            );
            try claims.mixInteractionClaims(manifest, &channel);
            try temporal_transcript_prefix.mixWireBoundaryEvidence(
                &channel,
                audited.wire_boundary,
            );
            try commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.INTERACTION_TREE_INDEX,
                commitments[ManifestContract.INTERACTION_TREE_INDEX],
                &channel,
            );

            var components = try cohort.initComponents(
                &generated,
                &relations,
                &provider_relations,
            );
            defer components.deinit();
            var gate = try ManifestContract.ProofGate.init(manifest);
            try components.appendToGate(manifest, &gate);
            try gate.sealGate(manifest);

            const proof = moveOwnedForVerifier(
                recursion.engine.Proof,
                proof_in,
                proof_owned,
            );
            var capture: OuterProofCapture = undefined;
            try stwo_core.verifier.verifyWithProofCapture(
                recursion.engine.Hasher,
                recursion.engine.MerkleChannel,
                allocator,
                try gate.verifierSlice(),
                &channel,
                &scheme,
                proof,
                &capture,
            );
            defer capture.deinit(allocator);
            try cohort.validateAuditedInteractions(
                &audited,
                &claims,
                &relations,
                &provider_relations,
            );
            return .{
                .cohort_authority_sha_id = cohort.authority_sha_id,
                .closure_receipt_sha_id = audited.closure.closure_id,
            };
        }

        fn assertPreprocessedRoot(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            actual: recursion.engine.Hasher.Hash,
        ) !void {
            const manifest = cohort.manifest();
            var scheme = try Engine.init(allocator, OUTER_CONFIG);
            defer Engine.deinit(&scheme, allocator);
            var channel = Engine.Channel{};
            var tree = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
            );
            defer tree.deinit();
            try cohort.fillPreprocessedInto(manifest, tree.columns);
            try tree.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
                return error.PreprocessedRootMismatch;
        }
    };
}

fn assertCoreCohortContract(comptime Cohort: type) void {
    inline for (.{
        "AuthorityInputs",
        "GeneratedInteractionsV1",
        "AuditedInteractionsV2",
        "PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS",
        "init",
        "deinit",
        "validate",
        "manifest",
        "mixAuthority",
        "fillPreprocessedInto",
        "fillMainInto",
        "fillInteractionInto",
        "validateGenerated",
        "auditGlobalClosureV2",
        "claimVector",
        "rebuildGeneratedInteractions",
        "initComponents",
        "validateAuditedInteractions",
    }) |name| if (!@hasDecl(Cohort, name))
        @compileError(
            "native core Cohort contract is incomplete: missing " ++ name,
        );
}
