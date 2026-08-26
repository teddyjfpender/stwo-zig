const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const contract = @import("recursive_binary_outer_contract.zig");
const support = @import("recursive_binary_outer_support.zig");
const fri_outer_diagnostic = @import("recursive_fri_outer.zig");
const binary_composition_authority = @import("recursive_binary_composition_authority.zig");
const verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_artifact_v3 = @import("recursive_binary_v3_verified_artifact.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const air = recursion.air;
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const poseidon2_channel = recursion.poseidon2_channel;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
const VerifiedBinaryClosurePublicationV2 = contract.VerifiedBinaryClosurePublicationV2;
const VerifiedBinaryArtifactV3 = contract.VerifiedBinaryArtifactV3;
const BinaryProgramDescriptorV3 = contract.BinaryProgramDescriptorV3;
const ExecutionOptions = contract.ExecutionOptions;
const Receipt = contract.Receipt;
const OUTER_CONFIG = contract.OUTER_CONFIG;
const COMPLETE_ROW_COUNT = contract.COMPLETE_ROW_COUNT;
const CANONICAL_PROOF_SERIALIZATION_PASSES = contract.CANONICAL_PROOF_SERIALIZATION_PASSES;
const RETAINED_CANONICAL_PROOF_BYTES = contract.RETAINED_CANONICAL_PROOF_BYTES;
const canonicalProofIdentity = support.canonicalProofIdentity;
const ProofExecutionPool = support.ProofExecutionPool;
const assertCohortContract = support.assertCohortContract;
const assertManifestContract = support.assertManifestContract;
const moveOwnedForVerifier = support.moveOwnedForVerifier;
const rejectTransactionOutputAlias = support.rejectTransactionOutputAlias;
const rejectV3TransactionOutputAlias = support.rejectV3TransactionOutputAlias;
const commitVerifierTreeForManifest = support.commitVerifierTreeForManifest;
const TreeStorageForManifest = support.TreeStorageForManifest;

pub fn proveAndVerifyCurrent(
    allocator: std.mem.Allocator,
    non_fri: anytype,
    fri: anytype,
    capture_out: *OuterProofCapture,
) !Receipt {
    _ = allocator;
    _ = capture_out;
    try non_fri.validate();
    try fri.validate();
    try fri.requireFullBundleAuthority();
    return error.BinaryFriInteractionAuthorityUnavailable;
}

/// Real Engine transaction, parameterized only by a cohort constructor. A
/// conforming cohort owns all claim derivation, domain auditing, component
/// construction, and exact row ordering. The caller supplies authority inputs,
/// never claims or component callbacks.
///
/// Required `Cohort` declarations are checked at instantiation:
/// `AuthorityInputs`, `GeneratedInteractionsV1`, `init`, `deinit`, `validate`,
/// `manifest`, `mixAuthority`, all three tree writers, `validateGenerated`,
/// `auditGlobalClosure`, `claimVector`, `rebuildGeneratedInteractions`,
/// `initComponents`, and a Components value with `appendToGate`/`deinit`.
pub fn EngineKernel(comptime Cohort: type) type {
    return EngineKernelForManifest(Cohort, manifest_mod);
}

/// Shared native proof transaction for any versioned 36-row outer manifest.
///
/// Manifest authority is a compile-time contract so tree placement, gate
/// construction, and verifier replay cannot silently fall back to frozen V1.
/// `EngineKernel` above remains the exact legacy alias; temporal V3 instantiates
/// this kernel with its own manifest contract and publication transaction.
pub fn EngineKernelForManifest(
    comptime Cohort: type,
    comptime manifest_contract: type,
) type {
    assertCohortContract(Cohort);
    assertManifestContract(manifest_contract);
    return struct {
        const Self = @This();
        const ManifestContract = manifest_contract;
        const TreeStorage = TreeStorageForManifest(ManifestContract);
        const V3Transaction = struct {
            descriptor: BinaryProgramDescriptorV3,
            artifact_out: *VerifiedBinaryArtifactV3,
        };

        pub fn proveAndVerify(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
        ) !Receipt {
            return proveAndVerifyWithExecution(
                allocator,
                authority_inputs,
                .{},
                capture_out,
                publication_out,
            );
        }

        pub fn proveAndVerifyWithExecution(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
        ) !Receipt {
            return runTransaction(
                allocator,
                authority_inputs,
                execution,
                capture_out,
                publication_out,
                null,
            );
        }

        /// Append-only V3 transaction. The descriptor selects the exact
        /// binary composition program, while all witness material is copied
        /// from the independently reconstructed verifier cohort. All three
        /// outputs remain untouched unless native verification and sidecar
        /// validation both succeed.
        pub fn proveAndVerifyV3(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            descriptor: BinaryProgramDescriptorV3,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
            artifact_out: *VerifiedBinaryArtifactV3,
        ) !Receipt {
            return proveAndVerifyWithExecutionV3(
                allocator,
                authority_inputs,
                .{},
                descriptor,
                capture_out,
                publication_out,
                artifact_out,
            );
        }

        pub fn proveAndVerifyWithExecutionV3(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
            descriptor: BinaryProgramDescriptorV3,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
            artifact_out: *VerifiedBinaryArtifactV3,
        ) !Receipt {
            try rejectV3TransactionOutputAlias(
                capture_out,
                publication_out,
                artifact_out,
            );
            return runTransaction(
                allocator,
                authority_inputs,
                execution,
                capture_out,
                publication_out,
                .{
                    .descriptor = descriptor,
                    .artifact_out = artifact_out,
                },
            );
        }

        fn runTransaction(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
            v3_transaction: ?V3Transaction,
        ) !Receipt {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);
            try rejectTransactionOutputAlias(capture_out, publication_out);

            // Retain a stable pool address for the complete transaction. Every
            // parallel-aware stage resolves this exact scoped binding through
            // the prover work-pool authority.
            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.worker_count);
            defer execution_pool.deinit();
            const effective_worker_count = try execution_pool.visibleWorkerCount();

            var prover = try Cohort.init(allocator, authority_inputs);
            defer prover.deinit();
            try prover.validate();
            if (v3_transaction) |transaction|
                try verified_artifact_v3.validateBinaryDescriptor(
                    transaction.descriptor,
                    prover.manifest(),
                );
            const preprocessed_columns = std.math.cast(
                u32,
                prover.manifest().total_preprocessed_columns,
            ) orelse return error.ArithmeticOverflow;
            const main_columns = std.math.cast(
                u32,
                prover.manifest().total_main_columns,
            ) orelse return error.ArithmeticOverflow;
            const interaction_columns = std.math.cast(
                u32,
                prover.manifest().total_interaction_columns,
            ) orelse return error.ArithmeticOverflow;

            var prove_timer = try std.time.Timer.start();
            var proof_bundle = try prove(allocator, &prover);
            var proof_owned = true;
            defer if (proof_owned) proof_bundle.proof.deinit(allocator);
            const prove_ns = prove_timer.read();
            const proof_size = proof_bundle.proof.sizeEstimate();
            var proof_canonicalize_timer = try std.time.Timer.start();
            const proof_identity = try canonicalProofIdentity(proof_bundle.proof);
            const proof_canonicalize_ns = proof_canonicalize_timer.read();

            // Independent construction from the authenticated authority inputs
            // catches retained prover mutation and preprocessing drift.
            var verifier = try Cohort.init(allocator, authority_inputs);
            defer verifier.deinit();
            try verifier.validate();
            var verify_timer = try std.time.Timer.start();
            const verifier_receipt = try verify(
                allocator,
                &verifier,
                &proof_bundle.proof,
                &proof_owned,
                proof_identity,
                capture_out,
                publication_out,
                v3_transaction,
            );
            std.debug.assert(!proof_owned);
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
                .canonical_proof_id_poseidon_permutations = poseidon2_channel.bytePermutationCount(
                    canonical_proof_bytes,
                ),
                .proof_canonicalize_ns = proof_canonicalize_ns,
                .prove_ns = prove_ns,
                .verify_ns = verify_timer.read(),
                .pair_authority_prepare_ns = verifier_receipt.pair_authority_prepare_ns,
                .publication_ns = verifier_receipt.publication_ns,
                .pair_authentication_poseidon_permutations = verified_publication
                    .PAIR_SCALAR_POSEIDON_PERMUTATIONS_PER_PUBLISH,
                .cohort_authority_sha256 = verifier_receipt.cohort_authority_sha_id,
                .closure_receipt_sha256 = verifier_receipt.closure_receipt_sha_id,
                .transcript_draws = proof_bundle.transcript_draws,
                .preprocessed_columns = preprocessed_columns,
                .main_columns = main_columns,
                .interaction_columns = interaction_columns,
                .roster_count = prover.manifest().roster_count,
                .worker_count = effective_worker_count,
            };
        }

        const ProofBundle = struct {
            proof: recursion.engine.Proof,
            transcript_draws: usize,
        };

        const VerifierPublicationReceipt = struct {
            pair_authority_prepare_ns: u64,
            publication_ns: u64,
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
            try cohort.auditGlobalClosure(
                &generated,
                &claims,
                &relations,
                &provider_relations,
            );
            try claims.mixInteractionClaims(manifest, &channel);
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
            proof_identity: verified_publication.CanonicalProofIdentityV1,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedBinaryClosurePublicationV2,
            v3_transaction: ?V3Transaction,
        ) !VerifierPublicationReceipt {
            if (!proof_owned.*) return error.ProofAlreadyConsumed;
            const manifest = cohort.manifest();
            try manifest.validate();
            const commitments = proof_in.commitment_scheme_proof.commitments.items;
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
            // Reconstruct this receipt from the independently initialized
            // verifier cohort. Passing the prover-side value across this
            // boundary would silently turn an in-process object into claim
            // authority, even though no proof byte authenticated it yet.
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
            // This exact verifier-reconstructed receipt is retained by value
            // through native proof admission and becomes the publication's
            // closure authority. No prover-side audited object crosses here.
            const audited = try cohort.auditGlobalClosureV2(
                &generated,
                &claims,
                &relations,
                &provider_relations,
            );
            const verified_closure = audited.closure;
            try claims.mixInteractionClaims(manifest, &channel);
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

            const publication_authority = try cohort.publicationAuthority();
            var pair_prepare_timer = try std.time.Timer.start();
            const prepared_pair = try verified_publication.preparePairAuthority(
                publication_authority.authority,
                publication_authority.root_pin,
            );
            const pair_authority_prepare_ns = pair_prepare_timer.read();

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

            // Capture owns verifier allocations after admission. If any
            // publication check rejects, release it locally and leave both
            // caller destinations byte-for-byte untouched.
            errdefer capture.deinit(allocator);
            var publication_timer = try std.time.Timer.start();
            const evidence = try verified_publication
                .SuccessfulVerifierEvidenceV1
                .initFromSuccessfulVerifierIdentity(
                proof_identity,
                publication_authority.authority.context.execution_statement_id,
                publication_authority.authority.context.aggregator_vk_id,
                publication_authority.cohort_authority_sha_id,
            );
            var staged_publication: VerifiedBinaryClosurePublicationV2 =
                undefined;
            try verified_publication.publishInto(
                &staged_publication,
                &evidence,
                &prepared_pair,
                publication_authority.authority,
                publication_authority.record,
                publication_authority.root_pin,
                &publication_authority.cohort_authority_sha_id,
                &verified_closure,
            );
            var staged_artifact: VerifiedBinaryArtifactV3 = undefined;
            if (v3_transaction) |transaction| {
                const statement_words = try cohort.recursiveStatementWords();
                staged_artifact = .{
                    .proof_id = staged_publication.proof_id,
                    .publication_id = staged_publication.publication_id,
                    .capture_id = verified_artifact_v3.captureIdentity(&capture),
                    .statement_id = staged_publication.statement_id,
                    .verification_key_id = staged_publication.recursive_parent_vk_id,
                    .cohort_id = staged_publication.cohort_id,
                    .air_program_id = transaction.descriptor.air_program_id,
                    .cohort_authority_sha_id = staged_publication.cohort_authority_sha_id,
                    .manifest_seal = manifest.seal,
                    .program_descriptor_identity = transaction.descriptor.identity,
                    .statement_words = statement_words.*,
                    .claimed_sums = claims.values,
                    .relation_draws = verified_artifact_v3.relationDraws(
                        &relations,
                    ),
                    .poseidon2_partials = generated.fri.claims.poseidon2_partials,
                    .claimed_sums_id = undefined,
                    .relation_draws_id = undefined,
                    .poseidon2_partials_id = undefined,
                    .artifact_id = undefined,
                };
                staged_artifact.claimed_sums_id =
                    verified_artifact_v3.claimedSumsId(&staged_artifact);
                staged_artifact.relation_draws_id =
                    verified_artifact_v3.relationDrawsId(&staged_artifact);
                staged_artifact.poseidon2_partials_id =
                    verified_artifact_v3.poseidon2PartialsId(&staged_artifact);
                staged_artifact.artifact_id =
                    verified_artifact_v3.artifactId(&staged_artifact);
                try staged_artifact.validateAgainst(
                    &capture,
                    &staged_publication,
                    manifest,
                    transaction.descriptor,
                );
            }
            const publication_ns = publication_timer.read();

            // The staged publication and optional V3 artifact have both been
            // validated. No fallible operation is permitted below this line.
            publication_out.* = staged_publication;
            if (v3_transaction) |transaction|
                transaction.artifact_out.* = staged_artifact;
            capture_out.* = capture;
            return .{
                .pair_authority_prepare_ns = pair_authority_prepare_ns,
                .publication_ns = publication_ns,
                .cohort_authority_sha_id = publication_authority.cohort_authority_sha_id,
                .closure_receipt_sha_id = verified_closure.closure_id,
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
