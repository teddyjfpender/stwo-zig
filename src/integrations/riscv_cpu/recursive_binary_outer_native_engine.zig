const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const contract = @import("recursive_binary_outer_contract.zig");
const support = @import("recursive_binary_outer_support.zig");
const binary_composition_authority = @import("recursive_binary_composition_authority.zig");
const verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_artifact_v3 = @import("recursive_binary_v3_verified_artifact.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const segment_artifact = @import("recursive_segment_v2_verified_artifact.zig");
const temporal_child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");
const temporal_pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const fri_outer_diagnostic = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const air = recursion.air;
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
const VerifiedBinaryArtifactV3 = contract.VerifiedBinaryArtifactV3;
const BinaryProgramDescriptorV3 = contract.BinaryProgramDescriptorV3;
const TemporalVerifierSuccessBindingV1 = contract.TemporalVerifierSuccessBindingV1;
const TemporalVerifierSuccessEvidenceV1 = contract.TemporalVerifierSuccessEvidenceV1;
const TemporalVerifierSuccessEvidenceStorageV1 =
    contract.TemporalVerifierSuccessEvidenceStorageV1;
const TemporalParentArtifactViewV1 = contract.TemporalParentArtifactViewV1;
const ExecutionOptions = contract.ExecutionOptions;
const Receipt = contract.Receipt;
const OUTER_CONFIG = contract.OUTER_CONFIG;
const CANONICAL_PROOF_SERIALIZATION_PASSES = contract.CANONICAL_PROOF_SERIALIZATION_PASSES;
const RETAINED_CANONICAL_PROOF_BYTES = contract.RETAINED_CANONICAL_PROOF_BYTES;
const canonicalProofIdentity = support.canonicalProofIdentity;
const ProofExecutionPool = support.ProofExecutionPool;
const assertNativeCohortContract = support.assertNativeCohortContract;
const assertManifestContract = support.assertManifestContract;
const moveOwnedForVerifier = support.moveOwnedForVerifier;
const rejectNativeTransactionOutputAlias = support.rejectNativeTransactionOutputAlias;
const rejectNativeArtifactTransactionOutputAlias =
    support.rejectNativeArtifactTransactionOutputAlias;
const rejectV3TransactionOutputAlias = support.rejectV3TransactionOutputAlias;
const nativeDigestCanonicalNonzero = support.nativeDigestCanonicalNonzero;
const commitVerifierTreeForManifest = support.commitVerifierTreeForManifest;
const TreeStorageForManifest = support.TreeStorageForManifest;
const mintTemporalVerifierSuccessEvidence =
    contract.mintTemporalVerifierSuccessEvidence;

pub fn NativeEngineKernelForManifest(
    comptime Cohort: type,
    comptime manifest_contract: type,
) type {
    assertNativeCohortContract(Cohort);
    assertManifestContract(manifest_contract);
    return struct {
        const ManifestContract = manifest_contract;
        const TreeStorage = TreeStorageForManifest(ManifestContract);
        pub const VerifiedPublicationV1 = Cohort.VerifiedPublicationV1;
        pub const VerifiedArtifactV1 = Cohort.VerifiedArtifactV1;

        pub fn proveAndVerify(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedPublicationV1,
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
            publication_out: *VerifiedPublicationV1,
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

        pub fn proveAndVerifyWithArtifact(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedPublicationV1,
            artifact_out: *VerifiedArtifactV1,
        ) !Receipt {
            return proveAndVerifyWithExecutionAndArtifact(
                allocator,
                authority_inputs,
                .{},
                capture_out,
                publication_out,
                artifact_out,
            );
        }

        pub fn proveAndVerifyWithExecutionAndArtifact(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedPublicationV1,
            artifact_out: *VerifiedArtifactV1,
        ) !Receipt {
            try rejectNativeArtifactTransactionOutputAlias(
                VerifiedPublicationV1,
                VerifiedArtifactV1,
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
                artifact_out,
            );
        }

        fn runTransaction(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            execution: ExecutionOptions,
            capture_out: *OuterProofCapture,
            publication_out: *VerifiedPublicationV1,
            artifact_out: ?*VerifiedArtifactV1,
        ) !Receipt {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);
            try rejectNativeTransactionOutputAlias(
                VerifiedPublicationV1,
                capture_out,
                publication_out,
            );

            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.worker_count);
            defer execution_pool.deinit();
            const effective_worker_count =
                try execution_pool.visibleWorkerCount();

            var prover = try Cohort.init(allocator, authority_inputs);
            defer prover.deinit();
            try prover.validate();
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
                proof_identity,
                capture_out,
                publication_out,
                artifact_out,
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
                .pair_authority_prepare_ns = 0,
                .publication_ns = verifier_receipt.publication_ns,
                .pair_authentication_poseidon_permutations = Cohort.PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS,
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

        const NativeVerifierReceipt = struct {
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
            publication_out: *VerifiedPublicationV1,
            artifact_out: ?*VerifiedArtifactV1,
        ) !NativeVerifierReceipt {
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
            errdefer capture.deinit(allocator);

            // Complete the one independent audit/closure replay before the
            // successful-verifier capability can exist. Publication later
            // performs only sealed-identity and cohort-binding checks.
            try cohort.validateAuditedInteractions(
                &audited,
                &claims,
                &relations,
                &provider_relations,
            );

            if (comptime @import("builtin").is_test and
                @hasDecl(Cohort, "runPublicationMutationFleetForTest"))
            {
                try cohort.runPublicationMutationFleetForTest(
                    &audited,
                    &claims,
                    &relations,
                    &provider_relations,
                );
            }

            // Mint the only successful-verifier capability while the accepted
            // proof capture and independently reconstructed cohort are still
            // transaction-local. Publication consumes this borrowed capability
            // synchronously and cannot be reached from proof-shaped values.
            const evidence_binding = try cohort.verifierSuccessBinding(
                proof_identity,
                &capture,
                recursion.protocol.transcriptId(
                    channel.digestWords(),
                    channel.n_draws,
                ),
                &claims,
                &audited,
            );
            var evidence_storage: TemporalVerifierSuccessEvidenceStorageV1 =
                undefined;
            const evidence = try mintTemporalVerifierSuccessEvidence(
                &evidence_storage,
                evidence_binding,
            );

            var publication_timer = try std.time.Timer.start();
            const staged_publication =
                try cohort.publishSuccessfulVerifier(
                    evidence,
                    &claims,
                    &audited,
                    &relations,
                    &provider_relations,
                );
            const staged_artifact = if (artifact_out != null)
                try cohort.publishVerifiedArtifact(
                    evidence,
                    &staged_publication,
                )
            else
                null;
            const publication_ns = publication_timer.read();

            // Every requested output is complete. No fallible operation is
            // permitted after the first caller write.
            publication_out.* = staged_publication;
            if (artifact_out) |destination|
                destination.* = staged_artifact.?;
            capture_out.* = capture;
            return .{
                .publication_ns = publication_ns,
                .cohort_authority_sha_id = staged_publication.cohort_authority_sha_id,
                .closure_receipt_sha_id = staged_publication.closure_receipt_sha_id,
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
