//! Shared proof transaction for the 39-component resumed-segment outer AIR.
//!
//! Prover and verifier cohorts are reconstructed independently from one
//! authenticated authority input.  On success the verifier publishes both its
//! full proof capture and a pointer-free SegmentV2 child receipt.  Canonical
//! proof bytes survive complete outer-producer destruction; fresh decoding and
//! verification retain the native prepared leaf as an admission input (this is
//! not a key-only root verifier). All publication
//! identities, exact 47-domain closure, and fixed recursive witness are then
//! minted privately from verifier-owned values, with all three caller outputs
//! committed fail-atomically.

pub fn ForBackend(comptime Backend: type, comptime Diagnostics: type) type {
    return struct {
        const std = @import("std");
        const stwo_core = @import("stwo_core");
        const postcard = @import("interop_postcard");
        const prover_engine = @import("stwo_prover_engine");
        const prover_pcs = prover_engine.pcs;
        const canonical_identity =
            @import("canonical_proof_identity.zig");
        const verified_publication =
            @import("segment_verified_publication.zig");
        const verified_artifact =
            @import("segment_verified_artifact.zig");
        const engine_storage = @import("transaction_storage.zig");
        const engine_support = @import("segment_outer_transaction_support.zig");

        const M31 = stwo_core.fields.m31.M31;
        const QM31 = stwo_core.fields.qm31.QM31;
        const recursion = struct {
            const engine = @import("engine.zig");
            const outer_parent_child_admission = @import("outer_parent_child_admission.zig");
            const poseidon2_channel = @import("stwo_riscv_memory").recursion.poseidon2_channel;
            const protocol = @import("stwo_riscv_recursion_air").protocol.recursion.protocol;
            const verifier_tree = @import("verifier_tree.zig");
            const air = struct {
                const segment_outer_adapter_manifest_v2 = @import("air/segment_outer_adapter_manifest.zig");
                const universal_challenges = @import("stwo_riscv_air_lang").framework.universal_challenges;
                const universal_shared_provider = @import("stwo_riscv_rv32").recursion.air.universal_shared_provider;
            };
        };
        const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
        const shared_provider = recursion.air.universal_shared_provider;
        const universal = recursion.air.universal_challenges;
        const poseidon2_channel = recursion.poseidon2_channel;

        pub const Engine = recursion.engine.ProverEngineForBackend(Backend);
        pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
            recursion.engine.Hasher,
        );
        pub const VerifiedSegmentV2PublicationV1 =
            verified_publication.VerifiedSegmentV2PublicationV1;
        pub const RecursiveWitnessV1 = verified_artifact.RecursiveWitnessV1;
        const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
            recursion.engine.Hasher,
            recursion.engine.MerkleChannel,
        );
        const ProofExecutionPool = engine_storage.ProofExecutionPool;
        const TreeStorage = engine_storage.TreeStorageFor(Engine);
        pub const ProducerAllocator = prover_engine.tracked_smp_allocator.TrackedSmpAllocator;
        const moveOwnedForVerifier = recursion.verifier_tree.moveOwnedForVerifier;
        const rejectTransactionOutputAlias = engine_support.rejectTransactionOutputAlias;
        const qm31Words = engine_support.qm31Words;
        const relationDraws = engine_support.relationDraws;
        const allZeroU32 = engine_support.allZeroU32;
        const commitVerifierTree = engine_support.commitVerifierTree;

        pub const FORMAT_VERSION: u16 = 1;
        pub const COMPLETE_ROW_COUNT: usize = manifest_mod.COMPONENT_COUNT;
        pub const ENGINE_AVAILABLE = true;
        pub const CANONICAL_PROOF_SERIALIZATION_PASSES: u8 = 1;

        pub const Error = error{
            ArithmeticOverflow,
            CohortContractViolation,
            InvalidProofShape,
            PreprocessedRootMismatch,
            ProofAlreadyConsumed,
            TransactionOutputAlias,
            WorkerPoolMismatch,
        };

        /// Worker count is an execution choice only.  It cannot alter any authority,
        /// transcript input, claim, commitment, or proof byte.
        pub const ExecutionOptions = struct {
            worker_count: usize = 1,
            /// Focused lifecycle gate only; production timing excludes these decodes.
            check_serialized_artifact_rejections: bool = false,
        };

        pub const Receipt = struct {
            format_version: u16 = FORMAT_VERSION,
            proof_size_estimate: usize,
            canonical_proof_bytes: usize,
            canonical_proof_streamed_bytes: usize,
            canonical_proof_serialization_passes: u8,
            canonical_proof_retained_bytes: usize,
            canonical_proof_id: verified_publication.Digest,
            canonical_proof_sha256: verified_publication.Sha256Digest,
            canonical_proof_id_poseidon_permutations: usize,
            proof_canonicalize_ns: u64,
            producer_prepare_ns: u64,
            producer_destroy_ns: u64,
            producer_peak_bytes: usize,
            producer_live_bytes_after_destroy: usize,
            verifier_prepare_ns: u64,
            decode_ns: u64,
            artifact_rejections_ns: u64,
            stark_verify_ns: u64,
            transaction_ns: u64,
            prove_ns: u64,
            verify_ns: u64,
            publication_ns: u64,
            transcript_draws: usize,
            preprocessed_columns: u32,
            main_columns: u32,
            interaction_columns: u32,
            roster_count: u8,
            worker_count: usize,

            pub fn validate(self: Receipt) !void {
                const expected_streamed_bytes = try std.math.mul(
                    usize,
                    self.canonical_proof_bytes,
                    CANONICAL_PROOF_SERIALIZATION_PASSES,
                );
                if (self.format_version != FORMAT_VERSION or
                    self.proof_size_estimate == 0 or
                    self.canonical_proof_bytes == 0 or
                    self.canonical_proof_streamed_bytes != expected_streamed_bytes or
                    self.canonical_proof_serialization_passes !=
                        CANONICAL_PROOF_SERIALIZATION_PASSES or
                    self.canonical_proof_retained_bytes !=
                        self.canonical_proof_bytes or
                    self.producer_live_bytes_after_destroy != 0 or
                    allZeroU32(&self.canonical_proof_id) or
                    std.mem.allEqual(u8, &self.canonical_proof_sha256, 0) or
                    self.canonical_proof_id_poseidon_permutations !=
                        poseidon2_channel.bytePermutationCount(
                            self.canonical_proof_bytes,
                        ) or
                    self.roster_count != COMPLETE_ROW_COUNT or
                    self.worker_count == 0)
                {
                    return error.CohortContractViolation;
                }
            }
        };

        /// Decode exactly one canonical artifact; trailing bytes cannot become an
        /// unbound transport suffix. Cryptographic admission remains in `verify`.
        fn decodeCanonicalProof(allocator: std.mem.Allocator, bytes: []const u8) !recursion.engine.Proof {
            var stream = std.io.fixedBufferStream(bytes);
            var proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
            errdefer proof.deinit(allocator);
            if (stream.pos != bytes.len) return error.InvalidProofShape;
            return proof;
        }

        fn checkSerializedArtifactRejections(allocator: std.mem.Allocator, bytes: []const u8) !void {
            try std.testing.expectError(error.EndOfStream, decodeCanonicalProof(allocator, bytes[0 .. bytes.len - 1]));
            const extended = try allocator.alloc(u8, bytes.len + 1);
            defer allocator.free(extended);
            @memcpy(extended[0..bytes.len], bytes);
            extended[bytes.len] = 0;
            try std.testing.expectError(error.InvalidProofShape, decodeCanonicalProof(allocator, extended));
        }

        /// Real three-tree STWO transaction parameterized by a strict V2 cohort.
        /// Claims and components can only be obtained from that cohort; callers never
        /// provide either as detached inputs. Cohort.init must admit its authority
        /// inputs and validate the completed cohort before returning it. This kernel
        /// retains each new cohort locally; no caller can mutate it between construction
        /// and use. All current consumers use the concrete SegmentV2 cohort, whose
        /// constructor finishes with validateEnvelope. Public admission methods remain
        /// responsible for checking mutable inputs whenever they accept them.
        const EngineTransaction = @import("segment_outer_engine_transaction.zig").For(.{
            .std = std,
            .stwo_core = stwo_core,
            .postcard = postcard,
            .canonical_identity = canonical_identity,
            .verified_publication = verified_publication,
            .verified_artifact = verified_artifact,
            .recursion = recursion,
            .manifest_mod = manifest_mod,
            .shared_provider = shared_provider,
            .universal = universal,
            .poseidon2_channel = poseidon2_channel,
            .Engine = Engine,
            .OuterProofCapture = OuterProofCapture,
            .VerifiedSegmentV2PublicationV1 = VerifiedSegmentV2PublicationV1,
            .RecursiveWitnessV1 = RecursiveWitnessV1,
            .VerifierScheme = VerifierScheme,
            .ProofExecutionPool = ProofExecutionPool,
            .TreeStorage = TreeStorage,
            .ProducerAllocator = ProducerAllocator,
            .moveOwnedForVerifier = moveOwnedForVerifier,
            .rejectTransactionOutputAlias = rejectTransactionOutputAlias,
            .qm31Words = qm31Words,
            .relationDraws = relationDraws,
            .commitVerifierTree = commitVerifierTree,
            .CANONICAL_PROOF_SERIALIZATION_PASSES = CANONICAL_PROOF_SERIALIZATION_PASSES,
            .ExecutionOptions = ExecutionOptions,
            .Receipt = Receipt,
            .OUTER_CONFIG = OUTER_CONFIG,
            .decodeCanonicalProof = decodeCanonicalProof,
            .checkSerializedArtifactRejections = checkSerializedArtifactRejections,
            .validateManifest = validateManifest,
            .assertCohortContract = assertCohortContract,
            .Diagnostics = Diagnostics,
        });
        pub const EngineKernel = EngineTransaction.EngineKernel;

        /// Fixed from the independently versioned recursive child-admission profile.
        pub const OUTER_CONFIG = stwo_core.pcs.PcsConfig{
            .pow_bits = recursion.outer_parent_child_admission.PCS_POW_BITS,
            .fri_config = .{
                .log_blowup_factor = recursion.outer_parent_child_admission.LOG_BLOWUP_FACTOR,
                .log_last_layer_degree_bound = recursion.outer_parent_child_admission.LOG_LAST_LAYER_DEGREE_BOUND,
                .n_queries = recursion.outer_parent_child_admission.QUERY_COUNT,
                .fold_step = recursion.outer_parent_child_admission.FOLD_STEP,
            },
        };

        fn validateManifest(manifest: *const manifest_mod.Manifest) !void {
            try manifest.validate();
            if (manifest.roster_count != COMPLETE_ROW_COUNT)
                return error.CohortContractViolation;
        }

        fn assertCohortContract(comptime Cohort: type) void {
            inline for (.{
                "AuthorityInputs",
                "GeneratedInteractionsV2",
                "Components",
                "VerifierComponents",
                "PublicationAuthorityV1",
                "init",
                "deinit",
                "validate",
                "manifest",
                "mixAuthority",
                "mixPublicWireBoundary",
                "recursivePublicationInputs",
                "fillPreprocessedInto",
                "fillMainInto",
                "fillInteractionInto",
                "validateGenerated",
                "auditGlobalClosure",
                "claimVector",
                "rebuildGeneratedInteractions",
                "initComponents",
                "initVerifierComponents",
                "publicationAuthority",
            }) |name| if (!@hasDecl(Cohort, name))
                @compileError("segment V2 outer Cohort contract is incomplete: missing " ++ name);
            inline for (.{ "appendToGate", "deinit" }) |name|
                if (!@hasDecl(Cohort.Components, name))
                    @compileError(
                        "segment V2 outer Cohort.Components contract is incomplete: missing " ++
                            name,
                    );
        }

        comptime {
            @import("stwo_prover_api").assertProverEngine(Engine);
            if (COMPLETE_ROW_COUNT != 39 or manifest_mod.TREE_COUNT != 3 or
                CANONICAL_PROOF_SERIALIZATION_PASSES != 1)
                @compileError("segment V2 outer engine manifest ABI drifted");
        }

        pub fn testProtocolContract() !void {
            try std.testing.expect(ENGINE_AVAILABLE);
            try std.testing.expectEqual(@as(usize, 39), COMPLETE_ROW_COUNT);
            try std.testing.expectEqual(@as(usize, 3), manifest_mod.TREE_COUNT);

            var capture: OuterProofCapture = undefined;
            var publication: VerifiedSegmentV2PublicationV1 = undefined;
            var witness: RecursiveWitnessV1 = undefined;
            try rejectTransactionOutputAlias(&capture, &publication, &witness);

            const overlap_size = @max(
                @sizeOf(OuterProofCapture),
                @max(
                    @sizeOf(VerifiedSegmentV2PublicationV1),
                    @sizeOf(RecursiveWitnessV1),
                ),
            );
            const overlap_alignment = @max(
                @alignOf(OuterProofCapture),
                @max(
                    @alignOf(VerifiedSegmentV2PublicationV1),
                    @alignOf(RecursiveWitnessV1),
                ),
            );
            var overlap: [overlap_size]u8 align(overlap_alignment) =
                [_]u8{0xa7} ** overlap_size;
            const before = overlap;
            const alias_capture: *OuterProofCapture = @ptrCast(&overlap);
            const alias_publication: *VerifiedSegmentV2PublicationV1 =
                @ptrCast(&overlap);
            const alias_witness: *RecursiveWitnessV1 = @ptrCast(&overlap);

            try std.testing.expectError(
                error.TransactionOutputAlias,
                rejectTransactionOutputAlias(alias_capture, alias_publication, &witness),
            );
            try std.testing.expectEqualSlices(u8, &before, &overlap);
            try std.testing.expectError(
                error.TransactionOutputAlias,
                rejectTransactionOutputAlias(alias_capture, &publication, alias_witness),
            );
            try std.testing.expectEqualSlices(u8, &before, &overlap);
            try std.testing.expectError(
                error.TransactionOutputAlias,
                rejectTransactionOutputAlias(&capture, alias_publication, alias_witness),
            );
            try std.testing.expectEqualSlices(u8, &before, &overlap);
        }
    };
}
