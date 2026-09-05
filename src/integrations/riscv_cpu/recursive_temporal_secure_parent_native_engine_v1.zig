//! Native secure temporal-parent proof transaction and cold verifier.
//!
//! This is an append-only sibling of the functional q=3 outer engine.  It
//! fixes q=193, PCS PoW 16, fold-four, and one interaction PoW 10 through the
//! sealed protocol authority.  The original engine and its byte route are not
//! imported or modified here.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const protocol_mod =
    @import("recursive_temporal_secure_parent_protocol_v1.zig");
const support = @import("recursive_binary_outer_support.zig");
const verified_publication =
    @import("recursive_binary_verified_publication.zig");
const segment_publication =
    @import("recursive_segment_v2_verified_publication.zig");
const temporal_transcript_prefix =
    @import("recursive_temporal_parent_transcript_prefix_v1.zig");
const ethereum_h1_transcript =
    @import("recursive_temporal_ethereum_poseidon_h1_transcript_v1.zig");
const secure_child_reconstruction =
    @import("recursive_temporal_secure_child_composition_v1.zig");
const secure_child_h1_capture =
    @import("recursive_temporal_secure_child_h1_capture_v1.zig");
const secure_child_parent_capture =
    @import("recursive_temporal_secure_child_parent_capture_v1.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");

const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const CANONICAL_PROOF_SERIALIZATION_PASSES: u8 = 2;
pub const RETAINED_CANONICAL_PROOF_COPIES: u8 = 1;

const AUDIT_DOMAIN =
    "stwo-zig/typed-air/secure-temporal-parent-audit/v1\x00";

/// The temporal flavor binds the same independently reconstructed public-wire
/// boundary as the current real parent.  The legacy flavor exists only so a
/// tiny, already-authenticated binary fixture can exercise the secure PCS and
/// cold-codec route before the full Ethereum h1 cohort is materialized.
pub const TranscriptFlavorV1 = enum(u8) {
    legacy_binary_test = 1,
    temporal_parent_v3 = 2,
    ethereum_poseidon_h1_v1 = 3,
    canonical_empty_wrapper_v1 = 4,
    /// Field-native public boundary. The cohort mixes NodePublicV2 before
    /// relation draws and mixes only the verifier-rebuilt QM31 boundary here;
    /// SHA custody receipts do not become recursive statement semantics.
    canonical_empty_field_v2 = 5,
    /// Field-native universal-36 fold over two independently cold-opened
    /// wrapper proofs and their verifier-rerecorded composition graphs.
    common_fold_field_v2 = 6,
    /// Genuine schema-3 role-0 wrapper over one independently cold-verified
    /// full Ethereum incremental V4 leaf.
    ethereum_incremental_leaf_wrapper_v4 = 7,
    /// Runtime-shape canonical empty. The campaign namespace and shape are
    /// committed by its distinct cohort/source/manifest authorities.
    canonical_empty_campaign_v2 = 8,
};

pub const ExecutionOptions = struct {
    worker_count: usize = 1,
};

pub const ReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    transcript_flavor: TranscriptFlavorV1,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    fri_query_count: u32,
    fri_fold_step: u32,
    canonical_proof_bytes: u32,
    canonical_proof_serialization_passes: u8,
    retained_canonical_proof_copies: u8,
    reserved: u16 = 0,
    prove_ns: u64,
    cold_verify_ns: u64,
    transcript_draws: u32,
    worker_count: u32,
    statement_identity_sha256: [32]u8,

    pub fn validate(self: *const ReceiptV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.reserved != 0 or
            self.interaction_pow_bits != 10 or self.pcs_pow_bits != 16 or
            self.fri_query_count != 193 or self.fri_fold_step != 4 or
            self.canonical_proof_bytes == 0 or
            self.canonical_proof_serialization_passes !=
                CANONICAL_PROOF_SERIALIZATION_PASSES or
            self.retained_canonical_proof_copies !=
                RETAINED_CANONICAL_PROOF_COPIES or
            self.worker_count == 0 or
            std.mem.allEqual(u8, &self.statement_identity_sha256, 0))
        {
            return error.InvalidSecureTemporalParentReceipt;
        }
    }
};

/// Non-serializable verifier result.  `capture` is assigned only after the
/// retained bytes have been decoded, canonically reserialized, and fully
/// verified with an independently initialized cohort.
pub const FreshVerificationV1 = struct {
    allocator: std.mem.Allocator,
    statement: artifact_mod.StatementV1,
    capture: OuterProofCapture,
    h1_reconstruction: ?secure_child_reconstruction.VerifiedReconstructionV1,
    h1_composition_capture: ?secure_child_h1_capture.CaptureV1,
    temporal_parent_reconstruction: ?secure_child_parent_capture.VerifiedReconstructionV1,
    temporal_parent_composition_capture: ?secure_child_parent_capture.CaptureV1,

    pub fn deinit(self: *FreshVerificationV1) void {
        if (self.temporal_parent_composition_capture) |*parent_capture|
            parent_capture.deinit();
        if (self.h1_composition_capture) |*h1_capture| h1_capture.deinit();
        self.capture.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ProveResultV1 = struct {
    artifact: artifact_mod.OwnedArtifactV1,
    fresh: FreshVerificationV1,
    receipt: ReceiptV1,

    pub fn deinit(self: *ProveResultV1) void {
        self.fresh.deinit();
        self.artifact.deinit();
        self.* = undefined;
    }
};

pub fn EngineKernelForManifest(
    comptime Cohort: type,
    comptime ManifestContract: type,
    comptime flavor: TranscriptFlavorV1,
) type {
    support.assertCohortContract(Cohort);
    assertSecureManifestContract(ManifestContract);
    if (flavor != .legacy_binary_test and
        !@hasDecl(Cohort, "validateAuditedInteractions"))
    {
        @compileError(
            "secure temporal flavor requires verifier-side audit replay",
        );
    }
    if ((flavor == .ethereum_poseidon_h1_v1 or
        flavor == .canonical_empty_wrapper_v1 or
        flavor == .canonical_empty_field_v2 or
        flavor == .canonical_empty_campaign_v2) and
        !@hasDecl(ManifestContract, "contractIdentity"))
    {
        @compileError(
            "Ethereum h1 secure flavor requires manifest contract identity",
        );
    }
    if ((flavor == .common_fold_field_v2 or
        flavor == .ethereum_incremental_leaf_wrapper_v4 or
        flavor == .canonical_empty_campaign_v2) and
        (!@hasDecl(Cohort, "parentManifestIdentity") or
            !@hasDecl(Cohort, "validateSession") or
            !@hasDecl(Cohort, "mixBoundaryReceipt")))
    {
        @compileError(
            "common-fold flavor requires dynamic manifest/session authority",
        );
    }
    return struct {
        const Self = @This();
        const TreeStorage = support.TreeStorageForManifest(ManifestContract);
        const PreprocessedCache = preprocessed_authority.CacheV1(
            recursion.engine.Hasher.Hash,
        );
        const STATIC_PREPROCESSED_CACHE_KEY_AVAILABLE =
            @hasDecl(ManifestContract, "contractIdentity") and
            @hasDecl(ManifestContract, "programIdentity") and
            @hasDecl(ManifestContract, "profileIdentity") and
            @hasDecl(ManifestContract, "paddingLayoutIdentity") and
            @hasDecl(ManifestContract, "tableLayoutIdentity");
        const DYNAMIC_PREPROCESSED_CACHE_KEY_AVAILABLE =
            @hasDecl(Cohort, "processLocalPreprocessedCacheKey");
        const PROCESS_LOCAL_PREPROCESSED_CACHE_AVAILABLE =
            STATIC_PREPROCESSED_CACHE_KEY_AVAILABLE or
            DYNAMIC_PREPROCESSED_CACHE_KEY_AVAILABLE;
        var process_local_preprocessed_cache: PreprocessedCache = .{};

        pub const VERIFIER_REPLAY_SHARING_AVAILABLE = true;
        pub const SERIALIZABLE_VERIFIER_REPLAY_AUTHORITY = false;

        pub fn preprocessedCacheSnapshot() preprocessed_authority.CounterSnapshotV1 {
            return process_local_preprocessed_cache.snapshot();
        }

        pub fn processLocalPreprocessedCacheAvailable() bool {
            return PROCESS_LOCAL_PREPROCESSED_CACHE_AVAILABLE;
        }

        /// Exact verifier-replayed algebraic state needed to rerecord a child
        /// composition circuit. This value is process-local and has no codec;
        /// it is reminted only from `FreshVerificationV1` after cold proof
        /// verification.
        pub const VerifiedReplay = struct {
            relations: universal.UniversalRelations,
            provider_relations: shared_provider.SharedProviderRelations,
            generated: Cohort.GeneratedInteractionsV1,
            claims: ManifestContract.ClaimVector,
            audited: Cohort.AuditedInteractionsV2,
            transcript_audit_sha256: [32]u8,
            /// Exact full field words drawn by the cold verifier. These are
            /// not the low-bit Merkle positions retained in `capture` and
            /// have no durable codec. Recursive row 20 may borrow them only
            /// from the live owner returned by this replay transaction.
            query_words: [193]M31,
            query_log_size: u32,
            final_transcript_digest: recursion.poseidon2_channel.Digest,
            final_transcript_draw_count: u32,
            query_words_identity_sha256: [32]u8,

            pub fn validateAgainst(self: *const VerifiedReplay, cohort: *Cohort) !void {
                try self.relations.validate();
                try self.provider_relations.validateAgainst(&self.relations);
                try cohort.validateGenerated(
                    &self.generated,
                    &self.relations,
                    &self.provider_relations,
                );
                if (!std.meta.eql(
                    self.claims,
                    try cohort.claimVector(&self.generated),
                )) return error.SecureTemporalParentStatementMismatch;
                try self.claims.validate(cohort.manifest());
                try cohort.validateAuditedInteractions(
                    &self.audited,
                    &self.claims,
                    &self.relations,
                    &self.provider_relations,
                );
                try self.validateStatementAudit(
                    self.transcript_audit_sha256,
                );
            }

            pub fn validateQueryWordsAgainst(
                self: *const VerifiedReplay,
                fresh: *const FreshVerificationV1,
            ) !void {
                if (self.query_log_size == 0 or self.query_log_size >= 31 or
                    fresh.capture.queries.raw.len != self.query_words.len or
                    !std.meta.eql(
                        fresh.statement.transcript_id,
                        recursion.protocol.transcriptId(
                            self.final_transcript_digest,
                            self.final_transcript_draw_count,
                        ),
                    ) or !std.mem.eql(
                    u8,
                    &self.query_words_identity_sha256,
                    &queryWordsIdentity(
                        fresh.statement.identity_sha256,
                        self.query_log_size,
                        self.final_transcript_digest,
                        self.final_transcript_draw_count,
                        &self.query_words,
                    ),
                )) return error.SecureTemporalParentStatementMismatch;
                const mask = (@as(u32, 1) << @intCast(
                    self.query_log_size,
                )) - 1;
                for (self.query_words, fresh.capture.queries.raw) |
                    full,
                    projected,
                | {
                    const projected_u32 = std.math.cast(u32, projected) orelse
                        return error.SecureTemporalParentStatementMismatch;
                    if ((full.toU32() & mask) != projected_u32)
                        return error.SecureTemporalParentStatementMismatch;
                }
            }

            /// Statement-bound audit seal. This is deliberately distinct
            /// from a cohort's own audited-interaction custody identity.
            pub fn computedTranscriptAuditIdentity(
                self: *const VerifiedReplay,
            ) [32]u8 {
                return auditIdentity(&self.claims, &self.audited);
            }

            pub fn validateStatementAudit(
                self: *const VerifiedReplay,
                statement_audit_sha256: [32]u8,
            ) !void {
                const expected = self.computedTranscriptAuditIdentity();
                if (!std.mem.eql(
                    u8,
                    &self.transcript_audit_sha256,
                    &expected,
                ) or !std.mem.eql(
                    u8,
                    &statement_audit_sha256,
                    &expected,
                )) return error.SecureTemporalParentStatementMismatch;
            }
        };

        /// Process-local result of one genuine cold verification and the
        /// replay state authenticated during that same verifier invocation.
        /// It has no codec and cannot cross a process boundary. The only
        /// additional transcript work is the exact PCS/FRI query-tail replay
        /// needed to retain all 193 full field words; q193 verification, both
        /// PoW checks, and every projected query check still run normally.
        pub const VerifiedColdReplayV1 = struct {
            fresh: FreshVerificationV1,
            replay: VerifiedReplay,
            cohort_ptr: usize,
            session_identity_sha256: [32]u8,
            replay_finalize_ns: u64,

            pub fn deinit(self: *VerifiedColdReplayV1) void {
                self.fresh.deinit();
                self.* = undefined;
            }

            pub fn validateBorrowed(
                self: *const VerifiedColdReplayV1,
                cohort: *Cohort,
                session: *const artifact_mod.SessionV1,
            ) !void {
                try session.validate();
                try self.fresh.statement.validateAgainstSession(session);
                try self.replay.validateQueryWordsAgainst(&self.fresh);
                try self.replay.validateStatementAudit(
                    self.fresh.statement.audit_sha256,
                );
                if (self.cohort_ptr == 0 or
                    self.cohort_ptr != @intFromPtr(cohort) or
                    !std.mem.eql(
                        u8,
                        &self.session_identity_sha256,
                        &session.identity_sha256,
                    ) or !std.mem.eql(
                    u8,
                    &self.replay.claims.seal,
                    &self.fresh.statement.claims_sha256,
                ) or !std.mem.eql(
                    u8,
                    &self.replay.audited.closure.closure_id,
                    &self.fresh.statement.closure_sha256,
                )) return error.InvalidSecureTemporalParentSharedReplay;
            }
        };

        comptime {
            if (@hasDecl(VerifiedColdReplayV1, "encode") or
                @hasDecl(VerifiedColdReplayV1, "decode"))
            {
                @compileError("verified cold replay must remain process-local");
            }
        }

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            session: artifact_mod.SessionV1,
            execution: ExecutionOptions,
        ) !ProveResultV1 {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);
            session.validate() catch |err|
                return stageFailure("engine.session", err);

            var execution_pool: support.ProofExecutionPool = .{};
            execution_pool.initInPlace(
                allocator,
                execution.worker_count,
            ) catch |err| return stageFailure("engine.pool", err);
            defer execution_pool.deinit();
            const worker_count = try execution_pool.visibleWorkerCount();

            var prover = Cohort.init(allocator, authority_inputs) catch |err|
                return stageFailure("engine.cohort-init", err);
            defer prover.deinit();
            prover.validate() catch |err|
                return stageFailure("engine.cohort-validate", err);
            validateSessionAgainstCohort(&session, &prover) catch |err|
                return stageFailure("engine.session-cohort", err);

            var prove_timer = try std.time.Timer.start();
            var bundle = prove(allocator, &prover, &session) catch |err|
                return stageFailure("engine.prove", err);
            defer bundle.proof.deinit(allocator);
            const prove_ns = prove_timer.read();

            const proof_bytes = serializeProofAlloc(
                allocator,
                bundle.proof,
            ) catch |err| return stageFailure("engine.encode", err);
            defer allocator.free(proof_bytes);

            var cold_timer = try std.time.Timer.start();
            var fresh = verifyBytes(
                allocator,
                authority_inputs,
                &session,
                bundle.interaction_pow_nonce,
                proof_bytes,
                null,
            ) catch |err| return stageFailure("engine.fresh-verify", err);
            errdefer fresh.deinit();
            const cold_verify_ns = cold_timer.read();

            var artifact = artifact_mod.OwnedArtifactV1.initCopy(
                allocator,
                fresh.statement,
                proof_bytes,
            ) catch |err| return stageFailure("engine.artifact", err);
            errdefer artifact.deinit();
            const receipt = ReceiptV1{
                .transcript_flavor = flavor,
                .interaction_pow_bits = session.protocol.interaction_pow_bits,
                .pcs_pow_bits = session.protocol.pcs_pow_bits,
                .fri_query_count = session.protocol.fri_query_count,
                .fri_fold_step = session.protocol.fri_fold_step,
                .canonical_proof_bytes = @intCast(proof_bytes.len),
                .canonical_proof_serialization_passes = CANONICAL_PROOF_SERIALIZATION_PASSES,
                .retained_canonical_proof_copies = RETAINED_CANONICAL_PROOF_COPIES,
                .prove_ns = prove_ns,
                .cold_verify_ns = cold_verify_ns,
                .transcript_draws = @intCast(bundle.transcript_draws),
                .worker_count = @intCast(worker_count),
                .statement_identity_sha256 = fresh.statement.identity_sha256,
            };
            receipt.validate() catch |err|
                return stageFailure("engine.receipt", err);
            return .{
                .artifact = artifact,
                .fresh = fresh,
                .receipt = receipt,
            };
        }

        /// Additive process-local entry point for versioned cohorts whose
        /// authenticated constructor needs more authority than the frozen
        /// `AuthorityInputs` value can carry. The caller-owned cohort is
        /// validated before proving and is also used by the independent q193
        /// proof verifier; no proof, PoW, query, PCS, or transcript check is
        /// skipped and no live capability is serialized.
        pub fn proveAndColdVerifyWithCohort(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: artifact_mod.SessionV1,
            execution: ExecutionOptions,
        ) !ProveResultV1 {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);
            session.validate() catch |err|
                return stageFailure("engine.session", err);

            var execution_pool: support.ProofExecutionPool = .{};
            execution_pool.initInPlace(
                allocator,
                execution.worker_count,
            ) catch |err| return stageFailure("engine.pool", err);
            defer execution_pool.deinit();
            const worker_count = try execution_pool.visibleWorkerCount();

            cohort.validate() catch |err|
                return stageFailure("engine.cohort-validate", err);
            validateSessionAgainstCohort(&session, cohort) catch |err|
                return stageFailure("engine.session-cohort", err);

            var prove_timer = try std.time.Timer.start();
            var bundle = prove(allocator, cohort, &session) catch |err|
                return stageFailure("engine.prove", err);
            defer bundle.proof.deinit(allocator);
            const prove_ns = prove_timer.read();

            const proof_bytes = serializeProofAlloc(
                allocator,
                bundle.proof,
            ) catch |err| return stageFailure("engine.encode", err);
            defer allocator.free(proof_bytes);

            var cold_timer = try std.time.Timer.start();
            var fresh = verifyBytesImpl(
                allocator,
                null,
                cohort,
                &session,
                bundle.interaction_pow_nonce,
                proof_bytes,
                null,
                null,
                null,
            ) catch |err| return stageFailure("engine.fresh-verify", err);
            errdefer fresh.deinit();
            const cold_verify_ns = cold_timer.read();

            var artifact = artifact_mod.OwnedArtifactV1.initCopy(
                allocator,
                fresh.statement,
                proof_bytes,
            ) catch |err| return stageFailure("engine.artifact", err);
            errdefer artifact.deinit();
            const receipt = ReceiptV1{
                .transcript_flavor = flavor,
                .interaction_pow_bits = session.protocol.interaction_pow_bits,
                .pcs_pow_bits = session.protocol.pcs_pow_bits,
                .fri_query_count = session.protocol.fri_query_count,
                .fri_fold_step = session.protocol.fri_fold_step,
                .canonical_proof_bytes = @intCast(proof_bytes.len),
                .canonical_proof_serialization_passes = CANONICAL_PROOF_SERIALIZATION_PASSES,
                .retained_canonical_proof_copies = RETAINED_CANONICAL_PROOF_COPIES,
                .prove_ns = prove_ns,
                .cold_verify_ns = cold_verify_ns,
                .transcript_draws = @intCast(bundle.transcript_draws),
                .worker_count = @intCast(worker_count),
                .statement_identity_sha256 = fresh.statement.identity_sha256,
            };
            receipt.validate() catch |err|
                return stageFailure("engine.receipt", err);
            return .{
                .artifact = artifact,
                .fresh = fresh,
                .receipt = receipt,
            };
        }

        /// Re-admits durable custody.  No decoded statement field is trusted:
        /// the verifier reconstructs an exact statement from the fresh cohort,
        /// proof capture, transcript, claims, and closure and then requires
        /// byte-for-byte equality with the retained value.
        pub fn verifyCold(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            session: *const artifact_mod.SessionV1,
            artifact: *const artifact_mod.OwnedArtifactV1,
        ) !FreshVerificationV1 {
            artifact.validateCustody() catch |err|
                return stageFailure("engine.cold-custody", err);
            artifact.statement.validateAgainstSession(session) catch |err|
                return stageFailure("engine.cold-session", err);
            return verifyBytes(
                allocator,
                authority_inputs,
                session,
                artifact.statement.interaction_pow_nonce,
                artifact.proof_bytes,
                &artifact.statement,
            ) catch |err| return stageFailure("engine.cold-verify", err);
        }

        /// Verifies one cold proof and retains the already authenticated
        /// verifier prefix in the caller-owned cohort. This is an additive
        /// process-local API: durable callers must still use `verifyCold` in
        /// every new process, and neither the replay nor its cohort pointer is
        /// serializable.
        pub fn verifyColdWithReplay(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            artifact: *const artifact_mod.OwnedArtifactV1,
        ) !VerifiedColdReplayV1 {
            artifact.validateCustody() catch |err|
                return stageFailure("engine.cold-custody", err);
            artifact.statement.validateAgainstSession(session) catch |err|
                return stageFailure("engine.cold-session", err);
            var replay: VerifiedReplay = undefined;
            var replay_finalize_ns: u64 = 0;
            var fresh = verifyBytesImpl(
                allocator,
                null,
                cohort,
                session,
                artifact.statement.interaction_pow_nonce,
                artifact.proof_bytes,
                &artifact.statement,
                &replay,
                &replay_finalize_ns,
            ) catch |err| return stageFailure("engine.cold-verify", err);
            errdefer fresh.deinit();
            const result = VerifiedColdReplayV1{
                .fresh = fresh,
                .replay = replay,
                .cohort_ptr = @intFromPtr(cohort),
                .session_identity_sha256 = session.identity_sha256,
                .replay_finalize_ns = replay_finalize_ns,
            };
            try result.validateBorrowed(cohort, session);
            return result;
        }

        /// Replays the verifier-owned public transcript through the exact
        /// interaction-claim boundary. This is intentionally separate from
        /// proof decoding: callers may retain algebraic state only after
        /// `verifyCold` has minted `fresh`, and no digest is promoted back
        /// into a claim vector or composition graph.
        pub fn reconstructVerifiedReplay(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            session: *const artifact_mod.SessionV1,
            fresh: *const FreshVerificationV1,
        ) !VerifiedReplay {
            var cohort = try Cohort.init(allocator, authority_inputs);
            defer cohort.deinit();
            return reconstructVerifiedReplayWithCohort(
                allocator,
                &cohort,
                session,
                fresh,
            );
        }

        /// Same cold replay, retaining the exactly rebuilt cohort for a
        /// verifier-owned composition-capture transaction. The caller owns
        /// `cohort`; this function never serializes or promotes its prepared
        /// rows, and the legacy entry point above preserves its API and
        /// lifetime behavior.
        pub fn reconstructVerifiedReplayWithCohort(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            fresh: *const FreshVerificationV1,
        ) !VerifiedReplay {
            try session.validate();
            try fresh.statement.validateAgainstSession(session);
            if (!std.meta.eql(
                fresh.statement.capture_id,
                segment_publication.captureIdentity(&fresh.capture),
            )) return error.SecureTemporalParentStatementMismatch;

            try cohort.validate();
            try validateSessionAgainstCohort(session, cohort);
            const manifest = cohort.manifest();
            const commitments = fresh.capture.commitments;
            if (commitments.len != ManifestContract.TREE_COUNT + 1)
                return error.InvalidSecureTemporalParentProofShape;
            try assertPreprocessedRoot(
                allocator,
                cohort,
                session,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
            );

            var scheme = try VerifierScheme.init(
                allocator,
                try session.protocol.pcsConfig(),
            );
            defer scheme.deinit(allocator);
            var transcript = Engine.Channel{};
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
                &transcript,
            );
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.MAIN_TREE_INDEX,
                commitments[ManifestContract.MAIN_TREE_INDEX],
                &transcript,
            );
            try manifest.mixStatementPrefix(&transcript);
            try cohort.mixAuthority(&transcript);
            try session.mixInto(&transcript);
            if (!transcript.verifyPowNonce(
                session.protocol.interaction_pow_bits,
                fresh.statement.interaction_pow_nonce,
            )) return error.InvalidSecureTemporalParentInteractionPow;
            transcript.mixU64(fresh.statement.interaction_pow_nonce);
            const relations = try universal.UniversalRelations.draw(
                allocator,
                &transcript,
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
            try claims.mixInteractionClaims(manifest, &transcript);
            try mixFlavorBoundary(&transcript, &audited);
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.INTERACTION_TREE_INDEX,
                commitments[ManifestContract.INTERACTION_TREE_INDEX],
                &transcript,
            );
            try validateFlavorAudit(
                cohort,
                &audited,
                &claims,
                &relations,
                &provider_relations,
            );
            return finishVerifiedReplay(
                cohort,
                session,
                fresh,
                &transcript,
                &relations,
                &provider_relations,
                &generated,
                &claims,
                &audited,
            );
        }

        fn finishVerifiedReplay(
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            fresh: *const FreshVerificationV1,
            transcript: *Engine.Channel,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const Cohort.GeneratedInteractionsV1,
            claims: *const ManifestContract.ClaimVector,
            audited: *const Cohort.AuditedInteractionsV2,
        ) !VerifiedReplay {
            if (!std.mem.eql(
                u8,
                &claims.seal,
                &fresh.statement.claims_sha256,
            ) or !std.mem.eql(
                u8,
                &auditIdentity(claims, audited),
                &fresh.statement.audit_sha256,
            ) or !std.mem.eql(
                u8,
                &audited.closure.closure_id,
                &fresh.statement.closure_sha256,
            )) return error.SecureTemporalParentStatementMismatch;
            const query_replay = try replayQueryWords(
                session,
                fresh,
                transcript,
            );
            const result = VerifiedReplay{
                .relations = relations.*,
                .provider_relations = provider_relations.*,
                .generated = generated.*,
                .claims = claims.*,
                .audited = audited.*,
                .transcript_audit_sha256 = auditIdentity(claims, audited),
                .query_words = query_replay.words,
                .query_log_size = query_replay.query_log_size,
                .final_transcript_digest = query_replay.final_digest,
                .final_transcript_draw_count = query_replay.final_draw_count,
                .query_words_identity_sha256 = undefined,
            };
            var sealed = result;
            sealed.query_words_identity_sha256 = queryWordsIdentity(
                fresh.statement.identity_sha256,
                sealed.query_log_size,
                sealed.final_transcript_digest,
                sealed.final_transcript_draw_count,
                &sealed.query_words,
            );
            try sealed.validateAgainst(cohort);
            try sealed.validateQueryWordsAgainst(fresh);
            return sealed;
        }

        const QueryReplayV1 = struct {
            words: [193]M31,
            query_log_size: u32,
            final_digest: recursion.poseidon2_channel.Digest,
            final_draw_count: u32,
        };

        /// Continues the exact already-rebuilt public transcript through the
        /// native PCS/FRI tail. It authenticates every retained challenge,
        /// checks all 193 projected positions, and binds the terminal channel
        /// state before publishing full words to the process-local replay.
        fn replayQueryWords(
            session: *const artifact_mod.SessionV1,
            fresh: *const FreshVerificationV1,
            transcript: *Engine.Channel,
        ) !QueryReplayV1 {
            const capture = &fresh.capture;
            if (session.protocol.fri_query_count != 193 or
                capture.commitments.len != ManifestContract.TREE_COUNT + 1 or
                capture.column_log_sizes.len != capture.commitments.len or
                capture.trace_paths.len != capture.commitments.len or
                capture.queries.raw.len != 193 or
                capture.deep_answers.len != 193 or
                capture.fri.layers.len == 0 or
                capture.last_layer_coefficients.len == 0)
            {
                return error.InvalidSecureTemporalParentProofShape;
            }

            const composition_randomness = transcript.drawSecureFelt();
            if (!composition_randomness.eql(capture.composition_randomness))
                return error.SecureTemporalParentStatementMismatch;
            recursion.engine.MerkleChannel.mixRoot(
                transcript,
                capture.commitments[ManifestContract.TREE_COUNT],
            );
            const oods_seed = transcript.drawSecureFelt();
            if (!oods_seed.eql(capture.oods_seed))
                return error.SecureTemporalParentStatementMismatch;
            transcript.mixFelts(capture.sampled_values);
            const deep_randomness = transcript.drawSecureFelt();
            if (!deep_randomness.eql(capture.deep_randomness))
                return error.SecureTemporalParentStatementMismatch;
            for (capture.fri.layers) |layer| {
                recursion.engine.MerkleChannel.mixRoot(
                    transcript,
                    layer.commitment,
                );
                if (!(transcript.drawSecureFelt()).eql(layer.folding_alpha))
                    return error.SecureTemporalParentStatementMismatch;
            }
            transcript.mixFelts(capture.last_layer_coefficients);
            if (!transcript.verifyPowNonce(
                session.protocol.pcs_pow_bits,
                capture.proof_of_work,
            )) return error.InvalidSecureTemporalParentProof;
            transcript.mixU64(capture.proof_of_work);

            const query_log_size = try queryLogFromCapture(capture);
            const mask = (@as(u32, 1) << @intCast(query_log_size)) - 1;
            var words: [193]M31 = undefined;
            var at: usize = 0;
            while (at < words.len) {
                const drawn = transcript.drawU32s();
                for (drawn) |word| {
                    if (at == words.len) break;
                    const projected = std.math.cast(
                        u32,
                        capture.queries.raw[at],
                    ) orelse return error.SecureTemporalParentStatementMismatch;
                    if (word >= stwo_core.fields.m31.Modulus or
                        (word & mask) != projected)
                    {
                        return error.SecureTemporalParentStatementMismatch;
                    }
                    words[at] = M31.fromCanonical(word);
                    at += 1;
                }
            }
            const final_digest = transcript.digestWords();
            const final_draw_count = transcript.n_draws;
            if (!std.meta.eql(
                fresh.statement.transcript_id,
                recursion.protocol.transcriptId(
                    final_digest,
                    final_draw_count,
                ),
            )) return error.SecureTemporalParentStatementMismatch;
            return .{
                .words = words,
                .query_log_size = query_log_size,
                .final_digest = final_digest,
                .final_draw_count = final_draw_count,
            };
        }

        fn queryLogFromCapture(capture: *const OuterProofCapture) !u32 {
            const logs = capture.column_log_sizes[
                ManifestContract.TREE_COUNT
            ];
            if (logs.len == 0)
                return error.InvalidSecureTemporalParentProofShape;
            var query_log_size: u32 = 0;
            for (logs) |log_size| {
                if (log_size == 0 or log_size >= 31)
                    return error.InvalidSecureTemporalParentProofShape;
                query_log_size = @max(query_log_size, log_size);
            }
            if (capture.trace_paths[ManifestContract.TREE_COUNT].path_depth !=
                query_log_size)
            {
                return error.InvalidSecureTemporalParentProofShape;
            }
            return query_log_size;
        }

        /// Compatibility projection for existing callers. The replay is
        /// still performed in full; only its checked claim vector is returned.
        pub fn reconstructVerifiedClaims(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            session: *const artifact_mod.SessionV1,
            fresh: *const FreshVerificationV1,
        ) !ManifestContract.ClaimVector {
            return (try reconstructVerifiedReplay(
                allocator,
                authority_inputs,
                session,
                fresh,
            )).claims;
        }

        const ProofBundle = struct {
            proof: recursion.engine.Proof,
            interaction_pow_nonce: u64,
            transcript_draws: usize,
        };

        fn prove(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
        ) !ProofBundle {
            const manifest = cohort.manifest();
            try manifest.validate();
            if (manifest.roster_count != ManifestContract.COMPONENT_COUNT)
                return error.CohortContractViolation;
            const secure_config = try session.protocol.pcsConfig();
            var scheme = try Engine.init(allocator, secure_config);
            scheme.setCoefficientRetentionPolicy(.never);
            var scheme_moved = false;
            defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
            var transcript = Engine.Channel{};

            var preprocessed = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
            );
            defer preprocessed.deinit();
            try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
            try preprocessed.commit(&scheme, &transcript);
            try Engine.flushPendingCommit(&scheme, allocator, &transcript);

            var main = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            try cohort.fillMainInto(manifest, main.columns);
            try main.commit(&scheme, &transcript);
            try Engine.flushPendingCommit(&scheme, allocator, &transcript);

            try manifest.mixStatementPrefix(&transcript);
            try cohort.mixAuthority(&transcript);
            try session.mixInto(&transcript);
            const interaction_pow_nonce = transcript.grind(
                session.protocol.interaction_pow_bits,
            );
            transcript.mixU64(interaction_pow_nonce);
            const relations = try universal.UniversalRelations.draw(
                allocator,
                &transcript,
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
            try claims.mixInteractionClaims(manifest, &transcript);
            try mixFlavorBoundary(&transcript, &audited);
            try interaction.commit(&scheme, &transcript);

            var components = try cohort.initComponents(
                &generated,
                &relations,
                &provider_relations,
            );
            defer components.deinit();
            var gate = try ManifestContract.ProofGate.init(manifest);
            try components.appendToGate(manifest, &gate);
            try gate.sealGate(manifest);

            scheme_moved = true;
            var extended = try Engine.prove(
                allocator,
                try gate.proverSlice(),
                &transcript,
                scheme,
                .{},
            );
            defer extended.aux.deinit(allocator);
            const proof = extended.proof;
            extended.proof = undefined;
            return .{
                .proof = proof,
                .interaction_pow_nonce = interaction_pow_nonce,
                .transcript_draws = transcript.n_draws,
            };
        }

        fn verifyBytes(
            allocator: std.mem.Allocator,
            authority_inputs: Cohort.AuthorityInputs,
            session: *const artifact_mod.SessionV1,
            interaction_pow_nonce: u64,
            proof_bytes: []const u8,
            expected_statement: ?*const artifact_mod.StatementV1,
        ) !FreshVerificationV1 {
            return verifyBytesImpl(
                allocator,
                authority_inputs,
                null,
                session,
                interaction_pow_nonce,
                proof_bytes,
                expected_statement,
                null,
                null,
            );
        }

        fn verifyBytesImpl(
            allocator: std.mem.Allocator,
            authority_inputs: ?Cohort.AuthorityInputs,
            supplied_cohort: ?*Cohort,
            session: *const artifact_mod.SessionV1,
            interaction_pow_nonce: u64,
            proof_bytes: []const u8,
            expected_statement: ?*const artifact_mod.StatementV1,
            replay_out: ?*VerifiedReplay,
            replay_finalize_ns_out: ?*u64,
        ) !FreshVerificationV1 {
            try session.validate();
            const proof_identity = try verified_publication
                .CanonicalProofIdentityV1.fromBytes(proof_bytes);
            var proof = try deserializeCanonicalProof(
                allocator,
                session,
                proof_bytes,
            );
            var proof_owned = true;
            defer if (proof_owned) proof.deinit(allocator);

            var owned_cohort: Cohort = undefined;
            const owns_cohort = supplied_cohort == null;
            if (owns_cohort) owned_cohort = try Cohort.init(
                allocator,
                authority_inputs orelse return error.CohortContractViolation,
            );
            defer if (owns_cohort) owned_cohort.deinit();
            const cohort = supplied_cohort orelse &owned_cohort;
            try cohort.validate();
            try validateSessionAgainstCohort(session, cohort);
            const manifest = cohort.manifest();
            const commitments = proof.commitment_scheme_proof.commitments.items;
            if (commitments.len != ManifestContract.TREE_COUNT + 1)
                return error.InvalidSecureTemporalParentProofShape;
            try assertPreprocessedRoot(
                allocator,
                cohort,
                session,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
            );

            const secure_config = try session.protocol.pcsConfig();
            var scheme = try VerifierScheme.init(allocator, secure_config);
            defer scheme.deinit(allocator);
            var transcript = Engine.Channel{};
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
                commitments[ManifestContract.PREPROCESSED_TREE_INDEX],
                &transcript,
            );
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.MAIN_TREE_INDEX,
                commitments[ManifestContract.MAIN_TREE_INDEX],
                &transcript,
            );
            try manifest.mixStatementPrefix(&transcript);
            try cohort.mixAuthority(&transcript);
            try session.mixInto(&transcript);
            if (!transcript.verifyPowNonce(
                session.protocol.interaction_pow_bits,
                interaction_pow_nonce,
            )) return error.InvalidSecureTemporalParentInteractionPow;
            transcript.mixU64(interaction_pow_nonce);
            const relations = try universal.UniversalRelations.draw(
                allocator,
                &transcript,
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
            try claims.mixInteractionClaims(manifest, &transcript);
            try mixFlavorBoundary(&transcript, &audited);
            try support.commitVerifierTreeForManifest(
                ManifestContract,
                allocator,
                &scheme,
                manifest,
                ManifestContract.INTERACTION_TREE_INDEX,
                commitments[ManifestContract.INTERACTION_TREE_INDEX],
                &transcript,
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
            // Retain the authenticated prefix immediately before the PCS
            // verifier consumes composition/FRI/query challenges. A shared
            // replay may copy and advance only this process-local channel.
            const replay_query_prefix = transcript;

            const moved = support.moveOwnedForVerifier(
                recursion.engine.Proof,
                &proof,
                &proof_owned,
            );
            var capture: OuterProofCapture = undefined;
            try stwo_core.verifier.verifyWithProofCapture(
                recursion.engine.Hasher,
                recursion.engine.MerkleChannel,
                allocator,
                try gate.verifierSlice(),
                &transcript,
                &scheme,
                moved,
                &capture,
            );
            errdefer capture.deinit(allocator);
            try validateFlavorAudit(
                cohort,
                &audited,
                &claims,
                &relations,
                &provider_relations,
            );

            const statement = try artifact_mod.statementFromVerifier(
                session,
                .{
                    .interaction_pow_nonce = interaction_pow_nonce,
                    .canonical_proof_byte_count = proof_identity.byte_count,
                    .canonical_proof_sha256 = proof_identity.canonical_proof_sha_id,
                    .proof_id = proof_identity.proof_id,
                    .capture_id = segment_publication.captureIdentity(&capture),
                    .transcript_id = recursion.protocol.transcriptId(
                        transcript.digestWords(),
                        transcript.n_draws,
                    ),
                    .claims_sha256 = claims.seal,
                    .audit_sha256 = auditIdentity(&claims, &audited),
                    .closure_sha256 = audited.closure.closure_id,
                },
            );
            if (expected_statement) |expected|
                if (!std.meta.eql(expected.*, statement))
                    return error.SecureTemporalParentStatementMismatch;
            var h1_reconstruction: ?secure_child_reconstruction.VerifiedReconstructionV1 =
                null;
            var h1_composition_capture: ?secure_child_h1_capture.CaptureV1 =
                null;
            var temporal_parent_reconstruction: ?secure_child_parent_capture.VerifiedReconstructionV1 =
                null;
            var temporal_parent_composition_capture: ?secure_child_parent_capture.CaptureV1 =
                null;
            errdefer if (temporal_parent_composition_capture) |*parent_capture|
                parent_capture.deinit();
            errdefer if (h1_composition_capture) |*h1_capture|
                h1_capture.deinit();
            if (comptime flavor == .ethereum_poseidon_h1_v1) {
                h1_reconstruction = try secure_child_reconstruction
                    .fromVerifiedH1Transaction(
                    Cohort,
                    cohort,
                    session,
                    &statement,
                    &capture,
                    &relations,
                    &provider_relations,
                    &generated,
                    &claims,
                    &audited,
                );
                h1_composition_capture = try secure_child_h1_capture.CaptureV1
                    .initForCohort(
                    Cohort,
                    allocator,
                    cohort,
                    &h1_reconstruction.?,
                    &capture,
                );
            } else if (comptime flavor == .temporal_parent_v3) {
                temporal_parent_reconstruction = try secure_child_parent_capture
                    .fromVerifiedTemporalParentTransaction(
                    Cohort,
                    cohort,
                    session,
                    &statement,
                    &capture,
                    &relations,
                    &provider_relations,
                    &generated,
                    &claims,
                    &audited,
                );
                temporal_parent_composition_capture =
                    try secure_child_parent_capture.CaptureV1.initForCohort(
                        Cohort,
                        allocator,
                        cohort,
                        &temporal_parent_reconstruction.?,
                        &capture,
                    );
            }
            const fresh = FreshVerificationV1{
                .allocator = allocator,
                .statement = statement,
                .capture = capture,
                .h1_reconstruction = h1_reconstruction,
                .h1_composition_capture = h1_composition_capture,
                .temporal_parent_reconstruction = temporal_parent_reconstruction,
                .temporal_parent_composition_capture = temporal_parent_composition_capture,
            };
            if (replay_out) |destination| {
                var replay_timer = std.time.Timer.start() catch null;
                var replay_transcript = replay_query_prefix;
                destination.* = try finishVerifiedReplay(
                    cohort,
                    session,
                    &fresh,
                    &replay_transcript,
                    &relations,
                    &provider_relations,
                    &generated,
                    &claims,
                    &audited,
                );
                if (replay_finalize_ns_out) |elapsed| elapsed.* =
                    if (replay_timer) |*timer| timer.read() else 0;
            } else if (replay_finalize_ns_out != null) {
                return error.InvalidSecureTemporalParentSharedReplay;
            }
            return fresh;
        }

        fn validateSessionAgainstCohort(
            session: *const artifact_mod.SessionV1,
            cohort: *Cohort,
        ) !void {
            try session.validate();
            try cohort.validate();
            const manifest = cohort.manifest();
            try manifest.validate();
            const statement_words = try cohort.recursiveStatementWords();
            const expected_parent_manifest =
                if (comptime flavor == .common_fold_field_v2 or
                flavor == .ethereum_incremental_leaf_wrapper_v4 or
                flavor == .canonical_empty_campaign_v2)
                    try cohort.parentManifestIdentity()
                else if (comptime flavor == .ethereum_poseidon_h1_v1 or
                flavor == .canonical_empty_wrapper_v1 or
                flavor == .canonical_empty_field_v2 or
                flavor == .canonical_empty_campaign_v2)
                    try ManifestContract.contractIdentity()
                else
                    manifest.seal;
            switch (comptime flavor) {
                .legacy_binary_test => if (session.source_kind != .testing_only)
                    return error.SecureTemporalParentSessionMismatch,
                .temporal_parent_v3 => if (session.source_kind != .fresh_temporal_parent_v3 or
                    !std.mem.eql(
                        u8,
                        &session.ingress_identity_sha256,
                        &cohort.authority_sha_id,
                    )) return error.SecureTemporalParentSessionMismatch,
                .ethereum_poseidon_h1_v1 => if (session.source_kind != .fresh_ethereum_poseidon_h1) return error.SecureTemporalParentSessionMismatch,
                .canonical_empty_wrapper_v1 => {
                    if (session.source_kind != .canonical_empty_wrapper_v1)
                        return error.SecureTemporalParentSessionMismatch;
                    try cohort.validateSession(session);
                },
                .canonical_empty_field_v2 => {
                    if (session.source_kind != .canonical_empty_wrapper_v1)
                        return error.SecureTemporalParentSessionMismatch;
                    try cohort.validateSession(session);
                },
                .canonical_empty_campaign_v2 => {
                    if (session.source_kind != .canonical_empty_campaign_v2)
                        return error.SecureTemporalParentSessionMismatch;
                    try cohort.validateSession(session);
                },
                .common_fold_field_v2 => {
                    if (session.source_kind != .common_fold_field_v2)
                        return error.SecureTemporalParentSessionMismatch;
                    try cohort.validateSession(session);
                },
                .ethereum_incremental_leaf_wrapper_v4 => {
                    if (session.source_kind !=
                        .ethereum_incremental_leaf_wrapper_v4)
                    {
                        return error.SecureTemporalParentSessionMismatch;
                    }
                    try cohort.validateSession(session);
                },
            }
            if (!std.meta.eql(
                session.parent_statement_words,
                statement_words.*,
            ) or !std.mem.eql(
                u8,
                &session.parent_outer_manifest_sha256,
                &expected_parent_manifest,
            )) return error.SecureTemporalParentSessionMismatch;
        }

        fn mixFlavorBoundary(
            transcript: *Engine.Channel,
            audited: *const Cohort.AuditedInteractionsV2,
        ) !void {
            switch (flavor) {
                .legacy_binary_test => {},
                .temporal_parent_v3 => try temporal_transcript_prefix.mixWireBoundaryEvidence(
                    transcript,
                    audited.wire_boundary,
                ),
                .ethereum_poseidon_h1_v1 => try ethereum_h1_transcript
                    .mixBoundaryReceipt(transcript, audited.h1_boundary),
                .canonical_empty_wrapper_v1 => try cohortBoundaryMix(
                    Cohort,
                    transcript,
                    audited,
                ),
                .canonical_empty_field_v2 => try Cohort.mixBoundaryReceipt(
                    transcript,
                    audited,
                ),
                .canonical_empty_campaign_v2 => try Cohort.mixBoundaryReceipt(
                    transcript,
                    audited,
                ),
                .common_fold_field_v2 => try Cohort.mixBoundaryReceipt(
                    transcript,
                    audited,
                ),
                .ethereum_incremental_leaf_wrapper_v4 => try Cohort.mixBoundaryReceipt(transcript, audited),
            }
        }

        fn validateFlavorAudit(
            cohort: *Cohort,
            audited: *const Cohort.AuditedInteractionsV2,
            claims: anytype,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            switch (flavor) {
                .legacy_binary_test => {},
                .temporal_parent_v3,
                .ethereum_poseidon_h1_v1,
                .canonical_empty_wrapper_v1,
                .canonical_empty_field_v2,
                .canonical_empty_campaign_v2,
                .common_fold_field_v2,
                .ethereum_incremental_leaf_wrapper_v4,
                => try cohort.validateAuditedInteractions(
                    audited,
                    claims,
                    relations,
                    provider_relations,
                ),
            }
        }

        fn assertPreprocessedRoot(
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            actual: recursion.engine.Hasher.Hash,
        ) !void {
            if (comptime PROCESS_LOCAL_PREPROCESSED_CACHE_AVAILABLE) {
                const key = try preprocessedCacheKey(cohort, session, actual);
                return process_local_preprocessed_cache.ensure(
                    key,
                    actual,
                    PreprocessedBuildContext{
                        .allocator = allocator,
                        .cohort = cohort,
                        .session = session,
                        .actual = actual,
                    },
                    rebuildAndValidatePreprocessedRoot,
                );
            }
            return rebuildAndValidatePreprocessedRoot(.{
                .allocator = allocator,
                .cohort = cohort,
                .session = session,
                .actual = actual,
            });
        }

        const PreprocessedBuildContext = struct {
            allocator: std.mem.Allocator,
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            actual: recursion.engine.Hasher.Hash,
        };

        fn rebuildAndValidatePreprocessedRoot(
            context: PreprocessedBuildContext,
        ) !void {
            const allocator = context.allocator;
            const cohort = context.cohort;
            const session = context.session;
            const manifest = cohort.manifest();
            var scheme = try Engine.init(
                allocator,
                try session.protocol.pcsConfig(),
            );
            defer Engine.deinit(&scheme, allocator);
            var transcript = Engine.Channel{};
            var tree = try TreeStorage.init(
                allocator,
                manifest,
                ManifestContract.PREPROCESSED_TREE_INDEX,
            );
            defer tree.deinit();
            try cohort.fillPreprocessedInto(manifest, tree.columns);
            try tree.commit(&scheme, &transcript);
            try Engine.flushPendingCommit(&scheme, allocator, &transcript);
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 1 or
                !std.meta.eql(roots.items[0], context.actual))
            {
                return error.SecureTemporalParentPreprocessedRootMismatch;
            }
        }

        fn preprocessedCacheKey(
            cohort: *Cohort,
            session: *const artifact_mod.SessionV1,
            actual: recursion.engine.Hasher.Hash,
        ) !preprocessed_authority.KeyV1 {
            if (comptime !PROCESS_LOCAL_PREPROCESSED_CACHE_AVAILABLE) {
                return error.SecureTemporalParentPreprocessedRootMismatch;
            } else if (comptime DYNAMIC_PREPROCESSED_CACHE_KEY_AVAILABLE) {
                return cohort.processLocalPreprocessedCacheKey(
                    session.protocol.identity_sha256,
                    actual,
                );
            } else {
                try session.validate();
                const manifest = cohort.manifest();
                try manifest.validate();
                return preprocessed_authority.KeyV1.init(.{
                    .circuit_identity_sha256 = try ManifestContract.contractIdentity(),
                    .program_identity_sha256 = try ManifestContract.programIdentity(),
                    .profile_identity_sha256 = try ManifestContract.profileIdentity(),
                    .pcs_identity_sha256 = session.protocol.identity_sha256,
                    .padding_identity_sha256 = try ManifestContract.paddingLayoutIdentity(),
                    .preprocessed_identity_sha256 = try preprocessed_authority.preprocessedIdentity(
                        recursion.engine.Hasher.Hash,
                        try ManifestContract.tableLayoutIdentity(),
                        manifest.seal,
                        actual,
                    ),
                    .identity_sha256 = undefined,
                });
            }
        }
    };
}

fn cohortBoundaryMix(
    comptime Cohort: type,
    transcript: *Engine.Channel,
    audited: *const Cohort.AuditedInteractionsV2,
) !void {
    try audited.validate();
    transcript.mixU32s(&.{
        0x4345_5742, // "CEWB"
        @intFromEnum(audited.wire_boundary.domain),
        @as(u32, @intCast(audited.wire_boundary.tuple_count)),
    });
    transcript.mixFelts(&.{audited.wire_boundary.claimed_sum});
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            audited.wire_boundary.tuple_provenance_sha256[index * 4 ..][0..4],
            .little,
        );
    }
    transcript.mixU32s(&words);
}

fn serializeProofAlloc(
    allocator: std.mem.Allocator,
    proof: recursion.engine.Proof,
) ![]u8 {
    var bytes: std.ArrayList(u8) = .{};
    errdefer bytes.deinit(allocator);
    try postcard.serializeProof(
        recursion.engine.Hasher,
        bytes.writer(allocator),
        proof,
    );
    if (bytes.items.len == 0 or
        bytes.items.len > artifact_mod.MAX_CANONICAL_PROOF_BYTES)
    {
        return error.SecureTemporalParentProofResourceLimitExceeded;
    }
    return bytes.toOwnedSlice(allocator);
}

fn deserializeCanonicalProof(
    allocator: std.mem.Allocator,
    session: *const artifact_mod.SessionV1,
    bytes: []const u8,
) !recursion.engine.Proof {
    if (bytes.len == 0 or bytes.len > artifact_mod.MAX_CANONICAL_PROOF_BYTES)
        return error.SecureTemporalParentProofResourceLimitExceeded;
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(
        recursion.engine.Hasher,
        allocator,
        stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (stream.pos != bytes.len or !std.meta.eql(
        proof.commitment_scheme_proof.config,
        try session.protocol.pcsConfig(),
    )) return error.InvalidSecureTemporalParentProofEncoding;

    const canonical = try serializeProofAlloc(allocator, proof);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalSecureTemporalParentProof;
    return proof;
}

/// The secure engine is roster-generic: the historical binary cohort has 36
/// placements while the full-Ethereum H1 wrapper has 12. Tree geometry and
/// proof-gate ordering remain manifest-owned in both cases. The functional
/// q=3 engine continues using its unchanged exact-36 assertion.
fn assertSecureManifestContract(comptime ManifestContract: type) void {
    inline for (.{
        "Manifest",
        "Placement",
        "Geometry",
        "ProofGate",
        "TREE_COUNT",
        "PREPROCESSED_TREE_INDEX",
        "MAIN_TREE_INDEX",
        "INTERACTION_TREE_INDEX",
        "COMPONENT_COUNT",
    }) |name| if (!@hasDecl(ManifestContract, name))
        @compileError(
            "secure parent manifest contract is incomplete: missing " ++ name,
        );
    if (ManifestContract.TREE_COUNT != 3 or
        ManifestContract.COMPONENT_COUNT == 0 or
        ManifestContract.COMPONENT_COUNT > 64 or
        ManifestContract.PREPROCESSED_TREE_INDEX ==
            ManifestContract.MAIN_TREE_INDEX or
        ManifestContract.PREPROCESSED_TREE_INDEX ==
            ManifestContract.INTERACTION_TREE_INDEX or
        ManifestContract.MAIN_TREE_INDEX ==
            ManifestContract.INTERACTION_TREE_INDEX)
    {
        @compileError("secure parent manifest tree contract drifted");
    }
}

fn auditIdentity(claims: anytype, audited: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUDIT_DOMAIN);
    hash.update(&claims.seal);
    hash.update(&audited.closure.closure_id);
    hashInt(&hash, u64, audited.wire_boundary.tuple_count);
    hashQm31(&hash, audited.wire_boundary.claimed_sum);
    hashInt(&hash, u64, audited.verifier_input_boundary.tuple_count);
    hashQm31(&hash, audited.verifier_input_boundary.claimed_sum);
    return hash.finalResult();
}

fn queryWordsIdentity(
    statement_identity_sha256: [32]u8,
    query_log_size: u32,
    final_digest: recursion.poseidon2_channel.Digest,
    final_draw_count: u32,
    words: *const [193]M31,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(
        "stwo-zig/typed-air/secure-query-word-replay/v1\x00",
    );
    hash.update(&statement_identity_sha256);
    hashInt(&hash, u32, query_log_size);
    for (final_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, final_draw_count);
    for (words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashQm31(hash: *Sha256, value: stwo_core.fields.qm31.QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

/// Test-only causal marker. The original error is returned unchanged and the
/// branch is eliminated from non-test products.
fn stageFailure(comptime stage: []const u8, err: anyerror) anyerror {
    if (builtin.is_test) std.debug.print(
        "SECURE_Q193_STAGE={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

comptime {
    @setEvalBranchQuota(100_000);
    const secure = protocol_mod.AuthorityV1.secureParent();
    if (PRODUCTION_ACTIVATION or CANONICAL_PROOF_SERIALIZATION_PASSES != 2 or
        RETAINED_CANONICAL_PROOF_COPIES != 1 or
        @intFromEnum(TranscriptFlavorV1.canonical_empty_campaign_v2) != 8 or
        secure.interaction_pow_bits != 10 or secure.pcs_pow_bits != 16 or
        secure.fri_query_count != 193 or secure.fri_fold_step != 4)
    {
        @compileError("secure temporal-parent native engine profile drifted");
    }
}
