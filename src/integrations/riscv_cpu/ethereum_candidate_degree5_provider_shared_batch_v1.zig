//! Canonical-byte boundary for the D5 provider shards of ONE omitted-provider
//! V4 incremental leaf.
//!
//! This is the shared-transcript sibling of
//! `ethereum_candidate_degree5_provider_order_batch_v1.zig`. The ordered batch
//! proves each shard under its own independent relation draw, which is fine
//! for throughput evidence and useless for a leaf: nothing binds those shards
//! to a core. Here every shard is proved through
//! `Stage101TranscriptAdapterV1`, so all 26 shards and the projected core
//! replay exactly one Fiat-Shamir order and share exactly one relation
//! context.
//!
//! Three custody properties are enforced here and nowhere else:
//!
//!   * Each shard proof is serialized to a canonical `STWD5PR1` artifact and
//!     the producer proof object is destroyed before the batch records the
//!     shard, so the cold CPU verifier receives bytes and never a
//!     producer-owned proof capability.
//!   * `validateCanonical` re-checks every shard statement against the plan
//!     descriptor, the shared relation authority and this leaf's omission
//!     digest, so a shard proved for another leaf, another shard index or
//!     another relation draw cannot enter the batch.
//!   * `verifySharedFreshParallelValidated` refuses any fresh claim that does
//!     not report `shared_core_relation_context_verified == true`. That flag
//!     is the single bit distinguishing this route from 26 unrelated proofs,
//!     and the receipt's `shared_context_verified_count` is read off the
//!     result of this check.
//!
//! Nothing here activates: `ACTIVATES_PRODUCTION_PROOF` stays false and the
//! fresh joint closure (`closeFreshClaimsV2`, on the ordinary source) remains
//! the only authority that may claim the leaf closed.

const std = @import("std");
const core = @import("stwo_core");
const core_pcs = core.pcs;
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("ethereum_degree5_provider_proof_artifact_v1.zig");
const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const prepared_mod =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
const transcript_mod =
    @import("ethereum_incremental_omitted_provider_transcript_v1.zig");

const protocol = frontend.prover_mod.ethereum_native_provider_omit_protocol_v1;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const degree5 =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;

pub const Digest = provider_authority.Digest;
pub const Adapter = transcript_mod.Stage101TranscriptAdapterV1;
pub const LeafProviderStatementV4 = transcript_mod.LeafProviderStatementV4;
pub const ProviderStatementV1 = transcript_mod.ProviderStatementV1;
pub const FreshDegree5ProviderClaimV1 = degree5.FreshDegree5ProviderClaimV1;

/// Every canonical shard artifact must fit the batch execution authority's
/// per-shard byte cap, header and metadata included. The proof budget is the
/// cap minus the fixed `STWD5PR1` framing, so `encodeAlloc` itself fails
/// closed before a single oversized artifact can reach `validateCanonical`.
pub const MAX_CANONICAL_SHARD_ARTIFACT_BYTES: usize =
    @intCast(execution_mod.MAX_CANONICAL_PROOF_BYTES_PER_SHARD);

pub const artifact_limits = artifact_mod.Limits{
    .max_artifact_bytes = MAX_CANONICAL_SHARD_ARTIFACT_BYTES,
    .max_proof_bytes = MAX_CANONICAL_SHARD_ARTIFACT_BYTES -
        artifact_mod.header_size - artifact_mod.metadata_size,
};

/// Refusals this module owns. Errors raised by the transcript source, the D5
/// prover/verifier, the artifact codec or the batch execution authority keep
/// their own names.
pub const Error = error{
    InvalidSharedDegree5ProviderBatchV1,
    InvalidSharedDegree5ProviderFreshBatchV1,
    MissingSharedDegree5ProviderProofV1,
    MissingSharedDegree5ProviderFreshClaimV1,
    MissingValidatedProviderPlanCallAuthorityV1,
    SharedDegree5ProviderBatchCallAuthorityMismatchV1,
    SharedDegree5ProviderBatchExecutionProfileMismatchV1,
    SharedDegree5ProviderBatchSharedAuthorityMismatchV1,
    SharedDegree5ProviderBatchLeafOmissionMismatchV1,
    SharedDegree5ProviderShardStatementMismatchV1,
    SharedDegree5ProviderShardArtifactMismatchV1,
    SharedDegree5ProviderShardArtifactSizeV1,
    SharedDegree5ProviderFreshClaimUnsharedContextV1,
    /// Raised by the worker fan-out, and shared verbatim with the ordered
    /// batch: an owner count the execution authority never admitted.
    InvalidDegree5ProviderBatchExecution,
};

// ---------------------------------------------------------------------------
// Encoded shard custody
// ---------------------------------------------------------------------------

/// One shard's canonical bytes plus the statement the cold verifier must
/// rebuild from them. `statement` is the leaf-bound wrapper, so a decoded
/// `STWD5PR1` statement alone can never satisfy it: the wrapper's identity
/// hashes this leaf's omission digest.
pub const EncodedSharedShardV1 = struct {
    statement: LeafProviderStatementV4,
    execution_profile_identity: Digest,
    stwd5pr1_bytes: []u8,
    sha256: [32]u8,
};

pub fn OwnedEncodedSharedBatchV1(comptime ProducerEngine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        item_allocator: std.mem.Allocator,
        shards: []EncodedSharedShardV1,
        live: []bool,
        execution_identity: Digest,
        /// The leaf this batch belongs to, captured from the producing source.
        leaf_omission_identity: Digest,
        /// The single relation draw every shard replayed.
        shared_identity: Digest,

        const Self = @This();

        /// Fail-closed readmission of the whole batch against the plan and the
        /// one shared relation authority.
        ///
        /// The plan text specifies `validateCanonical(plan, shared.identity)`;
        /// the whole `shared` value is taken instead because the per-shard
        /// checks it prescribes (`relation_context_identity`,
        /// `manifest_identity`) live on that value and cannot be derived from
        /// its identity digest. The identity itself is still checked, against
        /// the binding this batch recorded when it was produced.
        pub fn validateCanonical(
            self: *const Self,
            plan: *const provider_authority.ProviderShardPlanV1,
            shared: protocol.SharedRelationAuthorityV1(ProducerEngine),
        ) !void {
            if (self.shards.len == 0 or self.shards.len != plan.shards.len or
                self.shards.len != self.live.len)
            {
                return error.InvalidSharedDegree5ProviderBatchV1;
            }
            if (!std.mem.eql(u8, &self.shared_identity, &shared.identity) or
                !std.mem.eql(u8, &shared.plan_identity, &plan.identity))
            {
                return error.SharedDegree5ProviderBatchSharedAuthorityMismatchV1;
            }
            for (self.shards, self.live, plan.shards, 0..) |
                shard,
                live,
                descriptor,
                index,
            | {
                if (!live) return error.InvalidSharedDegree5ProviderBatchV1;
                // The wrapper's own identity must rebuild before any field of
                // it is trusted.
                try shard.statement.validate();
                if (!std.mem.eql(
                    u8,
                    &shard.statement.leaf_omission_identity,
                    &self.leaf_omission_identity,
                )) return error.SharedDegree5ProviderBatchLeafOmissionMismatchV1;
                // Size first, and by its own name: it must be decided
                // before the shard bytes are read at all.
                if (shard.stwd5pr1_bytes.len == 0 or
                    shard.stwd5pr1_bytes.len >
                        MAX_CANONICAL_SHARD_ARTIFACT_BYTES)
                    return error.SharedDegree5ProviderShardArtifactSizeV1;
                const statement = shard.statement.provider;
                if (statement.shard_index != index or
                    statement.first_call != descriptor.first_call or
                    statement.call_count != descriptor.call_count or
                    statement.log_size != descriptor.expected_log_size or
                    !std.mem.eql(
                        u8,
                        &statement.descriptor_identity,
                        &descriptor.identity,
                    ) or !std.mem.eql(
                    u8,
                    &statement.plan_identity,
                    &plan.identity,
                ) or !std.mem.eql(
                    u8,
                    &statement.call_list_commitment,
                    &plan.call_list_commitment,
                ) or !std.mem.eql(
                    u8,
                    &statement.relation_context_identity,
                    &shared.relation_context.identity,
                ) or !std.mem.eql(
                    u8,
                    &statement.manifest_identity,
                    &shared.manifest_identity,
                ) or !std.mem.eql(
                    u8,
                    &shard.execution_profile_identity,
                    &self.execution_identity,
                ) or !std.mem.eql(
                    u8,
                    &shard.sha256,
                    &sha256(shard.stwd5pr1_bytes),
                )) return error.InvalidSharedDegree5ProviderBatchV1;
            }
        }

        pub fn deinit(self: *Self) void {
            for (self.shards, self.live) |shard, live|
                if (live) self.item_allocator.free(shard.stwd5pr1_bytes);
            self.allocator.free(self.live);
            self.allocator.free(self.shards);
            self.* = undefined;
        }
    };
}

// ---------------------------------------------------------------------------
// Fresh claim custody
// ---------------------------------------------------------------------------

pub const OwnedFreshSharedBatchV1 = struct {
    allocator: std.mem.Allocator,
    claims: []FreshDegree5ProviderClaimV1,

    /// Requires the plan-shaped coverage AND the property the whole route
    /// exists for: every fresh claim was verified under the leaf's single
    /// shared relation context.
    ///
    /// Every structural check runs over the whole claim list before any
    /// `claim.validate()` does, so a batch that is mis-shaped for this leaf
    /// names its own refusal instead of collapsing into the D5 claim's
    /// blanket identity error at whichever position happens to come first.
    pub fn validateAgainst(
        self: *const OwnedFreshSharedBatchV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        execution_profile: degree5.ExecutionProfileV2,
        relation_context_identity: Digest,
    ) !void {
        if (self.claims.len == 0 or self.claims.len != plan.shards.len)
            return error.InvalidSharedDegree5ProviderFreshBatchV1;
        for (self.claims, plan.shards, 0..) |claim, descriptor, index| {
            if (!claim.shared_core_relation_context_verified)
                return error.SharedDegree5ProviderFreshClaimUnsharedContextV1;
            const native = claim.provider.native_claim;
            if (native.shard_index != index or
                descriptor.shard_index != index or
                !std.mem.eql(
                    u8,
                    &claim.relation_context_identity,
                    &relation_context_identity,
                ) or !std.mem.eql(
                u8,
                &native.relation_context_identity,
                &relation_context_identity,
            ) or !std.mem.eql(
                u8,
                &claim.execution_profile_identity,
                &execution_profile.identity,
            ) or !std.mem.eql(
                u8,
                &native.descriptor_identity,
                &descriptor.identity,
            ) or !std.mem.eql(u8, &native.plan_identity, &plan.identity))
                return error.InvalidSharedDegree5ProviderFreshBatchV1;
        }
        for (self.claims) |claim| try claim.validate();
    }

    /// Receipt input for `shared_context_verified_count`. It counts, it never
    /// asserts: `validateAgainst` is what refuses.
    pub fn sharedContextVerifiedCount(
        self: *const OwnedFreshSharedBatchV1,
    ) usize {
        var count: usize = 0;
        for (self.claims) |claim|
            if (claim.shared_core_relation_context_verified) {
                count += 1;
            };
        return count;
    }

    pub fn deinit(self: *OwnedFreshSharedBatchV1) void {
        self.allocator.free(self.claims);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Proves all shards of one omitted-provider leaf from their retained Stage-A
/// transactions, under the leaf's shared transcript, and hands back canonical
/// bytes only.
///
/// There is no non-validated sibling: G1 makes the O(1) corpus authority
/// mandatory on this route, and `SourceV1.validate` already refuses a source
/// without it.
pub fn proveSharedPreparedParallelValidated(
    comptime ProducerEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: degree5.VerifierProgramAuthorityV2,
    profile: degree5.ExecutionProfileV2,
    source: transcript_mod.SourceV1(ProducerEngine),
    validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    prepared: *prepared_mod.OwnedPreparedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedEncodedSharedBatchV1(ProducerEngine) {
    try source.validate();
    const validated = source.validated_calls orelse
        return error.MissingValidatedProviderPlanCallAuthorityV1;
    if (validated != validated_calls)
        return error.SharedDegree5ProviderBatchCallAuthorityMismatchV1;
    const plan = source.plan;
    try execution.validateAgainstPlan(plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.SharedDegree5ProviderBatchExecutionProfileMismatchV1;
    try prepared.validatePreparedValidated(
        program,
        plan,
        source.calls,
        validated_calls,
        execution,
    );

    const shards = try allocator.alloc(
        EncodedSharedShardV1,
        plan.shards.len,
    );
    errdefer allocator.free(shards);
    const live = try allocator.alloc(bool, shards.len);
    errdefer allocator.free(live);
    @memset(live, false);
    const failures = try allocator.alloc(?anyerror, shards.len);
    defer allocator.free(failures);
    @memset(failures, null);
    var owned = true;
    errdefer if (owned) for (shards, live) |shard, is_live|
        if (is_live) std.heap.smp_allocator.free(shard.stwd5pr1_bytes);

    var shared_work = ProveShared(ProducerEngine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .source = source,
        .validated_calls = validated_calls,
        .transactions = prepared.transactions,
        .shards = shards,
        .live = live,
        .failures = failures,
    };
    try runWorkers(
        execution.concurrent_owners,
        &shared_work,
        @TypeOf(shared_work).run,
    );
    for (failures) |failure| if (failure) |err| return err;
    for (live) |is_live| if (!is_live)
        return error.MissingSharedDegree5ProviderProofV1;
    try prepared.validateConsumed();

    var result = OwnedEncodedSharedBatchV1(ProducerEngine){
        .allocator = allocator,
        .item_allocator = std.heap.smp_allocator,
        .shards = shards,
        .live = live,
        .execution_identity = profile.identity,
        .leaf_omission_identity = source.leaf_omission.identity,
        .shared_identity = source.shared.identity,
    };
    try result.validateCanonical(plan, source.shared);
    owned = false;
    return result;
}

// ---------------------------------------------------------------------------
// Cold fresh verification
// ---------------------------------------------------------------------------

/// Decodes every shard artifact on the CPU verifier engine and fresh-verifies
/// it under the same shared transcript, from bytes only.
///
/// `source_cpu` is the CPU-typed route source: the caller retypes the shared
/// relation authority and rebuilds the Stage-A manifest with the Step-5
/// helpers, which are the only sanctioned way across the engine boundary.
pub fn verifySharedFreshParallelValidated(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: degree5.VerifierProgramAuthorityV2,
    profile: degree5.ExecutionProfileV2,
    source_cpu: transcript_mod.SourceV1(CpuVerifierEngine),
    validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    shards: *const OwnedEncodedSharedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedFreshSharedBatchV1 {
    comptime {
        if (!transcript_mod.transcriptTypesCompatible(
            ProducerEngine,
            CpuVerifierEngine,
        )) {
            @compileError(
                "shared D5 producer and cold verifier transcript types differ",
            );
        }
    }
    try source_cpu.validate();
    const validated = source_cpu.validated_calls orelse
        return error.MissingValidatedProviderPlanCallAuthorityV1;
    if (validated != validated_calls)
        return error.SharedDegree5ProviderBatchCallAuthorityMismatchV1;
    const plan = source_cpu.plan;
    try execution.validateAgainstPlan(plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.SharedDegree5ProviderBatchExecutionProfileMismatchV1;
    if (!std.mem.eql(
        u8,
        &shards.leaf_omission_identity,
        &source_cpu.leaf_omission.identity,
    )) return error.SharedDegree5ProviderBatchLeafOmissionMismatchV1;
    try shards.validateCanonical(plan, transcript_mod.retypeSharedRelation(
        CpuVerifierEngine,
        ProducerEngine,
        source_cpu.shared,
    ));

    const claims = try allocator.alloc(
        FreshDegree5ProviderClaimV1,
        shards.shards.len,
    );
    errdefer allocator.free(claims);
    const live = try allocator.alloc(bool, claims.len);
    defer allocator.free(live);
    @memset(live, false);
    const failures = try allocator.alloc(?anyerror, claims.len);
    defer allocator.free(failures);
    @memset(failures, null);

    var shared_work = VerifyShared(ProducerEngine, CpuVerifierEngine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .source = source_cpu,
        .validated_calls = validated_calls,
        .shards = shards,
        .claims = claims,
        .live = live,
        .failures = failures,
    };
    try runWorkers(
        execution.concurrent_owners,
        &shared_work,
        @TypeOf(shared_work).run,
    );
    for (failures) |failure| if (failure) |err| return err;
    for (live) |is_live| if (!is_live)
        return error.MissingSharedDegree5ProviderFreshClaimV1;

    var result = OwnedFreshSharedBatchV1{
        .allocator = allocator,
        .claims = claims,
    };
    try result.validateAgainst(
        plan,
        profile,
        source_cpu.shared.relation_context.identity,
    );
    return result;
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

fn ProveShared(comptime Engine: type) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: degree5.VerifierProgramAuthorityV2,
        profile: degree5.ExecutionProfileV2,
        source: transcript_mod.SourceV1(Engine),
        validated_calls: *const provider_authority
            .OwnedValidatedPlanCallAuthorityV1,
        transactions: []degree5.PreparedStageATransactionV1(Engine),
        shards: []EncodedSharedShardV1,
        live: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.shards.len) return;
                self.prove(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn prove(self: *Self, index: usize) !void {
            var output = try degree5
                .proveProviderPreparedValidatedWithTranscriptV2(
                Engine,
                Adapter,
                std.heap.smp_allocator,
                self.pcs_config,
                self.program,
                self.profile,
                self.source,
                self.validated_calls,
                @intCast(index),
                &self.transactions[index],
            );
            // The producer proof object dies with this frame, before the batch
            // is readable by anything: the cold verifier only ever sees bytes.
            defer output.proof.deinit(std.heap.smp_allocator);
            const statement = try transcript_mod.makeLeafProviderStatement(
                self.source,
                output.statement,
            );
            const bytes = try artifact_mod.encodeAlloc(
                Engine,
                std.heap.smp_allocator,
                self.pcs_config,
                output.execution_profile_identity,
                output.statement,
                output.proof,
                artifact_limits,
            );
            errdefer std.heap.smp_allocator.free(bytes);
            if (bytes.len == 0 or
                bytes.len > MAX_CANONICAL_SHARD_ARTIFACT_BYTES)
                return error.SharedDegree5ProviderShardArtifactSizeV1;
            self.shards[index] = .{
                .statement = statement,
                .execution_profile_identity = output.execution_profile_identity,
                .stwd5pr1_bytes = bytes,
                .sha256 = sha256(bytes),
            };
            self.live[index] = true;
        }
    };
}

fn VerifyShared(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: degree5.VerifierProgramAuthorityV2,
        profile: degree5.ExecutionProfileV2,
        source: transcript_mod.SourceV1(CpuVerifierEngine),
        validated_calls: *const provider_authority
            .OwnedValidatedPlanCallAuthorityV1,
        shards: *const OwnedEncodedSharedBatchV1(ProducerEngine),
        claims: []FreshDegree5ProviderClaimV1,
        live: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.claims.len) return;
                self.verify(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn verify(self: *Self, index: usize) !void {
            const shard = self.shards.shards[index];
            var decoded = try artifact_mod.decodeAlloc(
                CpuVerifierEngine,
                std.heap.smp_allocator,
                shard.stwd5pr1_bytes,
                self.pcs_config,
                artifact_limits,
            );
            var proof_moved = false;
            errdefer if (!proof_moved)
                decoded.deinit(std.heap.smp_allocator);
            if (!std.mem.eql(
                u8,
                &decoded.artifact_sha256,
                &shard.sha256,
            ) or !std.mem.eql(
                u8,
                &decoded.execution_profile_identity,
                &shard.execution_profile_identity,
            )) return error.SharedDegree5ProviderShardArtifactMismatchV1;
            // The decoded D5 statement must wrap, under this leaf's omission
            // digest, to exactly the statement the batch carries.
            const rewrapped = try LeafProviderStatementV4.canonical(
                self.source.leaf_omission.identity,
                decoded.statement,
            );
            if (!std.meta.eql(rewrapped, shard.statement))
                return error.SharedDegree5ProviderShardStatementMismatchV1;
            try shard.statement.validateAgainst(
                &self.source.leaf_omission,
                decoded.statement,
            );
            const proof = decoded.proof;
            decoded.deinitAfterProofMoved();
            proof_moved = true;
            const claim = try degree5
                .verifyProviderFreshValidatedWithTranscriptV2(
                CpuVerifierEngine,
                Adapter,
                std.heap.smp_allocator,
                self.pcs_config,
                self.program,
                self.profile,
                self.source,
                self.validated_calls,
                shard.statement.provider,
                proof,
            );
            if (!claim.shared_core_relation_context_verified)
                return error.SharedDegree5ProviderFreshClaimUnsharedContextV1;
            self.claims[index] = claim;
            self.live[index] = true;
        }
    };
}

fn runWorkers(worker_count: u16, context: anytype, comptime run: anytype) !void {
    if (worker_count == 0 or worker_count > execution_mod.MAX_ENGINE_WORKERS)
        return error.InvalidDegree5ProviderBatchExecution;
    if (worker_count == 1) {
        run(context);
        return;
    }
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{
        .allocator = std.heap.smp_allocator,
        .n_jobs = worker_count - 1,
    });
    defer pool.deinit();
    var wait_group: std.Thread.WaitGroup = .{};
    for (1..@as(usize, worker_count)) |_|
        pool.spawnWg(&wait_group, run, .{context});
    run(context);
    pool.waitAndWork(&wait_group);
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

// ---------------------------------------------------------------------------
// Comptime pins
// ---------------------------------------------------------------------------

comptime {
    if (ACTIVATES_PRODUCTION_PROOF) {
        @compileError(
            "the shared D5 provider batch cannot claim production before " ++
                "fresh joint closure activation",
        );
    }
    // A shard artifact plus its framing must never exceed the execution
    // authority's per-shard byte cap.
    if (artifact_limits.max_proof_bytes + artifact_mod.header_size +
        artifact_mod.metadata_size != MAX_CANONICAL_SHARD_ARTIFACT_BYTES)
    {
        @compileError("shared D5 shard artifact limits drifted from the cap");
    }
    // The batch stores canonical `STWD5PR1` bytes, never a proof object.
    if (@FieldType(EncodedSharedShardV1, "stwd5pr1_bytes") != []u8)
        @compileError("shared D5 shard custody must stay byte-only");
    if (@FieldType(EncodedSharedShardV1, "statement") != LeafProviderStatementV4)
        @compileError("shared D5 shard statement must stay leaf bound");
}
