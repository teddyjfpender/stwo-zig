//! Focused gates for the shared-transcript D5 provider batch.
//!
//! What is reachable here, and what is not:
//!
//!   * `validateCanonical` is fully reachable. It never opens a proof, so a
//!     batch of synthetic shard records exercises the whole accept path and
//!     the whole rejection matrix -- one mutation per bound field.
//!   * The leaf statement wrapper is fully reachable: it is a pure digest.
//!   * The byte cap is reachable through the limits arithmetic and through an
//!     oversized (reserved, never touched) shard slice.
//!   * `OwnedFreshSharedBatchV1.validateAgainst` is reachable only on its
//!     *rejection* side. Its accept path needs a fresh claim whose identity
//!     rebuilds, and the D5 fresh-claim identity function is not exported to
//!     `riscv_cpu`; a genuine claim only exists once a shard is really proved
//!     and verified, which is
//!     `test-riscv-ethereum-incremental-omitted-leaf-proof-v1` (Step 10).
//!     The structural checks therefore run before `claim.validate()` so each
//!     names its own refusal, and this file pins those refusals.
//!   * `proveSharedPreparedParallelValidated` and
//!     `verifySharedFreshParallelValidated` are bound to the concrete q193 CPU
//!     engine in a comptime block, so their bodies (and the D5 prover /
//!     verifier / artifact codec calls inside them) are semantically analysed
//!     at this cheap root. Nothing runs them: that also needs a real leaf.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const shared_batch =
    @import("ethereum_candidate_degree5_provider_shared_batch_v1.zig");
const artifact_mod = @import("ethereum_degree5_provider_proof_artifact_v1.zig");
const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const prepared_mod =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
const transcript_mod =
    @import("ethereum_incremental_omitted_provider_transcript_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const protocol = frontend.prover_mod.ethereum_native_provider_omit_protocol_v1;
const route =
    frontend.prover_mod.guest_precompile.incremental_ethereum_omit_protocol_v4;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider_order = frontend.testing.narrow_memory_provider_order_component;
const degree5 =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Shared = protocol.SharedRelationAuthorityV1(Engine);
const Batch = shared_batch.OwnedEncodedSharedBatchV1(Engine);
const LeafOmission = transcript_mod.LeafOmissionAuthorityV4;
const LeafStatement = shared_batch.LeafProviderStatementV4;

const call_count = 33;
const test_shard_log = 4;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn digest(marker: u8) provider_authority.Digest {
    return [_]u8{marker} ** 32;
}

fn authorityId(marker: u32) route.AuthorityId {
    return [_]u32{marker} ** 8;
}

fn sha256(bytes: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return value;
}

fn rootValue(seed: u32) Engine.Hasher.Hash {
    var value: Engine.Hasher.Hash = undefined;
    const words = std.mem.bytesAsSlice(u32, std.mem.asBytes(&value));
    var state: u32 = seed *% 0x9e37_79b9 +% 1;
    for (words) |*word| {
        state = state *% 1_664_525 +% 1_013_904_223;
        word.* = state & 0x3fff_ffff;
    }
    return value;
}

fn callsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    return calls;
}

/// Same shape as the route's pins, with a test shard log so the fixture plans
/// three shards instead of one 2^18 shard.
fn request(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = provider_authority.main_column_count,
        .min_shard_log_size = test_shard_log,
        .max_shard_log_size = test_shard_log,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

/// Plan, the one shared relation authority, this leaf's omission digest, and
/// one canonical encoded shard per plan descriptor. No proof exists anywhere
/// in here: `validateCanonical` never opens the bytes it guards.
const BatchFixture = struct {
    allocator: std.mem.Allocator,
    calls: []poseidon2_air.Call,
    plan: provider_authority.ProviderShardPlanV1,
    shared: Shared,
    leaf_omission: LeafOmission,
    batch: Batch,

    const execution_identity = digest(0x71);
    const manifest_identity = digest(0xb1);

    fn init(self: *BatchFixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.calls = try callsFixture(allocator, call_count);
        errdefer allocator.free(self.calls);
        self.plan = try provider_authority.ProviderShardPlanV1.create(
            allocator,
            digest(0xa7),
            self.calls,
            request(self.calls.len),
        );
        errdefer self.plan.deinit(allocator);
        const relation_context = try provider_authority
            .PoseidonRelationContextV1.canonical(
            self.plan.session,
            QM31.fromU32Unchecked(11, 12, 13, 14),
            QM31.fromU32Unchecked(21, 22, 23, 24),
        );
        self.shared = .{
            .format = 1,
            .plan_identity = self.plan.identity,
            .manifest_identity = manifest_identity,
            .projection_identity = digest(0xc2),
            .tree0_root = rootValue(0x5100),
            .tree1_root = rootValue(0xa200),
            .interaction_pow_bits = 16,
            .interaction_pow = 4242,
            .relation_context = relation_context,
            .identity = digest(0xd3),
        };
        self.leaf_omission = try LeafOmission.canonical(
            digest(0x31),
            digest(0x42),
            self.shared.identity,
            authorityId(0x64),
        );
        self.batch = try encodedBatch(
            allocator,
            &self.plan,
            self.shared,
            self.leaf_omission.identity,
        );
    }

    fn deinit(self: *BatchFixture) void {
        self.batch.deinit();
        self.plan.deinit(self.allocator);
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    fn validate(self: *const BatchFixture) !void {
        try self.batch.validateCanonical(&self.plan, self.shared);
    }

    /// Rewraps shard `index`'s (possibly mutated) D5 statement so the wrapper
    /// identity stays canonical: a field mutation must be caught by the
    /// batch's own checks, not incidentally by a stale wrapper digest.
    fn rewrap(self: *BatchFixture, index: usize, leaf_identity: [32]u8) !void {
        self.batch.shards[index].statement = try LeafStatement.canonical(
            leaf_identity,
            self.batch.shards[index].statement.provider,
        );
    }
};

fn providerStatement(
    plan: *const provider_authority.ProviderShardPlanV1,
    shared: Shared,
    index: usize,
) !shared_batch.ProviderStatementV1 {
    const descriptor = plan.shards[index];
    var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
    for (&sums, 0..) |*value, ordinal|
        value.* = QM31.fromU32Unchecked(
            @intCast(index * 7 + ordinal + 1),
            0,
            0,
            0,
        );
    return .{
        .format = degree5.format_version,
        .air_program_identity = digest(0xe5),
        .plan_identity = plan.identity,
        .manifest_identity = shared.manifest_identity,
        .stage_a_identity = digest(@intCast(0x10 + index)),
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = shared.relation_context.identity,
        .call_list_commitment = plan.call_list_commitment,
        .shard_index = @intCast(index),
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .geometry = try degree5.ProviderTree2GeometryV1.canonical(
            descriptor.expected_log_size,
        ),
        .claims = .{ .sums = sums },
        .ordered_call_claim = .{
            .format = provider_order.format_version,
            .first_call = descriptor.first_call,
            .call_count = descriptor.call_count,
            .terminal = QM31.fromU32Unchecked(7, 0, 0, 0),
        },
        // The wrapper only requires a non-zero D5 statement identity; the
        // cold verifier is what rebuilds it from the decoded artifact.
        .identity = digest(@intCast(0x80 + index)),
    };
}

fn encodedBatch(
    allocator: std.mem.Allocator,
    plan: *const provider_authority.ProviderShardPlanV1,
    shared: Shared,
    leaf_omission_identity: [32]u8,
) !Batch {
    const shards = try allocator.alloc(
        shared_batch.EncodedSharedShardV1,
        plan.shards.len,
    );
    errdefer allocator.free(shards);
    const live = try allocator.alloc(bool, shards.len);
    errdefer allocator.free(live);
    @memset(live, false);
    for (shards, live, 0..) |*shard, *is_live, index| {
        const bytes = try std.fmt.allocPrint(
            allocator,
            "STWD5PR1-fixture-shard-{d}",
            .{index},
        );
        errdefer allocator.free(bytes);
        shard.* = .{
            .statement = try LeafStatement.canonical(
                leaf_omission_identity,
                try providerStatement(plan, shared, index),
            ),
            .execution_profile_identity = BatchFixture.execution_identity,
            .stwd5pr1_bytes = bytes,
            .sha256 = sha256(bytes),
        };
        is_live.* = true;
    }
    return .{
        .allocator = allocator,
        .item_allocator = allocator,
        .shards = shards,
        .live = live,
        .execution_identity = BatchFixture.execution_identity,
        .leaf_omission_identity = leaf_omission_identity,
        .shared_identity = shared.identity,
    };
}

// ---------------------------------------------------------------------------
// 1. Canonical shard admission
// ---------------------------------------------------------------------------

test "shared D5 provider batch: a canonical batch admits its own shards" {
    var fixture: BatchFixture = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try fixture.validate();
    // The fixture is the route's real shape: several shards, one plan, one
    // relation context, one leaf.
    try std.testing.expect(fixture.plan.shards.len >= 2);
    try std.testing.expectEqual(
        fixture.plan.shards.len,
        fixture.batch.shards.len,
    );
    for (fixture.batch.shards, 0..) |shard, index| {
        try std.testing.expectEqual(
            @as(u32, @intCast(index)),
            shard.statement.provider.shard_index,
        );
        try std.testing.expectEqualSlices(
            u8,
            &fixture.leaf_omission.identity,
            &shard.statement.leaf_omission_identity,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Canonical rejection matrix
// ---------------------------------------------------------------------------

test "shared D5 provider batch: canonical validation rejects every mutated field" {
    const allocator = std.testing.allocator;

    // Shard index: a shard proved at another position in the same plan.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[1].statement.provider.shard_index = 0;
        try fixture.rewrap(1, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Descriptor identity: another plan's shard descriptor.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.descriptor_identity =
            digest(0x99);
        try fixture.rewrap(0, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Relation context: the whole point of the route. A shard drawn under its
    // own independent context cannot enter this batch.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[2].statement.provider.relation_context_identity =
            digest(0x99);
        try fixture.rewrap(2, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Stage-A manifest identity.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.manifest_identity =
            digest(0x99);
        try fixture.rewrap(0, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Plan identity and call-list commitment.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[1].statement.provider.plan_identity = digest(0x99);
        try fixture.rewrap(1, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[1].statement.provider.call_list_commitment =
            digest(0x99);
        try fixture.rewrap(1, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Call window and log size against the plan descriptor.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.first_call += 1;
        try fixture.rewrap(0, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.call_count -= 1;
        try fixture.rewrap(0, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.log_size += 1;
        try fixture.rewrap(0, fixture.leaf_omission.identity);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Execution profile identity.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[2].execution_profile_identity = digest(0x99);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // Recorded artifact digest: bytes and their sha must agree.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[1].sha256 = digest(0x99);
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
    }

    // A missing or dead shard is never a pass.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.live[2] = false;
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
        fixture.batch.live[2] = true;
        const held = fixture.batch.shards;
        fixture.batch.shards = held[0 .. held.len - 1];
        fixture.batch.live = fixture.batch.live[0 .. held.len - 1];
        try std.testing.expectError(
            error.InvalidSharedDegree5ProviderBatchV1,
            fixture.validate(),
        );
        fixture.batch.shards = held;
        fixture.batch.live = fixture.batch.live.ptr[0..held.len];
    }

    // Empty artifact bytes.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        const held = fixture.batch.shards[0].stwd5pr1_bytes;
        fixture.batch.shards[0].stwd5pr1_bytes = held[0..0];
        try std.testing.expectError(
            error.SharedDegree5ProviderShardArtifactSizeV1,
            fixture.validate(),
        );
        fixture.batch.shards[0].stwd5pr1_bytes = held;
    }

    // The leaf this batch belongs to: a shard wrapped for another leaf's
    // omission digest is refused by name.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        const other = try LeafOmission.canonical(
            digest(0x31),
            digest(0x42),
            fixture.shared.identity,
            authorityId(0x65),
        );
        try fixture.rewrap(0, other.identity);
        try std.testing.expectError(
            error.SharedDegree5ProviderBatchLeafOmissionMismatchV1,
            fixture.validate(),
        );
    }

    // A mutated D5 statement identity breaks the wrapper itself.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        fixture.batch.shards[0].statement.provider.identity = digest(0x99);
        try std.testing.expectError(
            error.InvalidLeafProviderStatementV4,
            fixture.validate(),
        );
    }

    // The shared relation authority the batch was produced under, and the
    // plan that authority names.
    {
        var fixture: BatchFixture = undefined;
        try fixture.init(allocator);
        defer fixture.deinit();
        var other = fixture.shared;
        other.identity = digest(0x99);
        try std.testing.expectError(
            error.SharedDegree5ProviderBatchSharedAuthorityMismatchV1,
            fixture.batch.validateCanonical(&fixture.plan, other),
        );
        other = fixture.shared;
        other.plan_identity = digest(0x99);
        try std.testing.expectError(
            error.SharedDegree5ProviderBatchSharedAuthorityMismatchV1,
            fixture.batch.validateCanonical(&fixture.plan, other),
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Leaf statement wrapping
// ---------------------------------------------------------------------------

test "shared D5 provider batch: leaf statement wrapping binds this leaf" {
    var fixture: BatchFixture = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const provider = fixture.batch.shards[0].statement.provider;
    const wrapped = try LeafStatement.canonical(
        fixture.leaf_omission.identity,
        provider,
    );
    try wrapped.validate();
    try wrapped.validateAgainst(&fixture.leaf_omission, provider);
    try std.testing.expect(
        std.meta.eql(wrapped, fixture.batch.shards[0].statement),
    );

    // Same D5 statement, another leaf: a different wrapper identity, and the
    // readmission against this leaf fails.
    const other = try LeafOmission.canonical(
        digest(0x31),
        digest(0x43),
        fixture.shared.identity,
        authorityId(0x64),
    );
    const relabelled = try LeafStatement.canonical(other.identity, provider);
    try std.testing.expect(!std.mem.eql(
        u8,
        &relabelled.identity,
        &wrapped.identity,
    ));
    try std.testing.expectError(
        error.InvalidLeafProviderStatementV4,
        relabelled.validateAgainst(&fixture.leaf_omission, provider),
    );

    // A wrapper whose identity does not rebuild is refused outright.
    var forged = wrapped;
    forged.identity = digest(0x99);
    try std.testing.expectError(
        error.InvalidLeafProviderStatementV4,
        forged.validate(),
    );
    forged = wrapped;
    forged.leaf_omission_identity = digest(0);
    try std.testing.expectError(
        error.InvalidLeafProviderStatementV4,
        forged.validate(),
    );
}

// ---------------------------------------------------------------------------
// 4. Byte caps
// ---------------------------------------------------------------------------

test "shared D5 provider batch: shard artifacts stay under the canonical cap" {
    try shared_batch.artifact_limits.validate();
    try std.testing.expectEqual(
        @as(usize, @intCast(execution_mod.MAX_CANONICAL_PROOF_BYTES_PER_SHARD)),
        shared_batch.MAX_CANONICAL_SHARD_ARTIFACT_BYTES,
    );
    // Framing plus proof budget is exactly the cap: an artifact `encodeAlloc`
    // accepts can never exceed what `validateCanonical` admits.
    try std.testing.expectEqual(
        shared_batch.MAX_CANONICAL_SHARD_ARTIFACT_BYTES,
        shared_batch.artifact_limits.max_proof_bytes +
            artifact_mod.header_size + artifact_mod.metadata_size,
    );
    try std.testing.expectEqual(
        shared_batch.MAX_CANONICAL_SHARD_ARTIFACT_BYTES,
        shared_batch.artifact_limits.max_artifact_bytes,
    );

    var fixture: BatchFixture = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.deinit();

    // One byte over the cap. The pages are reserved and never touched: the
    // length check precedes the sha256 of the shard bytes, which is the
    // ordering this assertion also pins.
    const oversized = try std.heap.page_allocator.alloc(
        u8,
        shared_batch.MAX_CANONICAL_SHARD_ARTIFACT_BYTES + 1,
    );
    defer std.heap.page_allocator.free(oversized);
    const held = fixture.batch.shards[0].stwd5pr1_bytes;
    fixture.batch.shards[0].stwd5pr1_bytes = oversized;
    try std.testing.expectError(
        error.SharedDegree5ProviderShardArtifactSizeV1,
        fixture.validate(),
    );
    fixture.batch.shards[0].stwd5pr1_bytes = held;
    try fixture.validate();
}

// ---------------------------------------------------------------------------
// 5. Fresh claims must carry the shared relation context
// ---------------------------------------------------------------------------

fn executionProfileFixture() degree5.ExecutionProfileV2 {
    return .{
        .format = 2,
        .air_program_identity = digest(0xe5),
        .retention = .always,
        .concurrent_provider_limit = 1,
        .composition_workers_per_provider = 1,
        .composition_host_byte_budget = 1024,
        .identity = BatchFixture.execution_identity,
    };
}

fn freshClaimFixture(
    plan: *const provider_authority.ProviderShardPlanV1,
    shared: Shared,
    index: usize,
    shared_context_verified: bool,
) shared_batch.FreshDegree5ProviderClaimV1 {
    const descriptor = plan.shards[index];
    var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
    for (&sums, 0..) |*value, ordinal|
        value.* = QM31.fromU32Unchecked(@intCast(ordinal + 1), 0, 0, 0);
    return .{
        .format = degree5.format_version,
        .air_program_identity = digest(0xe5),
        .execution_profile_identity = BatchFixture.execution_identity,
        .relation_context_identity = shared.relation_context.identity,
        .provider = .{
            .format = 2,
            .manifest_identity = shared.manifest_identity,
            .statement_identity = digest(@intCast(0x80 + index)),
            .proof_commitments_identity = digest(0x21),
            .fresh_provider_stark_verified = true,
            .ordered_call_air_verified = true,
            .ordered_call_claim_recomputed = true,
            .native_claim = .{
                .plan_identity = plan.identity,
                .descriptor_identity = descriptor.identity,
                .shard_index = @intCast(index),
                .relation_context_identity = shared.relation_context.identity,
                .claims = .{ .sums = sums },
            },
            .ordered_call_claim = .{
                .format = provider_order.format_version,
                .first_call = descriptor.first_call,
                .call_count = descriptor.call_count,
                .terminal = QM31.fromU32Unchecked(7, 0, 0, 0),
            },
            .identity = digest(0x33),
        },
        .shared_core_relation_context_verified = shared_context_verified,
        .global_degree5_domain_verified = true,
        .identity = digest(0x44),
    };
}

test "shared D5 provider batch: fresh claims must report the shared context" {
    const allocator = std.testing.allocator;
    var fixture: BatchFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const profile = executionProfileFixture();
    const claims = try allocator.alloc(
        shared_batch.FreshDegree5ProviderClaimV1,
        fixture.plan.shards.len,
    );
    var fresh = shared_batch.OwnedFreshSharedBatchV1{
        .allocator = allocator,
        .claims = claims,
    };
    defer fresh.deinit();
    for (fresh.claims, 0..) |*claim, index|
        claim.* = freshClaimFixture(&fixture.plan, fixture.shared, index, true);

    // The single bit this route exists for. It is checked before the claim's
    // own identity, so its refusal is its own.
    fresh.claims[1].shared_core_relation_context_verified = false;
    try std.testing.expectError(
        error.SharedDegree5ProviderFreshClaimUnsharedContextV1,
        fresh.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );
    try std.testing.expectEqual(
        fresh.claims.len - 1,
        fresh.sharedContextVerifiedCount(),
    );
    fresh.claims[1].shared_core_relation_context_verified = true;
    try std.testing.expectEqual(
        fresh.claims.len,
        fresh.sharedContextVerifiedCount(),
    );

    // Position, relation context, execution profile and plan binding are all
    // structural refusals, ahead of the claim identity check.
    fresh.claims[1].provider.native_claim.shard_index = 0;
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        fresh.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );
    fresh.claims[1].provider.native_claim.shard_index = 1;
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        fresh.validateAgainst(&fixture.plan, profile, digest(0x99)),
    );

    var other_profile = profile;
    other_profile.identity = digest(0x99);
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        fresh.validateAgainst(
            &fixture.plan,
            other_profile,
            fixture.shared.relation_context.identity,
        ),
    );

    fresh.claims[0].provider.native_claim.plan_identity = digest(0x99);
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        fresh.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );
    fresh.claims[0].provider.native_claim.plan_identity = fixture.plan.identity;
    fresh.claims[0].provider.native_claim.descriptor_identity = digest(0x99);
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        fresh.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );
    fresh.claims[0].provider.native_claim.descriptor_identity =
        fixture.plan.shards[0].identity;

    // A short claim list is never coverage.
    var short = shared_batch.OwnedFreshSharedBatchV1{
        .allocator = allocator,
        .claims = fresh.claims[0 .. fresh.claims.len - 1],
    };
    try std.testing.expectError(
        error.InvalidSharedDegree5ProviderFreshBatchV1,
        short.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );

    // With every structural check satisfied, the hand-built claim still fails
    // on its own identity: only a really verified claim can pass here.
    try std.testing.expectError(
        error.InvalidFreshProviderClaim,
        fresh.validateAgainst(
            &fixture.plan,
            profile,
            fixture.shared.relation_context.identity,
        ),
    );
}

// ---------------------------------------------------------------------------
// 6. Concrete instantiation of the two generic entrypoints
// ---------------------------------------------------------------------------

fn proveSharedRouteBatch(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    program: degree5.VerifierProgramAuthorityV2,
    profile: degree5.ExecutionProfileV2,
    source: transcript_mod.SourceV1(Engine),
    validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    prepared: *prepared_mod.OwnedPreparedBatchV1(Engine),
    execution: *const execution_mod.AuthorityV1,
) !Batch {
    return shared_batch.proveSharedPreparedParallelValidated(
        Engine,
        allocator,
        pcs_config,
        program,
        profile,
        source,
        validated,
        prepared,
        execution,
    );
}

fn verifySharedRouteBatch(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    program: degree5.VerifierProgramAuthorityV2,
    profile: degree5.ExecutionProfileV2,
    source_cpu: transcript_mod.SourceV1(Engine),
    validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    shards: *const Batch,
    execution: *const execution_mod.AuthorityV1,
) !shared_batch.OwnedFreshSharedBatchV1 {
    return shared_batch.verifySharedFreshParallelValidated(
        Engine,
        Engine,
        allocator,
        pcs_config,
        program,
        profile,
        source_cpu,
        validated,
        shards,
        execution,
    );
}

comptime {
    _ = &proveSharedRouteBatch;
    _ = &verifySharedRouteBatch;
}

test "shared D5 provider batch: custody surfaces stay byte only and leaf bound" {
    // The comptime block above is the gate; this body pins what it bound.
    try std.testing.expect(
        @FieldType(shared_batch.EncodedSharedShardV1, "stwd5pr1_bytes") == []u8,
    );
    try std.testing.expect(
        @FieldType(shared_batch.EncodedSharedShardV1, "statement") ==
            LeafStatement,
    );
    try std.testing.expect(
        @FieldType(Batch, "leaf_omission_identity") ==
            provider_authority.Digest,
    );
    try std.testing.expect(!shared_batch.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(shared_batch.RESEARCH_ONLY);
}
