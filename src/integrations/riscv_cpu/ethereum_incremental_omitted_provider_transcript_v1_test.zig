//! Focused gates for the V4 omitted-provider shard transcript source.
//!
//! The four things this file pins are the four that can silently break the
//! route without any proof failing loudly:
//!
//!   1. `validateRouteAuthorityBindings` rejects a mutation of every single
//!      bound field. This is `SourceV1.validate`'s route half reduced to
//!      digests, which is the only form of it reachable without a proved leaf
//!      (the statement half needs a real projection and is exercised by
//!      `test-riscv-ethereum-incremental-omitted-leaf-proof-v1`).
//!   2. `replaySharedTranscriptV4` reproduces, byte for byte, a channel built
//!      by hand in the plan's order -- profile pre-Tree0, omission frame, T0
//!      root, T1 root, profile post-Tree1, shared draw -- and recovers the
//!      same relation context. A reordering or an omitted mix changes the
//!      channel digest and fails here.
//!   3. The route's provider-local prefix is the ordinary V2 prefix followed
//!      by exactly the leaf-omission frame, so a segment-route shard proof of
//!      the same calls cannot be relabelled into this leaf.
//!   4. The retype helpers preserve every field and their comptime guard is
//!      false for a pair of engines with different transcript types.
//!
//! The channels here are the real q193 Poseidon2 engine's; the *profile* is a
//! fake, because `mixRoutePreTree0` takes it as `anytype` and a real
//! `AuthorityV4` cannot be minted without a boundary artifact. What is under
//! test is the order this module imposes around the profile, not the profile.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const transcript_mod =
    @import("ethereum_incremental_omitted_provider_transcript_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const public_data = frontend.air.public_data;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const incremental_bridge = frontend.prover_mod.incremental_bridge_external_v3;
const ethereum_transcript =
    frontend.prover_mod.guest_precompile.ethereum_transcript;
const route =
    frontend.prover_mod.guest_precompile.incremental_ethereum_omit_protocol_v4;
const protocol =
    frontend.prover_mod.ethereum_native_provider_omit_protocol_v1;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider_order = frontend.testing.narrow_memory_provider_order_component;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const shard_planner =
    @import("stwo_prover_engine").pcs.residency_shard_plan;

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Manifest = protocol.ProviderStageAManifestV1(Engine);
const Shared = protocol.SharedRelationAuthorityV1(Engine);
const Frame = transcript_mod.IncrementalOmissionFrameV4;
const LeafOmission = transcript_mod.LeafOmissionAuthorityV4;

const call_count = 33;
const test_shard_log = 4;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn digest(marker: u8) provider_authority.Digest {
    return [_]u8{marker} ** 32;
}

fn sha(marker: u8) [32]u8 {
    return [_]u8{marker} ** 32;
}

fn authorityId(marker: u32) route.AuthorityId {
    return [_]u32{marker} ** 8;
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

/// A residency request with the same shape as the route's pins but a test
/// shard log, so the fixture plans three shards instead of one 2^18 shard.
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

fn rootsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]harness.StageACommitment(Engine) {
    const roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        count,
    );
    for (roots, 0..) |*value, index| {
        value.* = .{
            .preprocessed_root = rootValue(@intCast(0x5100 + index)),
            .main_root = rootValue(@intCast(0xa200 + index)),
        };
    }
    return roots;
}

/// Distinct, field-safe root words. They must genuinely differ between the
/// preprocessed and the main root: a fixture whose two roots collide would
/// make a swapped `mixRoot` order invisible to the transcript gates.
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

/// A projected core stand-in. `mixMainClaim` reads only the descriptor
/// prefixes and the two counts, so a synthetic statement pins the same bytes a
/// real projected core would.
fn projectedCoreFixture() statement_mod.RiscVStatement {
    var core = std.mem.zeroes(statement_mod.RiscVStatement);
    core.initializeDescriptorStorage();
    core.n_components = 1;
    core.component_descs[0] = .{
        .family = .base_alu_reg,
        .log_size = 8,
        .n_rows = 200,
        .n_columns = 40,
    };
    core.n_infra = 2;
    core.infra_descs[0] = .{
        .kind = .program,
        .log_size = 7,
        .n_rows = 100,
        .n_columns = 12,
    };
    core.infra_descs[1] = .{
        .kind = .merkle,
        .log_size = 9,
        .n_rows = 400,
        .n_columns = 30,
    };
    return core;
}

/// Stands in for `AuthorityV4` at the two seams `mixRoutePreTree0` and
/// `replaySharedTranscriptV4` use. Every mix is domain separated and
/// order-sensitive, which is all the transcript gates need.
const FakeProfile = struct {
    identity_sha256: [32]u8,

    pub fn mixPreTree0(
        self: *const FakeProfile,
        native: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        channel: anytype,
    ) !void {
        _ = native;
        _ = role_aware_public;
        channel.mixU32s(&.{ 0x5052_4530, 0x0000_0001 });
        mixSha(channel, self.identity_sha256);
    }

    pub fn mixPostTree1(
        self: *const FakeProfile,
        native: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        channel: anytype,
    ) !void {
        _ = native;
        _ = role_aware_public;
        channel.mixU32s(&.{ 0x504f_5354, 0x0000_0001 });
        mixSha(channel, self.identity_sha256);
    }
};

fn mixSha(channel: anytype, value: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

/// A full-prefix bridge geometry and the projected prefix that follows once
/// the omitted component's (2, 445, 8) columns are gone.
const GeometryFixture = struct {
    full: incremental_bridge.GeometryV3,
    projected_prefix: incremental_bridge.PrefixColumnsV3,
    projected: incremental_bridge.GeometryV3,

    fn init() !GeometryFixture {
        const projected_prefix = incremental_bridge.PrefixColumnsV3{
            .preprocessed = 24,
            .main = 610,
            .interaction = 96,
        };
        const full_prefix = incremental_bridge.PrefixColumnsV3{
            .preprocessed = projected_prefix.preprocessed +
                route.omitted_preprocessed_columns,
            .main = projected_prefix.main + route.omitted_main_columns,
            .interaction = projected_prefix.interaction +
                route.omitted_interaction_columns,
        };
        const n_rows: u32 = 1024;
        return .{
            .full = try incremental_bridge.GeometryV3.canonicalAfterPrefix(
                n_rows,
                full_prefix,
            ),
            .projected_prefix = projected_prefix,
            .projected = try incremental_bridge.GeometryV3
                .canonicalAfterPrefix(n_rows, projected_prefix),
        };
    }
};

const Bindings = transcript_mod.RouteBindingsV1;

fn bindingsFixture(geometry: GeometryFixture) Bindings {
    return .{
        .profile_identity_sha256 = sha(0x31),
        .projection_identity = digest(0x42),
        .shared_identity = digest(0x53),
        .full_statement_authority_id = authorityId(0x64),
        .full_bridge_geometry = geometry.full,
        .projected_prefix = geometry.projected_prefix,
    };
}

const RouteAuthorities = struct {
    projected_bridge: incremental_bridge.GeometryV3,
    frame: Frame,
    leaf_omission: LeafOmission,
};

fn routeAuthorities(bindings: Bindings) !RouteAuthorities {
    const geometry = try frontend.testing
        .incremental_ethereum_omit_orchestration_v4_internal
        .projectedRouteGeometryFromPrefix(
        &bindings.full_bridge_geometry,
        bindings.projected_prefix,
    );
    const frame = try Frame.canonicalFromGeometry(
        bindings.projection_identity,
        geometry.bridge,
    );
    return .{
        .projected_bridge = geometry.bridge,
        .frame = frame,
        .leaf_omission = try LeafOmission.canonical(
            bindings.profile_identity_sha256,
            frame.identity,
            bindings.shared_identity,
            bindings.full_statement_authority_id,
        ),
    };
}

/// Plan, calls, Stage-A manifest and the projected core -- everything the
/// shared transcript replay reads, with no proof anywhere.
const TranscriptFixture = struct {
    allocator: std.mem.Allocator,
    calls: []poseidon2_air.Call,
    plan: provider_authority.ProviderShardPlanV1,
    roots: []harness.StageACommitment(Engine),
    manifest: protocol.OwnedProviderStageAManifestV1(Engine),
    token: provider_authority.OwnedValidatedPlanCallAuthorityV1,
    core: statement_mod.RiscVStatement,
    profile: FakeProfile,

    /// Initialised in place: `OwnedValidatedPlanCallAuthorityV1` and the
    /// Stage-A manifest both close over `&self.plan` by pointer, so the
    /// fixture must already live at its final address before they are minted.
    fn init(self: *TranscriptFixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.core = projectedCoreFixture();
        self.profile = .{ .identity_sha256 = sha(0x31) };
        self.calls = try callsFixture(allocator, call_count);
        errdefer allocator.free(self.calls);
        self.plan = try provider_authority.ProviderShardPlanV1.create(
            allocator,
            digest(0xa7),
            self.calls,
            request(self.calls.len),
        );
        errdefer self.plan.deinit(allocator);
        self.roots = try rootsFixture(allocator, self.plan.shards.len);
        errdefer allocator.free(self.roots);
        self.token = try provider_authority.OwnedValidatedPlanCallAuthorityV1
            .init(allocator, &self.plan, self.calls);
        errdefer self.token.deinit();
        self.manifest = try Manifest.createFromRootsValidated(
            allocator,
            &self.plan,
            self.calls,
            &self.token,
            self.roots,
        );
    }

    fn deinit(self: *TranscriptFixture) void {
        self.manifest.deinit(self.allocator);
        self.token.deinit();
        self.allocator.free(self.roots);
        self.plan.deinit(self.allocator);
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    /// Replays [1]..[5] by hand, then *produces* the shared draw so the
    /// fixture owns a real 16-bit PoW nonce and the exact relations the
    /// adapter must recover.
    fn produceShared(
        self: *const TranscriptFixture,
        allocator: std.mem.Allocator,
        frame: *const Frame,
    ) !Shared {
        var channel = Engine.Channel{};
        try self.mixThroughPostTree1(&channel, frame);
        const prefix = try ethereum_transcript.proveToRelationsWithExtension(
            allocator,
            &channel,
            &self.core,
            protocol.ProviderFrameV1(Engine){
                .projection_identity = frame.projection_identity,
                .provider_stage_a = &self.manifest.manifest,
                .tree0_root = self.roots[0].preprocessed_root,
                .tree1_root = self.roots[0].main_root,
            },
        );
        const relation_context = try provider_authority
            .PoseidonRelationContextV1.canonical(
            self.plan.session,
            prefix.relations.base.poseidon2.z,
            prefix.relations.base.poseidon2.alpha,
        );
        return .{
            .format = 1,
            .plan_identity = self.plan.identity,
            .manifest_identity = self.manifest.manifest.identity,
            .projection_identity = frame.projection_identity,
            .tree0_root = self.roots[0].preprocessed_root,
            .tree1_root = self.roots[0].main_root,
            .interaction_pow_bits = 16,
            .interaction_pow = prefix.interaction_pow,
            .relation_context = relation_context,
            .identity = digest(0),
        };
    }

    /// Steps [1] through [5], written out here rather than borrowed from the
    /// module under test: that is what makes this a byte-order pin.
    fn mixThroughPostTree1(
        self: *const TranscriptFixture,
        channel: *Engine.Channel,
        frame: *const Frame,
    ) !void {
        var native: statement_v2.RiscVStatementV2 = undefined;
        var role_aware: public_data.PublicData = undefined;
        try self.profile.mixPreTree0(&native, &role_aware, channel);
        frame.mixInto(channel);
        Engine.MerkleChannel.mixRoot(channel, self.roots[0].preprocessed_root);
        Engine.MerkleChannel.mixRoot(channel, self.roots[0].main_root);
        try self.profile.mixPostTree1(&native, &role_aware, channel);
    }

    fn replay(
        self: *const TranscriptFixture,
        allocator: std.mem.Allocator,
        frame: *const Frame,
        shared: Shared,
    ) !protocol.Replay(Engine) {
        var native: statement_v2.RiscVStatementV2 = undefined;
        var role_aware: public_data.PublicData = undefined;
        return transcript_mod.replaySharedTranscriptV4(
            Engine,
            allocator,
            &self.profile,
            &native,
            &role_aware,
            frame,
            &self.core,
            &self.plan,
            &self.manifest.manifest,
            shared,
        );
    }

    fn shardClaim(
        self: *const TranscriptFixture,
        shared: Shared,
        index: usize,
    ) provider_authority.ProviderShardClaimV1 {
        var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
        for (&sums, 0..) |*value, ordinal|
            value.* = QM31.fromU32Unchecked(
                @intCast(index * 7 + ordinal + 1),
                0,
                0,
                0,
            );
        return .{
            .plan_identity = self.plan.identity,
            .descriptor_identity = self.plan.shards[index].identity,
            .shard_index = @intCast(index),
            .relation_context_identity = shared.relation_context.identity,
            .claims = .{ .sums = sums },
        };
    }

    fn orderedClaim(
        self: *const TranscriptFixture,
        index: usize,
    ) provider_order.ClaimV1 {
        return .{
            .format = provider_order.format_version,
            .first_call = self.plan.shards[index].first_call,
            .call_count = self.plan.shards[index].call_count,
            .terminal = QM31.fromU32Unchecked(7, 0, 0, 0),
        };
    }
};

// ---------------------------------------------------------------------------
// 1. Route binding rejection matrix
// ---------------------------------------------------------------------------

test "omitted provider transcript v1: route bindings admit exactly the recomputed authorities" {
    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);

    try transcript_mod.validateRouteAuthorityBindings(
        bindings,
        &authorities.projected_bridge,
        &authorities.frame,
        &authorities.leaf_omission,
    );

    // The projected geometry is the full one minus exactly the omitted
    // component's columns, and it keeps the same rows and log size.
    try std.testing.expectEqual(
        geometry.full.n_rows,
        authorities.projected_bridge.n_rows,
    );
    try std.testing.expectEqual(
        geometry.full.log_size,
        authorities.projected_bridge.log_size,
    );
    try std.testing.expectEqual(
        @as(usize, 445),
        geometry.full.placement.main_col_offset -
            authorities.projected_bridge.placement.main_col_offset,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        geometry.full.placement.interaction_col_offset -
            authorities.projected_bridge.placement.interaction_col_offset,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        geometry.full.placement.is_first_col_idx -
            authorities.projected_bridge.placement.is_first_col_idx,
    );
}

test "omitted provider transcript v1: route bindings reject every mutated field" {
    const geometry = try GeometryFixture.init();
    const base = bindingsFixture(geometry);
    const authorities = try routeAuthorities(base);

    // Profile identity: the leaf omission digest no longer rebuilds.
    var mutated = base;
    mutated.profile_identity_sha256 = sha(0x99);
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceLeafOmissionMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // Projection identity: the frame no longer rebuilds, and the failure is
    // caught before the leaf omission digest is even reached.
    mutated = base;
    mutated.projection_identity = digest(0x99);
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceFrameMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // Shared relation identity.
    mutated = base;
    mutated.shared_identity = digest(0x99);
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceLeafOmissionMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // Full statement authority id: this is what stops another leaf's shard
    // proof from being relabelled into this one.
    mutated = base;
    mutated.full_statement_authority_id = authorityId(0x99);
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceLeafOmissionMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // Full bridge geometry: no longer exactly (2, 445, 8) above the projected
    // prefix, so the placement arithmetic itself fails closed.
    mutated = base;
    mutated.full_bridge_geometry = try incremental_bridge.GeometryV3
        .canonicalAfterPrefix(geometry.full.n_rows, .{
        .preprocessed = geometry.projected_prefix.preprocessed + 3,
        .main = geometry.projected_prefix.main + 445,
        .interaction = geometry.projected_prefix.interaction + 8,
    });
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // Projected prefix.
    mutated = base;
    mutated.projected_prefix.main += 1;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        transcript_mod.validateRouteAuthorityBindings(
            mutated,
            &authorities.projected_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );
}

test "omitted provider transcript v1: route bindings reject a mutated recomputed authority" {
    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);

    // A projected bridge geometry that is not the one the prefix implies.
    var wrong_bridge = authorities.projected_bridge;
    wrong_bridge.n_rows += 8;
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceBridgeMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            bindings,
            &wrong_bridge,
            &authorities.frame,
            &authorities.leaf_omission,
        ),
    );

    // A frame whose identity was tampered with after minting.
    var wrong_frame = authorities.frame;
    wrong_frame.identity = digest(0x77);
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceFrameMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            bindings,
            &authorities.projected_bridge,
            &wrong_frame,
            &authorities.leaf_omission,
        ),
    );

    // A leaf omission digest bound to a different frame.
    const other_frame = try Frame.canonicalFromGeometry(
        digest(0x21),
        authorities.projected_bridge,
    );
    const foreign_leaf = try LeafOmission.canonical(
        bindings.profile_identity_sha256,
        other_frame.identity,
        bindings.shared_identity,
        bindings.full_statement_authority_id,
    );
    try std.testing.expectError(
        error.IncrementalOmittedProviderSourceLeafOmissionMismatchV1,
        transcript_mod.validateRouteAuthorityBindings(
            bindings,
            &authorities.projected_bridge,
            &authorities.frame,
            &foreign_leaf,
        ),
    );
}

// ---------------------------------------------------------------------------
// 2. Shared transcript replay
// ---------------------------------------------------------------------------

test "omitted provider transcript v1: replayShared reproduces the hand-built channel" {
    const allocator = std.testing.allocator;
    var fixture: TranscriptFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);

    var shared = try fixture.produceShared(allocator, &authorities.frame);

    // Hand-built control arm: exactly the plan's order, written out locally.
    var expected_channel = Engine.Channel{};
    try fixture.mixThroughPostTree1(&expected_channel, &authorities.frame);
    const expected_relations = try ethereum_transcript
        .verifyToRelationsWithExtension(
        allocator,
        &expected_channel,
        &fixture.core,
        shared.interaction_pow,
        protocol.ProviderFrameV1(Engine){
            .projection_identity = authorities.frame.projection_identity,
            .provider_stage_a = &fixture.manifest.manifest,
            .tree0_root = shared.tree0_root,
            .tree1_root = shared.tree1_root,
        },
    );

    var replay = try fixture.replay(allocator, &authorities.frame, shared);

    try std.testing.expectEqualSlices(
        u32,
        &expected_channel.digestWords(),
        &replay.channel.digestWords(),
    );
    try std.testing.expectEqual(
        expected_channel.n_draws,
        replay.channel.n_draws,
    );
    try std.testing.expect(std.meta.eql(
        replay.relations.base.poseidon2.z,
        expected_relations.base.poseidon2.z,
    ));

    // The relation context recovered from the replayed draw is the one the
    // shared authority carries; that equality is the whole point of the route.
    const recovered = try provider_authority.PoseidonRelationContextV1
        .canonical(
        fixture.plan.session,
        replay.relations.base.poseidon2.z,
        replay.relations.base.poseidon2.alpha,
    );
    try std.testing.expect(
        std.meta.eql(recovered, replay.authority_value.relation_context),
    );

    // A shared authority carrying any other relation context is refused.
    shared.relation_context.identity = digest(0x5a);
    try std.testing.expectError(
        error.EthereumProviderRelationContextMismatch,
        fixture.replay(allocator, &authorities.frame, shared),
    );
}

test "omitted provider transcript v1: replay refuses a frame bound to another projection" {
    const allocator = std.testing.allocator;
    var fixture: TranscriptFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);
    const shared = try fixture.produceShared(allocator, &authorities.frame);

    const other_frame = try Frame.canonicalFromGeometry(
        digest(0x21),
        authorities.projected_bridge,
    );
    try std.testing.expectError(
        error.IncrementalOmittedProviderFrameProjectionMismatchV1,
        fixture.replay(allocator, &other_frame, shared),
    );
}

// ---------------------------------------------------------------------------
// 3. Provider-local prefix byte order
// ---------------------------------------------------------------------------

test "omitted provider transcript v1: local prefix is the ordinary frame plus the leaf omission frame" {
    const allocator = std.testing.allocator;
    var fixture: TranscriptFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);
    const shared = try fixture.produceShared(allocator, &authorities.frame);
    const claim = fixture.shardClaim(shared, 0);
    const ordered = fixture.orderedClaim(0);

    var route_channel = Engine.Channel{};
    const route_replay = try fixture.replay(
        allocator,
        &authorities.frame,
        shared,
    );
    route_channel = route_replay.channel;
    try transcript_mod.appendLeafProviderLocalFrame(
        &route_channel,
        &fixture.plan,
        &fixture.manifest.manifest,
        shared.relation_context.identity,
        &authorities.leaf_omission,
        claim,
        ordered,
    );

    // Control arm: the ordinary provider V2 frame alone, then the route frame
    // applied on top. The two must land on the same channel state, which pins
    // both the position and the content of the appended words.
    var control = route_replay.channel;
    try protocol.appendProviderLocalFrameV2(
        &control,
        &fixture.plan,
        &fixture.manifest.manifest,
        shared.relation_context.identity,
        claim,
        ordered,
    );
    const ordinary_digest = control.digestWords();
    authorities.leaf_omission.mixIntoLocalPrefix(&control);

    try std.testing.expectEqualSlices(
        u32,
        &control.digestWords(),
        &route_channel.digestWords(),
    );
    // ... and the route frame is not a no-op: a segment-route shard proof,
    // which stops at the ordinary frame, lands somewhere else entirely.
    try std.testing.expect(!std.mem.eql(
        u32,
        &ordinary_digest,
        &route_channel.digestWords(),
    ));

    // A leaf omission digest from another leaf changes the prefix.
    const other_frame = try Frame.canonicalFromGeometry(
        digest(0x21),
        authorities.projected_bridge,
    );
    const foreign_leaf = try LeafOmission.canonical(
        bindings.profile_identity_sha256,
        other_frame.identity,
        bindings.shared_identity,
        bindings.full_statement_authority_id,
    );
    var foreign_channel = route_replay.channel;
    try transcript_mod.appendLeafProviderLocalFrame(
        &foreign_channel,
        &fixture.plan,
        &fixture.manifest.manifest,
        shared.relation_context.identity,
        &foreign_leaf,
        claim,
        ordered,
    );
    try std.testing.expect(!std.mem.eql(
        u32,
        &foreign_channel.digestWords(),
        &route_channel.digestWords(),
    ));
}

test "omitted provider transcript v1: leaf provider statement binds the omission digest" {
    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);

    var provider = std.mem.zeroes(transcript_mod.ProviderStatementV1);
    provider.identity = digest(0x11);
    const wrapped = try transcript_mod.LeafProviderStatementV4.canonical(
        authorities.leaf_omission.identity,
        provider,
    );
    try wrapped.validateAgainst(&authorities.leaf_omission, provider);

    // A wrapper naming another leaf, and a wrapper whose identity was
    // recomputed for a different provider statement, are both refused.
    const other_frame = try Frame.canonicalFromGeometry(
        digest(0x21),
        authorities.projected_bridge,
    );
    const foreign_leaf = try LeafOmission.canonical(
        bindings.profile_identity_sha256,
        other_frame.identity,
        bindings.shared_identity,
        bindings.full_statement_authority_id,
    );
    try std.testing.expectError(
        error.InvalidLeafProviderStatementV4,
        wrapped.validateAgainst(&foreign_leaf, provider),
    );

    var tampered = wrapped;
    tampered.provider.identity = digest(0x12);
    try std.testing.expectError(
        error.InvalidLeafProviderStatementV4,
        tampered.validate(),
    );
}

// ---------------------------------------------------------------------------
// 4. Engine retype helpers
// ---------------------------------------------------------------------------

/// Shares `Hasher`/`Channel`/`MerkleChannel` with `Engine` by construction:
/// this is the shape of the Metal-to-CPU hand-off the route performs.
const AliasEngine = struct {
    pub const Hasher = Engine.Hasher;
    pub const Channel = Engine.Channel;
    pub const MerkleChannel = Engine.MerkleChannel;
};

/// A deliberately incompatible engine: same hasher, different channel.
const ForeignEngine = struct {
    pub const Hasher = Engine.Hasher;
    pub const Channel = stwo_core.channel.blake2s.Blake2sChannel;
    pub const MerkleChannel = Engine.MerkleChannel;
};

test "omitted provider transcript v1: retype helpers guard transcript types and preserve identity" {
    const allocator = std.testing.allocator;

    // The comptime guard the retype helpers use is true only for a pair that
    // shares all three transcript types.
    try std.testing.expect(
        transcript_mod.transcriptTypesCompatible(Engine, Engine),
    );
    try std.testing.expect(
        transcript_mod.transcriptTypesCompatible(Engine, AliasEngine),
    );
    try std.testing.expect(
        !transcript_mod.transcriptTypesCompatible(Engine, ForeignEngine),
    );
    try std.testing.expect(
        !transcript_mod.transcriptTypesCompatible(ForeignEngine, Engine),
    );

    var fixture: TranscriptFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();

    const retyped_roots = try transcript_mod.retypeStageARoots(
        Engine,
        AliasEngine,
        allocator,
        fixture.roots,
    );
    defer allocator.free(retyped_roots);
    try std.testing.expectEqual(fixture.roots.len, retyped_roots.len);
    for (fixture.roots, retyped_roots) |source, destination| {
        try std.testing.expect(std.meta.eql(
            source.preprocessed_root,
            destination.preprocessed_root,
        ));
        try std.testing.expect(std.meta.eql(
            source.main_root,
            destination.main_root,
        ));
    }

    const geometry = try GeometryFixture.init();
    const bindings = bindingsFixture(geometry);
    const authorities = try routeAuthorities(bindings);
    const shared = try fixture.produceShared(allocator, &authorities.frame);
    const retyped_shared = transcript_mod.retypeSharedRelation(
        Engine,
        AliasEngine,
        shared,
    );
    try std.testing.expectEqualSlices(
        u8,
        &shared.identity,
        &retyped_shared.identity,
    );
    try std.testing.expectEqual(
        shared.interaction_pow,
        retyped_shared.interaction_pow,
    );
    try std.testing.expect(std.meta.eql(
        shared.relation_context,
        retyped_shared.relation_context,
    ));

    // The verifier-side manifest is rebuilt, not copied, and only an identity
    // equal to the producer's is accepted.
    var verifier_manifest = try transcript_mod.manifestForVerifier(
        Engine,
        AliasEngine,
        allocator,
        &fixture.plan,
        fixture.calls,
        &fixture.token,
        &fixture.manifest.manifest,
    );
    defer verifier_manifest.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &fixture.manifest.manifest.identity,
        &verifier_manifest.manifest.identity,
    );

    // A producer manifest whose record count disagrees with the plan is
    // refused before any rebuild happens.
    var short = fixture.manifest.manifest;
    short.providers = fixture.manifest.manifest.providers[0 .. fixture.manifest
        .manifest.providers.len - 1];
    try std.testing.expectError(
        error.IncrementalOmittedProviderStageARootCountMismatchV1,
        transcript_mod.manifestForVerifier(
            Engine,
            AliasEngine,
            allocator,
            &fixture.plan,
            fixture.calls,
            &fixture.token,
            &short,
        ),
    );
}

test "omitted provider transcript v1: module stays research only" {
    try std.testing.expect(transcript_mod.RESEARCH_ONLY);
    try std.testing.expect(!transcript_mod.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expectEqual(
        @as(u32, 1),
        transcript_mod.FORMAT_VERSION,
    );
}

// ---------------------------------------------------------------------------
// Concrete instantiation
// ---------------------------------------------------------------------------
//
// `SourceV1`, the adapter and the retype helpers are generic over the engine,
// so Zig analyses none of their bodies until something binds them to a real
// one. The wrappers below bind them to the q193 Poseidon2 CPU engine and the
// real `AuthorityV4`, and the comptime block references them, which forces
// full semantic analysis -- of `validate`'s statement half in particular,
// which the fixtures above deliberately cannot reach. Without this the first
// thing to type-check these bodies would be a ten-minute product build.

const RouteSource = transcript_mod.SourceV1(Engine);

fn validateRouteSource(source: RouteSource) !void {
    try source.validate();
    try source.validateRouteAuthorities();
}

fn ordinaryRouteSource(
    source: RouteSource,
) frontend.testing.narrow_memory_provider_ethereum_omit_proof_v1
    .Source(Engine) {
    return source.ordinary();
}

fn routeSourceGeometry(
    source: RouteSource,
) !transcript_mod.ProjectedRouteGeometryV4 {
    return source.projectedRouteGeometry();
}

fn replaySharedRoute(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    source: RouteSource,
) !protocol.Replay(Engine) {
    return transcript_mod.Stage101TranscriptAdapterV1.replayShared(
        Engine,
        allocator,
        pcs_config,
        source,
    );
}

fn providerLocalPrefixRoute(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    source: RouteSource,
    claim: provider_authority.ProviderShardClaimV1,
    ordered: provider_order.ClaimV1,
) !Engine.Channel {
    return transcript_mod.Stage101TranscriptAdapterV1.providerLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        source,
        claim,
        ordered,
    );
}

fn leafStatementForRoute(
    source: RouteSource,
    provider: transcript_mod.ProviderStatementV1,
) !transcript_mod.LeafProviderStatementV4 {
    return transcript_mod.makeLeafProviderStatement(source, provider);
}

const degree5_proof =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;

/// The contract this whole step exists to satisfy: the D5 shard prover and
/// fresh verifier must accept `Stage101TranscriptAdapterV1` and `SourceV1` in
/// place of their ordinary pair. Binding both here turns any drift in the
/// adapter's argument list or in the fields the prover reads off the source
/// into a compile error at this focused root, instead of at Step 6.
fn proveRouteShard(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    program: degree5_proof.VerifierProgramAuthorityV2,
    execution_profile: degree5_proof.ExecutionProfileV2,
    source: RouteSource,
    validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    shard_index: u32,
    prepared: *degree5_proof.PreparedStageATransactionV1(Engine),
) !degree5_proof.ProviderProofOutputV1(Engine) {
    return degree5_proof.proveProviderPreparedValidatedWithTranscriptV2(
        Engine,
        transcript_mod.Stage101TranscriptAdapterV1,
        allocator,
        pcs_config,
        program,
        execution_profile,
        source,
        validated,
        shard_index,
        prepared,
    );
}

fn verifyRouteShard(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    program: degree5_proof.VerifierProgramAuthorityV2,
    execution_profile: degree5_proof.ExecutionProfileV2,
    source: RouteSource,
    validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    statement: transcript_mod.ProviderStatementV1,
    proof_in: stwo_core.proof.StarkProof(Engine.Hasher),
) !degree5_proof.FreshDegree5ProviderClaimV1 {
    return degree5_proof.verifyProviderFreshValidatedWithTranscriptV2(
        Engine,
        transcript_mod.Stage101TranscriptAdapterV1,
        allocator,
        pcs_config,
        program,
        execution_profile,
        source,
        validated,
        statement,
        proof_in,
    );
}

/// `closeFreshClaimsV2` takes the *ordinary* source, which is what
/// `SourceV1.ordinary()` exists to produce.
fn closeRouteClaims(
    allocator: std.mem.Allocator,
    program: degree5_proof.VerifierProgramAuthorityV2,
    execution_profile: degree5_proof.ExecutionProfileV2,
    source: RouteSource,
    core: protocol.FreshCoreResidualV1,
    providers: []const degree5_proof.FreshDegree5ProviderClaimV1,
) !degree5_proof.ClosedStrategyV1 {
    return degree5_proof.closeFreshClaimsV2(
        Engine,
        allocator,
        program,
        execution_profile,
        source.ordinary(),
        core,
        providers,
    );
}

comptime {
    _ = &validateRouteSource;
    _ = &ordinaryRouteSource;
    _ = &routeSourceGeometry;
    _ = &replaySharedRoute;
    _ = &providerLocalPrefixRoute;
    _ = &leafStatementForRoute;
    _ = &proveRouteShard;
    _ = &verifyRouteShard;
    _ = &closeRouteClaims;
}

test "omitted provider transcript v1: route source binds the real V4 profile" {
    // The comptime block above is the gate; this body only pins what it bound.
    try std.testing.expect(
        @FieldType(RouteSource, "profile") == *const transcript_mod.AuthorityV4,
    );
    try std.testing.expect(
        @FieldType(RouteSource, "projected_bridge") ==
            incremental_bridge.GeometryV3,
    );
    try std.testing.expect(@FieldType(RouteSource, "frame_v4") == Frame);
    try std.testing.expect(
        @FieldType(RouteSource, "leaf_omission") == LeafOmission,
    );
    // The full statement, never a projected core: ordinary admission requires
    // the omitted 445-column descriptor and can never accept a projected one.
    try std.testing.expect(
        @FieldType(RouteSource, "native") ==
            *const statement_v2.RiscVStatementV2,
    );
}
