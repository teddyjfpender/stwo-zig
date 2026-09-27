//! Research-only caller+N transcript for base narrow-memory Poseidon shards.
//!
//! The manifest binds a real base-Merkle caller Tree0/Tree1 pair and every
//! real provider shard Tree0/Tree1 pair in canonical plan order.  One
//! joint interaction PoW follows the complete Stage-A manifest; only then are
//! the shared base relations drawn.  A shard-local suffix binds its descriptor,
//! range, and two QM31 claims before that shard may commit Tree2.
//!
//! This closes transcript-order ambiguity for tiny research proofs.  It does
//! not externalize the real caller residual, AIR-prove call order, aggregate
//! proofs under one final PoW, or activate a production/recursive protocol.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const transcript = @import("../../air/transcript/mod.zig");
const relations_mod = @import("../../air/relation_challenges.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const provider_order = @import("provider_order_component.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const REAL_CALLER_STAGE_A_IMPLEMENTED = true;
pub const CORE_STAGE_A_IS_SYNTHETIC = false;
pub const ORDERED_CALL_RANGES_ARE_CUSTODY_ONLY = true;
pub const ORDERED_CALL_RANGES_ARE_AIR_PROVED = false;
pub const PROVIDER_V2_ORDERED_CALL_RANGES_ARE_AIR_PROVED = true;
pub const JOINT_STAGE_A_MANIFEST_IMPLEMENTED = true;
pub const JOINT_INTERACTION_POW_IMPLEMENTED = true;
pub const SHARD_TREE2_FOLLOWS_LOCAL_SUFFIX = true;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;

pub const format_version: u32 = 2;
pub const joint_interaction_pow_bits: u32 = transcript.INTERACTION_POW_BITS;
pub const Digest = authority.Digest;

pub const CoreStageASource = enum(u8) {
    base_merkle_externalized_provider_caller = 1,
};

pub fn CoreStageARecord(comptime Engine: type) type {
    return struct {
        format: u32,
        plan_identity: Digest,
        session: Digest,
        source: CoreStageASource,
        call_list_commitment: Digest,
        log_size: u32,
        n_rows: u32,
        main_columns: u16,
        interaction_columns: u16,
        preprocessed_root: Engine.Hasher.Hash,
        main_root: Engine.Hasher.Hash,
        identity: Digest,

        const Self = @This();

        fn canonical(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
            roots: harness.StageACommitment(Engine),
        ) Self {
            var result = Self{
                .format = format_version,
                .plan_identity = plan.identity,
                .session = plan.session,
                .source = .base_merkle_externalized_provider_caller,
                .call_list_commitment = plan.call_list_commitment,
                .log_size = expectedCoreLogSize(calls.len),
                .n_rows = @intCast(calls.len),
                .main_columns = @import("../../air/memory_commitment/merkle_node.zig").N_MAIN_COLUMNS,
                .interaction_columns = @import("../../air/memory_commitment/merkle_node.zig").N_INTERACTION_COLUMNS,
                .preprocessed_root = roots.preprocessed_root,
                .main_root = roots.main_root,
                .identity = undefined,
            };
            result.identity = coreStageAIdentity(Engine, result);
            return result;
        }

        fn validate(
            self: Self,
            plan: *const authority.ProviderShardPlanV1,
        ) !void {
            if (self.format != format_version) return error.InvalidFormatVersion;
            if (self.source != .base_merkle_externalized_provider_caller)
                return error.InvalidCoreStageASource;
            if (!aggregation_hash.eql(self.plan_identity, plan.identity))
                return error.PlanIdentityMismatch;
            if (!aggregation_hash.eql(self.session, plan.session))
                return error.SessionMismatch;
            if (!aggregation_hash.eql(
                self.call_list_commitment,
                plan.call_list_commitment,
            ) or self.n_rows != plan.total_call_count or
                self.log_size != expectedCoreLogSize(@intCast(plan.total_call_count)) or
                self.main_columns !=
                    @import("../../air/memory_commitment/merkle_node.zig").N_MAIN_COLUMNS or
                self.interaction_columns !=
                    @import("../../air/memory_commitment/merkle_node.zig").N_INTERACTION_COLUMNS)
            {
                return error.InvalidCoreStageAGeometry;
            }
            if (!aggregation_hash.eql(
                self.identity,
                coreStageAIdentity(Engine, self),
            )) return error.CoreStageAIdentityMismatch;
        }
    };
}

pub fn ProviderStageARecord(comptime Engine: type) type {
    return struct {
        format: u32,
        plan_identity: Digest,
        descriptor_identity: Digest,
        shard_index: u32,
        shard_count: u32,
        first_call: u64,
        call_count: u32,
        expected_log_size: u32,
        preprocessed_root: Engine.Hasher.Hash,
        main_root: Engine.Hasher.Hash,
        identity: Digest,

        const Self = @This();

        pub fn canonical(
            plan: *const authority.ProviderShardPlanV1,
            shard_index: usize,
            roots: harness.StageACommitment(Engine),
        ) Self {
            const descriptor = plan.shards[shard_index];
            var result = Self{
                .format = format_version,
                .plan_identity = plan.identity,
                .descriptor_identity = descriptor.identity,
                .shard_index = descriptor.shard_index,
                .shard_count = descriptor.shard_count,
                .first_call = descriptor.first_call,
                .call_count = descriptor.call_count,
                .expected_log_size = descriptor.expected_log_size,
                .preprocessed_root = roots.preprocessed_root,
                .main_root = roots.main_root,
                .identity = undefined,
            };
            result.identity = providerStageAIdentity(Engine, result);
            return result;
        }

        pub fn validate(
            self: Self,
            plan: *const authority.ProviderShardPlanV1,
            shard_index: usize,
        ) !void {
            const descriptor = plan.shards[shard_index];
            if (self.format != format_version) return error.InvalidFormatVersion;
            if (!aggregation_hash.eql(self.plan_identity, plan.identity))
                return error.PlanIdentityMismatch;
            if (!aggregation_hash.eql(
                self.descriptor_identity,
                descriptor.identity,
            )) return error.ShardIdentityMismatch;
            if (self.shard_index != shard_index or
                self.shard_count != plan.shard_count)
            {
                return error.NonCanonicalShardPosition;
            }
            if (self.first_call != descriptor.first_call or
                self.call_count != descriptor.call_count or
                self.expected_log_size != descriptor.expected_log_size)
            {
                return error.ProviderGeometryMismatch;
            }
            if (!aggregation_hash.eql(
                self.identity,
                providerStageAIdentity(Engine, self),
            )) return error.ProviderStageAIdentityMismatch;
        }
    };
}

pub fn JointManifest(comptime Engine: type) type {
    return struct {
        format: u32,
        plan_identity: Digest,
        session: Digest,
        call_list_commitment: Digest,
        shard_count: u32,
        core: CoreStageARecord(Engine),
        providers: []ProviderStageARecord(Engine),
        identity: Digest,

        const Self = @This();

        pub fn create(
            allocator: std.mem.Allocator,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
            core_roots: harness.StageACommitment(Engine),
            provider_roots: []const harness.StageACommitment(Engine),
        ) !Self {
            try plan.validate(calls);
            if (provider_roots.len != plan.shards.len)
                return error.IncompleteStageAManifest;
            const providers = try allocator.alloc(
                ProviderStageARecord(Engine),
                provider_roots.len,
            );
            errdefer allocator.free(providers);
            for (providers, provider_roots, 0..) |*record, roots, index| {
                record.* = ProviderStageARecord(Engine).canonical(
                    plan,
                    index,
                    roots,
                );
            }
            var result = Self{
                .format = format_version,
                .plan_identity = plan.identity,
                .session = plan.session,
                .call_list_commitment = plan.call_list_commitment,
                .shard_count = plan.shard_count,
                .core = CoreStageARecord(Engine).canonical(plan, calls, core_roots),
                .providers = providers,
                .identity = undefined,
            };
            result.identity = manifestIdentity(Engine, &result);
            try result.validate(plan, calls);
            return result;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.providers);
            self.* = undefined;
        }

        pub fn validate(
            self: *const Self,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
        ) !void {
            try plan.validate(calls);
            if (self.format != format_version) return error.InvalidFormatVersion;
            if (!aggregation_hash.eql(self.plan_identity, plan.identity))
                return error.PlanIdentityMismatch;
            if (!aggregation_hash.eql(self.session, plan.session))
                return error.SessionMismatch;
            if (!aggregation_hash.eql(
                self.call_list_commitment,
                plan.call_list_commitment,
            )) return error.GlobalCallCommitmentMismatch;
            if (self.shard_count != plan.shard_count or
                self.providers.len != plan.shards.len)
            {
                return error.IncompleteStageAManifest;
            }
            try self.core.validate(plan);
            for (self.providers, 0..) |record, index|
                try record.validate(plan, index);
            if (!aggregation_hash.eql(
                self.identity,
                manifestIdentity(Engine, self),
            )) return error.JointManifestIdentityMismatch;
        }
    };
}

pub const SharedRelationAuthorityV1 = struct {
    manifest_identity: Digest,
    interaction_pow_bits: u32,
    interaction_pow: u64,
    pow_context_digest: Digest,
    relation_context: authority.PoseidonRelationContextV1,
};

pub fn PreparedTranscript(comptime Engine: type) type {
    return struct {
        channel: Engine.Channel,
        relations: relations_mod.Relations,
        authority_value: SharedRelationAuthorityV1,
    };
}

/// Replays the complete manifest, mines one joint PoW, and only then draws the
/// shared relations.  The returned channel is the common prefix for every
/// shard-local claim/Tree2 transcript.
pub fn prepareSharedTranscript(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
) !PreparedTranscript(Engine) {
    try manifest.validate(plan, calls);
    var channel = jointPrefix(Engine, pcs_config, manifest);
    const interaction_pow = channel.grind(joint_interaction_pow_bits);
    channel.mixU64(interaction_pow);
    const pow_context_digest = digestBytes(channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        relations.poseidon2.z,
        relations.poseidon2.alpha,
    );
    return .{
        .channel = channel,
        .relations = relations,
        .authority_value = .{
            .manifest_identity = manifest.identity,
            .interaction_pow_bits = joint_interaction_pow_bits,
            .interaction_pow = interaction_pow,
            .pow_context_digest = pow_context_digest,
            .relation_context = relation_context,
        },
    };
}

/// Fresh replay rejects the nonce before mixing it and re-derives every
/// relation rather than trusting a detached context.
pub fn replaySharedTranscript(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
    expected: SharedRelationAuthorityV1,
) !PreparedTranscript(Engine) {
    try manifest.validate(plan, calls);
    if (!aggregation_hash.eql(expected.manifest_identity, manifest.identity))
        return error.JointManifestIdentityMismatch;
    if (expected.interaction_pow_bits != joint_interaction_pow_bits)
        return error.InvalidJointProofOfWork;
    var channel = jointPrefix(Engine, pcs_config, manifest);
    if (!channel.verifyPowNonce(
        joint_interaction_pow_bits,
        expected.interaction_pow,
    )) return error.InvalidJointProofOfWork;
    channel.mixU64(expected.interaction_pow);
    const pow_context_digest = digestBytes(channel);
    if (!aggregation_hash.eql(
        pow_context_digest,
        expected.pow_context_digest,
    )) return error.PowContextMismatch;
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        relations.poseidon2.z,
        relations.poseidon2.alpha,
    );
    if (!aggregation_hash.eql(
        relation_context.identity,
        expected.relation_context.identity,
    ) or !relation_context.z.eql(expected.relation_context.z) or
        !relation_context.alpha.eql(expected.relation_context.alpha))
    {
        return error.RelationContextMismatch;
    }
    return .{
        .channel = channel,
        .relations = relations,
        .authority_value = expected,
    };
}

/// Produces the exact provider-local transcript state immediately before its
/// Tree2 root.  It does not itself commit Tree2 or claim that the existing
/// standalone proof has adopted this prefix.
pub fn providerLocalPrefix(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
    shared: SharedRelationAuthorityV1,
    claim: authority.ProviderShardClaimV1,
) !Engine.Channel {
    var replay = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    const index = std.math.cast(usize, claim.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const record = manifest.providers[index];
    if (!aggregation_hash.eql(claim.plan_identity, plan.identity))
        return error.PlanIdentityMismatch;
    if (!aggregation_hash.eql(
        claim.descriptor_identity,
        descriptor.identity,
    )) return error.ShardClaimDescriptorMismatch;
    if (!aggregation_hash.eql(
        claim.relation_context_identity,
        shared.relation_context.identity,
    )) return error.RelationContextMismatch;

    replay.channel.mixU32s(&local_suffix_domain_words);
    mixDigest(&replay.channel, manifest.identity);
    mixDigest(&replay.channel, record.identity);
    replay.channel.mixU64(claim.shard_index);
    replay.channel.mixU64(descriptor.first_call);
    replay.channel.mixU64(descriptor.call_count);
    replay.channel.mixFelts(&claim.claims.sums);
    return replay.channel;
}

/// Append-only V2 provider suffix.  The shared Stage-A manifest and one PoW
/// remain byte-identical to V1, while this distinct suffix binds the public
/// endpoint of the ordered-call AIR before the twelve-column Tree 2 root.
/// V1 callers continue to use `providerLocalPrefix` unchanged.
pub fn providerLocalPrefixV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
    shared: SharedRelationAuthorityV1,
    claim: authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
) !Engine.Channel {
    var replay = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    const index = std.math.cast(usize, claim.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const record = manifest.providers[index];
    if (!aggregation_hash.eql(claim.plan_identity, plan.identity))
        return error.PlanIdentityMismatch;
    if (!aggregation_hash.eql(claim.descriptor_identity, descriptor.identity))
        return error.ShardClaimDescriptorMismatch;
    if (!aggregation_hash.eql(
        claim.relation_context_identity,
        shared.relation_context.identity,
    )) return error.RelationContextMismatch;
    if (ordered_call_claim.format != provider_order.format_version or
        ordered_call_claim.first_call != descriptor.first_call or
        ordered_call_claim.call_count != descriptor.call_count)
    {
        return error.InvalidProviderOrderClaim;
    }

    replay.channel.mixU32s(&local_suffix_v2_domain_words);
    mixDigest(&replay.channel, manifest.identity);
    mixDigest(&replay.channel, record.identity);
    mixDigest(&replay.channel, plan.call_list_commitment);
    replay.channel.mixU64(claim.shard_index);
    replay.channel.mixU64(descriptor.first_call);
    replay.channel.mixU64(descriptor.call_count);
    replay.channel.mixU64(provider_order.interaction_column_count);
    replay.channel.mixFelts(&claim.claims.sums);
    replay.channel.mixU64(ordered_call_claim.format);
    replay.channel.mixU64(ordered_call_claim.first_call);
    replay.channel.mixU64(ordered_call_claim.call_count);
    replay.channel.mixFelts(&.{ordered_call_claim.terminal});
    return replay.channel;
}

/// Exact caller-local transcript immediately before its Tree2 root.  The
/// caller statement is mixed only after replaying the complete joint Stage-A
/// manifest and the one accepted interaction PoW.
pub fn coreLocalPrefix(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
    shared: SharedRelationAuthorityV1,
    claims: @import("../../air/memory_commitment/merkle_node.zig").Claims,
) !Engine.Channel {
    var replay = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    replay.channel.mixU32s(&core_local_suffix_domain_words);
    mixDigest(&replay.channel, manifest.identity);
    mixDigest(&replay.channel, manifest.core.identity);
    replay.channel.mixU64(manifest.core.log_size);
    replay.channel.mixU64(manifest.core.n_rows);
    replay.channel.mixFelts(&claims.sums);
    return replay.channel;
}

pub const SyntheticClosureV1 = struct {
    manifest_identity: Digest,
    relation_context_identity: Digest,
    core_residual_is_synthetic: bool,
    real_caller_stark_verified: bool,
    production_eligible: bool,
    aggregate: authority.AggregateClosureV1,
};

/// Research-only algebraic checkpoint.  The core residual is deliberately
/// synthesized as `-sum(provider)`; this proves the closure helper and no
/// caller statement, witness, or STARK.
pub fn verifyWithSyntheticCoreResidual(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    manifest: *const JointManifest(Engine),
    shared: SharedRelationAuthorityV1,
    provider_claims: []const authority.ProviderShardClaimV1,
) !SyntheticClosureV1 {
    _ = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    if (provider_claims.len != plan.shards.len)
        return error.ShardClaimCountMismatch;
    var provider_total = QM31.zero();
    for (provider_claims, plan.shards, 0..) |claim, descriptor, index| {
        if (claim.shard_index != index)
            return error.NonCanonicalShardClaimOrder;
        if (!aggregation_hash.eql(claim.plan_identity, plan.identity))
            return error.PlanIdentityMismatch;
        if (!aggregation_hash.eql(
            claim.descriptor_identity,
            descriptor.identity,
        )) return error.ShardClaimDescriptorMismatch;
        if (!aggregation_hash.eql(
            claim.relation_context_identity,
            shared.relation_context.identity,
        )) return error.RelationContextMismatch;
        provider_total = provider_total.add(claim.claims.total());
    }
    const core = authority.CorePoseidonClaimV1{
        .plan_identity = plan.identity,
        .relation_context_identity = shared.relation_context.identity,
        .claim = provider_total.neg(),
    };
    const aggregate = try authority.verifyAggregateClosure(
        plan,
        calls,
        shared.relation_context,
        core,
        provider_claims,
    );
    return .{
        .manifest_identity = manifest.identity,
        .relation_context_identity = shared.relation_context.identity,
        .core_residual_is_synthetic = true,
        .real_caller_stark_verified = false,
        .production_eligible = false,
        .aggregate = aggregate,
    };
}

fn jointPrefix(
    comptime Engine: type,
    pcs_config: core_pcs.PcsConfig,
    manifest: *const JointManifest(Engine),
) Engine.Channel {
    var channel = Engine.Channel{};
    pcs_config.mixInto(&channel);
    channel.mixU32s(&joint_prefix_domain_words);
    mixDigest(&channel, manifest.identity);
    mixDigest(&channel, manifest.plan_identity);
    mixDigest(&channel, manifest.session);
    mixDigest(&channel, manifest.call_list_commitment);
    channel.mixU64(manifest.shard_count);

    channel.mixU64(0); // caller role
    mixDigest(&channel, manifest.core.identity);
    Engine.MerkleChannel.mixRoot(&channel, manifest.core.preprocessed_root);
    Engine.MerkleChannel.mixRoot(&channel, manifest.core.main_root);
    for (manifest.providers) |record| {
        channel.mixU64(1); // provider role
        mixDigest(&channel, record.identity);
        mixDigest(&channel, record.descriptor_identity);
        channel.mixU64(record.shard_index);
        channel.mixU64(record.shard_count);
        channel.mixU64(record.first_call);
        channel.mixU64(record.call_count);
        channel.mixU64(record.expected_log_size);
        Engine.MerkleChannel.mixRoot(&channel, record.preprocessed_root);
        Engine.MerkleChannel.mixRoot(&channel, record.main_root);
    }
    return channel;
}

fn coreStageAIdentity(comptime Engine: type, value: CoreStageARecord(Engine)) Digest {
    var sink = aggregation_hash.HashSink.init(core_stage_a_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.session) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.source)}) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, value.log_size) catch unreachable;
    aggregation_hash.writeU32(&sink, value.n_rows) catch unreachable;
    aggregation_hash.writeU16(&sink, value.main_columns) catch unreachable;
    aggregation_hash.writeU16(&sink, value.interaction_columns) catch unreachable;
    writeRoot(&sink, value.preprocessed_root);
    writeRoot(&sink, value.main_root);
    return sink.finalize();
}

fn providerStageAIdentity(
    comptime Engine: type,
    value: ProviderStageARecord(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(provider_stage_a_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.descriptor_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_index) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    aggregation_hash.writeU64(&sink, value.first_call) catch unreachable;
    aggregation_hash.writeU32(&sink, value.call_count) catch unreachable;
    aggregation_hash.writeU32(&sink, value.expected_log_size) catch unreachable;
    writeRoot(&sink, value.preprocessed_root);
    writeRoot(&sink, value.main_root);
    return sink.finalize();
}

fn manifestIdentity(
    comptime Engine: type,
    manifest: *const JointManifest(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(manifest_domain);
    aggregation_hash.writeU32(&sink, manifest.format) catch unreachable;
    sink.writeAll(&manifest.plan_identity) catch unreachable;
    sink.writeAll(&manifest.session) catch unreachable;
    sink.writeAll(&manifest.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, manifest.shard_count) catch unreachable;
    sink.writeAll(&manifest.core.identity) catch unreachable;
    aggregation_hash.writeU64(&sink, manifest.providers.len) catch unreachable;
    for (manifest.providers) |record|
        sink.writeAll(&record.identity) catch unreachable;
    return sink.finalize();
}

fn writeRoot(sink: anytype, root: anytype) void {
    const bytes = std.mem.asBytes(&root);
    aggregation_hash.writeU32(sink, bytes.len) catch unreachable;
    sink.writeAll(bytes) catch unreachable;
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    }
    channel.mixU32s(&words);
}

fn digestBytes(channel: anytype) Digest {
    const digest = channel.digestBytes();
    comptime if (@TypeOf(digest) != Digest)
        @compileError("joint provider transcript requires a canonical 32-byte channel digest");
    return digest;
}

const joint_prefix_domain_words = [8]u32{
    0x5354_5742, // STWB
    0x4e4d_504a, // NMPJ
    0x544e_494f, // OINT
    format_version,
    joint_interaction_pow_bits,
    @intFromBool(CORE_STAGE_A_IS_SYNTHETIC),
    @intFromBool(ORDERED_CALL_RANGES_ARE_CUSTODY_ONLY),
    relations_mod.DRAW_COUNT,
};

const local_suffix_domain_words = [5]u32{
    0x5354_5742, // STWB
    0x4e4d_504c, // NMPL
    0x4c43_4941, // AICL
    format_version,
    2,
};

const local_suffix_v2_domain_words = [7]u32{
    0x5354_5742, // STWB
    0x4e4d_504c, // NMPL
    0x5244_524f, // ORDR
    format_version,
    2, // provider statement format
    @import("../../air/memory_commitment/poseidon2_air.zig").N_INTERACTION_COLUMNS,
    provider_order.interaction_column_count,
};

const core_local_suffix_domain_words = [5]u32{
    0x5354_5742, // STWB
    0x4e4d_504c, // NMPL
    0x4552_4f43, // CORE
    format_version,
    @import("../../air/memory_commitment/merkle_node.zig").N_SUMS,
};

const core_stage_a_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/base-caller-stage-a/v2\x00";
const provider_stage_a_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/provider-stage-a/v1\x00";
const manifest_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/joint-stage-a-manifest/v2\x00";

fn expectedCoreLogSize(count: usize) u32 {
    const value = std.math.cast(u32, count) orelse return 31;
    return @max(@as(u32, 4), std.math.log2_int_ceil(u32, value));
}
