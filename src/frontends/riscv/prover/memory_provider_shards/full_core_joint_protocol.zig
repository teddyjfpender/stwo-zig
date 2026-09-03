//! Additive full-RISC-V + N provider Stage-A transcript authority.
//!
//! The ordinary RISC-V transcript remains unchanged.  This sibling binds the
//! actual full-core Tree0/Tree1 roots and every provider shard Tree0/Tree1 root
//! after the ordinary public statement, before one interaction PoW and one
//! shared relation draw.  The current full-core proof still retains its native
//! Poseidon provider, so this is a correctness bridge rather than the bounded
//! omit/recompute production owner.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const core_pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const transcript = @import("../../air/transcript/mod.zig");
const statement_mod = @import("../../air/statement.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const proof_transcript = @import("../../proof_transcript.zig");
const interaction_witness_work = @import("../interaction_witness_work.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const authority = @import("authority.zig");
const joint = @import("joint_protocol.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");

pub const format_version: u32 = 1;
pub const interaction_pow_bits: u32 = transcript.INTERACTION_POW_BITS;
pub const NATIVE_PROVIDER_RETAINED_CORRECTNESS_BRIDGE = true;
pub const OMIT_RECOMPUTE_OWNER_IMPLEMENTED = false;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const Digest = authority.Digest;

/// Borrowed, sealed provider Stage-A authority.  The earlier tiny-caller
/// manifest remains useful for producing these records, but its synthetic
/// caller roots and manifest identity are deliberately excluded here.
pub fn ProviderStageASource(comptime Engine: type) type {
    return struct {
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        provider_manifest: *const joint.JointManifest(Engine),
        identity: Digest,

        const Self = @This();

        pub fn init(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_manifest: *const joint.JointManifest(Engine),
        ) !Self {
            try provider_manifest.validate(plan, calls);
            var result = Self{
                .plan = plan,
                .calls = calls,
                .provider_manifest = provider_manifest,
                .identity = undefined,
            };
            result.identity = sourceIdentity(Engine, &result);
            return result;
        }

        pub fn validate(self: *const Self) !void {
            try self.provider_manifest.validate(self.plan, self.calls);
            if (self.provider_manifest.providers.len != self.plan.shards.len or
                !aggregation_hash.eql(self.identity, sourceIdentity(Engine, self)))
            {
                return error.InvalidFullCoreProviderSource;
            }
        }
    };
}

pub fn FullCoreManifestV1(comptime Engine: type) type {
    return struct {
        format: u32,
        source_identity: Digest,
        plan_identity: Digest,
        session: Digest,
        call_list_commitment: Digest,
        core_statement_identity: Digest,
        core_preprocessed_root: Engine.Hasher.Hash,
        core_main_root: Engine.Hasher.Hash,
        providers: []const joint.ProviderStageARecord(Engine),
        identity: Digest,

        const Self = @This();

        pub fn create(
            source: *const ProviderStageASource(Engine),
            statement: *const statement_mod.RiscVStatement,
            core_preprocessed_root: Engine.Hasher.Hash,
            core_main_root: Engine.Hasher.Hash,
        ) !Self {
            try source.validate();
            var result = Self{
                .format = format_version,
                .source_identity = source.identity,
                .plan_identity = source.plan.identity,
                .session = source.plan.session,
                .call_list_commitment = source.plan.call_list_commitment,
                .core_statement_identity = statementTranscriptIdentity(statement),
                .core_preprocessed_root = core_preprocessed_root,
                .core_main_root = core_main_root,
                .providers = source.provider_manifest.providers,
                .identity = undefined,
            };
            result.identity = manifestIdentity(Engine, &result);
            try result.validate(source, statement);
            return result;
        }

        pub fn validate(
            self: *const Self,
            source: *const ProviderStageASource(Engine),
            statement: *const statement_mod.RiscVStatement,
        ) !void {
            try source.validate();
            if (self.format != format_version or
                !aggregation_hash.eql(self.source_identity, source.identity) or
                !aggregation_hash.eql(self.plan_identity, source.plan.identity) or
                !aggregation_hash.eql(self.session, source.plan.session) or
                !aggregation_hash.eql(
                    self.call_list_commitment,
                    source.plan.call_list_commitment,
                ) or !aggregation_hash.eql(
                self.core_statement_identity,
                statementTranscriptIdentity(statement),
            ) or self.providers.len != source.provider_manifest.providers.len) {
                return error.InvalidFullCoreManifest;
            }
            for (self.providers, source.provider_manifest.providers) |actual, expected| {
                if (!std.meta.eql(actual, expected))
                    return error.InvalidFullCoreManifest;
            }
            if (!aggregation_hash.eql(self.identity, manifestIdentity(Engine, self)))
                return error.FullCoreManifestIdentityMismatch;
        }

        /// Mixed only after the ordinary RISC-V main claim and shard manifest.
        pub fn mixInto(self: *const Self, channel: anytype) void {
            channel.mixU32s(&manifest_domain_words);
            mixDigest(channel, self.identity);
            mixDigest(channel, self.source_identity);
            mixDigest(channel, self.plan_identity);
            mixDigest(channel, self.session);
            mixDigest(channel, self.call_list_commitment);
            mixDigest(channel, self.core_statement_identity);
            Engine.MerkleChannel.mixRoot(channel, self.core_preprocessed_root);
            Engine.MerkleChannel.mixRoot(channel, self.core_main_root);
            channel.mixU64(self.providers.len);
            for (self.providers) |record| {
                mixDigest(channel, record.identity);
                mixDigest(channel, record.descriptor_identity);
                channel.mixU64(record.shard_index);
                channel.mixU64(record.shard_count);
                channel.mixU64(record.first_call);
                channel.mixU64(record.call_count);
                channel.mixU64(record.expected_log_size);
                Engine.MerkleChannel.mixRoot(channel, record.preprocessed_root);
                Engine.MerkleChannel.mixRoot(channel, record.main_root);
            }
        }
    };
}

pub const SharedRelationAuthorityV1 = struct {
    format: u32,
    manifest_identity: Digest,
    interaction_pow_bits: u32,
    interaction_pow: u64,
    relation_context: authority.PoseidonRelationContextV1,

    pub fn validate(self: @This(), manifest_identity: Digest) !void {
        if (self.format != format_version or
            self.interaction_pow_bits != interaction_pow_bits or
            !aggregation_hash.eql(self.manifest_identity, manifest_identity))
        {
            return error.InvalidFullCoreSharedAuthority;
        }
    }
};

pub fn Replay(comptime Engine: type) type {
    return struct {
        channel: Engine.Channel,
        relations: @import("../../air/relation_challenges.zig").Relations,
        authority_value: SharedRelationAuthorityV1,
    };
}

/// Reconstructs the full core commitment prefix and rejects the joint nonce
/// before deriving any relation used by a provider proof or closure receipt.
pub fn replaySharedTranscript(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: *const ProviderStageASource(Engine),
    statement: *const statement_mod.RiscVStatement,
    manifest: *const FullCoreManifestV1(Engine),
    expected: SharedRelationAuthorityV1,
) !Replay(Engine) {
    try manifest.validate(source, statement);
    try expected.validate(manifest.identity);
    var channel = Engine.Channel{};
    try bindCorePrefix(Engine, pcs_config, statement, &channel);
    Engine.MerkleChannel.mixRoot(&channel, manifest.core_preprocessed_root);
    Engine.MerkleChannel.mixRoot(&channel, manifest.core_main_root);
    const relations = try proof_transcript.verifyToRelationsWithExtension(
        allocator,
        &channel,
        statement,
        expected.interaction_pow,
        manifest,
    );
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        source.plan.session,
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

/// Full-core V2 provider-local prefix. It replays the exact full-core Stage-A
/// manifest and shared draw, then binds the shard/range/order endpoint before
/// the provider's twelve-column Tree2 commitment.
pub fn providerLocalPrefixV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: *const ProviderStageASource(Engine),
    statement: *const statement_mod.RiscVStatement,
    manifest: *const FullCoreManifestV1(Engine),
    shared: SharedRelationAuthorityV1,
    claim: authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
) !Engine.Channel {
    var replay = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        source,
        statement,
        manifest,
        shared,
    );
    const index = std.math.cast(usize, claim.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= source.plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = source.plan.shards[index];
    const record = manifest.providers[index];
    if (!aggregation_hash.eql(claim.plan_identity, source.plan.identity))
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

    replay.channel.mixU32s(&provider_local_v2_domain_words);
    mixDigest(&replay.channel, manifest.identity);
    mixDigest(&replay.channel, record.identity);
    mixDigest(&replay.channel, source.plan.call_list_commitment);
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

/// Stable-address output slot used by the additive orchestration route.
pub fn ProveExtension(comptime Engine: type) type {
    return struct {
        source: *const ProviderStageASource(Engine),
        manifest_out: *FullCoreManifestV1(Engine),
        shared_out: *SharedRelationAuthorityV1,

        pub fn drawChallenges(
            self: @This(),
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            statement: *const statement_mod.RiscVStatement,
            recorder: ?*@import("stwo_prover_api").stage_profile.Recorder,
        ) !proof_transcript.ProverRelations {
            try self.source.validate();
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 2) return error.InvalidFullCoreStageATreeCount;
            self.manifest_out.* = try FullCoreManifestV1(Engine).create(
                self.source,
                statement,
                roots.items[0],
                roots.items[1],
            );
            var work_authority = try interaction_witness_work.plan(recorder);
            const result = if (work_authority) |*work|
                try proof_transcript.proveToRelationsWithExtensionAndWorkReceipt(
                    allocator,
                    channel,
                    statement,
                    self.manifest_out,
                    work,
                )
            else
                try proof_transcript.proveToRelationsWithExtension(
                    allocator,
                    channel,
                    statement,
                    self.manifest_out,
                );
            self.shared_out.* = .{
                .format = format_version,
                .manifest_identity = self.manifest_out.identity,
                .interaction_pow_bits = interaction_pow_bits,
                .interaction_pow = result.interaction_pow,
                .relation_context = try authority.PoseidonRelationContextV1.canonical(
                    self.source.plan.session,
                    result.relations.poseidon2.z,
                    result.relations.poseidon2.alpha,
                ),
            };
            return result;
        }
    };
}

pub const FreshFullCoreResidualV1 = struct {
    format: u32,
    plan_identity: Digest,
    manifest_identity: Digest,
    core_statement_identity: Digest,
    relation_context_identity: Digest,
    proof_commitments_identity: Digest,
    fresh_core_stark_verified: bool,
    global_relation_closure_verified: bool,
    native_provider_retained: bool,
    poseidon2_residual: QM31,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != format_version or !self.fresh_core_stark_verified or
            !self.global_relation_closure_verified or
            !self.native_provider_retained or self.production_eligible or
            !aggregation_hash.eql(self.identity, freshCoreResidualIdentity(self)))
        {
            return error.InvalidFreshFullCoreResidual;
        }
    }

    pub fn native(self: @This()) authority.CorePoseidonClaimV1 {
        return .{
            .plan_identity = self.plan_identity,
            .relation_context_identity = self.relation_context_identity,
            .claim = self.poseidon2_residual,
        };
    }
};

/// Freshly verified full-core + ordered-provider closure. The cryptographic
/// relation is genuine, while production eligibility remains false until the
/// native full-core provider is omitted/recomputed under a bounded owner.
pub const VerifiedFullCoreJointClosureV1 = struct {
    format: u32,
    plan_identity: Digest,
    manifest_identity: Digest,
    relation_context_identity: Digest,
    core_claim_identity: Digest,
    ordered_provider_claims_identity: Digest,
    shard_count: u32,
    core_claim: QM31,
    provider_claim: QM31,
    closed_sum: QM31,
    full_core_freshly_verified: bool,
    every_provider_freshly_verified: bool,
    every_ordered_call_air_verified: bool,
    complete_ordered_coverage: bool,
    one_shared_relation_context: bool,
    native_provider_retained: bool,
    omit_recompute_owner_verified: bool,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != proof_authority.provider_format_version_v2 or
            self.shard_count == 0 or !self.full_core_freshly_verified or
            !self.every_provider_freshly_verified or
            !self.every_ordered_call_air_verified or
            !self.complete_ordered_coverage or
            !self.one_shared_relation_context or
            !self.native_provider_retained or
            self.omit_recompute_owner_verified or self.production_eligible or
            !self.closed_sum.isZero() or
            !aggregation_hash.eql(self.identity, fullClosureIdentity(self)))
        {
            return error.InvalidVerifiedFullCoreJointClosure;
        }
    }
};

pub fn freshCoreResidualIdentity(value: FreshFullCoreResidualV1) Digest {
    var sink = aggregation_hash.HashSink.init(fresh_core_residual_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.core_statement_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.fresh_core_stark_verified),
        @intFromBool(value.global_relation_closure_verified),
        @intFromBool(value.native_provider_retained),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    hashQm31(&sink, value.poseidon2_residual);
    return sink.finalize();
}

pub fn fullClosureIdentity(value: VerifiedFullCoreJointClosureV1) Digest {
    var sink = aggregation_hash.HashSink.init(full_closure_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.core_claim_identity) catch unreachable;
    sink.writeAll(&value.ordered_provider_claims_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    hashQm31(&sink, value.core_claim);
    hashQm31(&sink, value.provider_claim);
    hashQm31(&sink, value.closed_sum);
    sink.writeAll(&.{
        @intFromBool(value.full_core_freshly_verified),
        @intFromBool(value.every_provider_freshly_verified),
        @intFromBool(value.every_ordered_call_air_verified),
        @intFromBool(value.complete_ordered_coverage),
        @intFromBool(value.one_shared_relation_context),
        @intFromBool(value.native_provider_retained),
        @intFromBool(value.omit_recompute_owner_verified),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

pub fn statementTranscriptIdentity(statement: *const statement_mod.RiscVStatement) Digest {
    var channel = Blake2sChannel{};
    const main_claim = statement.canonicalMainClaim();
    main_claim.mixInto(&channel);
    statement.mixShardManifest(&channel);
    return channel.digestBytes();
}

fn bindCorePrefix(
    comptime Engine: type,
    pcs_config: core_pcs.PcsConfig,
    statement: *const statement_mod.RiscVStatement,
    channel: *Engine.Channel,
) !void {
    if (comptime @hasDecl(Engine.Channel, "bindRiscVTranscript")) {
        try channel.bindRiscVTranscript(pcs_config, &statement.public_data);
    } else {
        pcs_config.mixInto(channel);
        statement.public_data.mixInto(channel);
    }
}

fn sourceIdentity(
    comptime Engine: type,
    source: *const ProviderStageASource(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(provider_source_domain);
    aggregation_hash.writeU32(&sink, format_version) catch unreachable;
    sink.writeAll(&source.plan.identity) catch unreachable;
    sink.writeAll(&source.plan.session) catch unreachable;
    sink.writeAll(&source.plan.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        @intCast(source.provider_manifest.providers.len),
    ) catch unreachable;
    for (source.provider_manifest.providers) |record|
        sink.writeAll(&record.identity) catch unreachable;
    return sink.finalize();
}

fn manifestIdentity(
    comptime Engine: type,
    manifest: *const FullCoreManifestV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(full_manifest_domain);
    aggregation_hash.writeU32(&sink, manifest.format) catch unreachable;
    sink.writeAll(&manifest.source_identity) catch unreachable;
    sink.writeAll(&manifest.plan_identity) catch unreachable;
    sink.writeAll(&manifest.session) catch unreachable;
    sink.writeAll(&manifest.call_list_commitment) catch unreachable;
    sink.writeAll(&manifest.core_statement_identity) catch unreachable;
    writeRoot(&sink, manifest.core_preprocessed_root);
    writeRoot(&sink, manifest.core_main_root);
    aggregation_hash.writeU32(&sink, @intCast(manifest.providers.len)) catch unreachable;
    for (manifest.providers) |record| sink.writeAll(&record.identity) catch unreachable;
    return sink.finalize();
}

fn writeRoot(sink: anytype, root: anytype) void {
    const bytes = std.mem.asBytes(&root);
    aggregation_hash.writeU32(sink, bytes.len) catch unreachable;
    sink.writeAll(bytes) catch unreachable;
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn hashQm31(sink: anytype, value: QM31) void {
    for (value.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

const manifest_domain_words = [7]u32{
    0x5354_5742, // STWB
    0x4e4d_5046, // NMPF
    0x4552_4f43, // CORE
    format_version,
    interaction_pow_bits,
    @intFromBool(NATIVE_PROVIDER_RETAINED_CORRECTNESS_BRIDGE),
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};
const provider_source_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/full-core-provider-source/v1\x00";
const full_manifest_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/full-core-stage-a-manifest/v1\x00";
const fresh_core_residual_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-full-core-residual/v1\x00";
const full_closure_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/full-core-joint-closure/v1\x00";
const provider_local_v2_domain_words = [8]u32{
    0x5354_5742, // STWB
    0x4e4d_5046, // NMPF
    0x4643_5032, // FCP2
    format_version,
    proof_authority.provider_format_version_v2,
    poseidon2_air.N_INTERACTION_COLUMNS,
    provider_order.interaction_column_count,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};
