//! One shared-relation constructor, corpus readmission and transcript frame authority.
const std = @import("std");
const aggregation_hash = @import("stwo_riscv_memory").aggregation.hash;
const poseidon2_air = @import("stwo_riscv_memory").air.poseidon2_air;
const ethereum_transcript = @import("../guest_precompile/ethereum_transcript.zig");
const authority = @import("stwo_riscv_memory").prover.authority;
const interaction_pow_bits = @import("stwo_riscv_rv32").air.transcript.api.INTERACTION_POW_BITS;
const Extension = @import("ethereum_omit_extension.zig").Extension;
const ACTIVATES_PRODUCTION_PROOF = @import("ethereum_omit_protocol.zig").ACTIVATES_PRODUCTION_PROOF;
const Digest = @import("ethereum_omit_protocol.zig").Digest;
const FRESH_PROVIDER_CLOSURE_REQUIRED = @import("ethereum_omit_protocol.zig").FRESH_PROVIDER_CLOSURE_REQUIRED;
const OMIT_RECOMPUTE_CORE_IMPLEMENTED = @import("ethereum_omit_protocol.zig").OMIT_RECOMPUTE_CORE_IMPLEMENTED;
const ProviderStageAManifestV1 = @import("ethereum_omit_protocol.zig").ProviderStageAManifestV1;
const SharedRelationAuthorityV1 = @import("ethereum_omit_protocol.zig").SharedRelationAuthorityV1;
const format_version = @import("ethereum_omit_protocol.zig").format_version;

pub fn admitCorpus(
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
) !void {
    if (validated) |token| return token.validateBorrowed(plan, calls);
    return plan.validate(calls);
}

pub fn Frame(comptime Engine: type) type {
    return struct {
        projection_identity: Digest,
        provider_stage_a: *const ProviderStageAManifestV1(Engine),
        tree0_root: Engine.Hasher.Hash,
        tree1_root: Engine.Hasher.Hash,

        pub fn mixInto(self: @This(), channel: anytype) void {
            channel.mixU32s(&frame_domain_words);
            mixDigest(channel, self.projection_identity);
            mixDigest(channel, self.provider_stage_a.identity);
            mixDigest(channel, self.provider_stage_a.plan_identity);
            mixDigest(channel, self.provider_stage_a.session);
            mixDigest(channel, self.provider_stage_a.call_list_commitment);
            channel.mixU64(self.provider_stage_a.providers.len);
            for (self.provider_stage_a.providers) |record| {
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
            Engine.MerkleChannel.mixRoot(channel, self.tree0_root);
            Engine.MerkleChannel.mixRoot(channel, self.tree1_root);
        }
    };
}

pub fn makeSharedRelation(
    comptime Engine: type,
    extension: *const Extension(Engine),
    tree0_root: Engine.Hasher.Hash,
    tree1_root: Engine.Hasher.Hash,
    prefix: ethereum_transcript.Prefix,
) !SharedRelationAuthorityV1(Engine) {
    return makeSharedRelationFromRelations(
        Engine,
        extension,
        tree0_root,
        tree1_root,
        prefix.interaction_pow,
        prefix.relations,
    );
}

pub fn makeSharedRelationFromRelations(
    comptime Engine: type,
    extension: *const Extension(Engine),
    tree0_root: Engine.Hasher.Hash,
    tree1_root: Engine.Hasher.Hash,
    interaction_pow: u64,
    relations: ethereum_transcript.Relations,
) !SharedRelationAuthorityV1(Engine) {
    var result = SharedRelationAuthorityV1(Engine){
        .format = format_version,
        .plan_identity = extension.plan.identity,
        .manifest_identity = extension.provider_stage_a.identity,
        .projection_identity = extension.projection.identity,
        .tree0_root = tree0_root,
        .tree1_root = tree1_root,
        .interaction_pow_bits = interaction_pow_bits,
        .interaction_pow = interaction_pow,
        .relation_context = try authority.PoseidonRelationContextV1.canonical(
            extension.plan.session,
            relations.base.poseidon2.z,
            relations.base.poseidon2.alpha,
        ),
        .identity = undefined,
    };
    result.identity = sharedRelationIdentity(Engine, result);
    try result.validate(
        extension.plan,
        extension.provider_stage_a,
        &extension.projection,
    );
    return result;
}

pub fn sharedRelationIdentity(
    comptime Engine: type,
    value: SharedRelationAuthorityV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(shared_relation_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.projection_identity) catch unreachable;
    writeRoot(&sink, value.tree0_root);
    writeRoot(&sink, value.tree1_root);
    aggregation_hash.writeU32(&sink, value.interaction_pow_bits) catch unreachable;
    aggregation_hash.writeU64(&sink, value.interaction_pow) catch unreachable;
    sink.writeAll(&value.relation_context.identity) catch unreachable;
    return sink.finalize();
}

pub fn writeRoot(sink: anytype, root: anytype) void {
    const bytes = std.mem.asBytes(&root);
    aggregation_hash.writeU32(sink, bytes.len) catch unreachable;
    sink.writeAll(bytes) catch unreachable;
}

pub fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

pub const shared_relation_domain =
    "stwo-zig/riscv/ethereum/native-provider-shared-relation/v1\x00";

pub const frame_domain_words = [7]u32{
    0x5354_5742, // STWB
    0x4d4f_4854, // THOM
    0x4d45_5254, // TREM
    format_version,
    @intFromBool(OMIT_RECOMPUTE_CORE_IMPLEMENTED),
    @intFromBool(FRESH_PROVIDER_CLOSURE_REQUIRED),
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};
pub const provider_local_v2_domain_words = [4]u32{
    0x5354_5745, // STWE
    0x5052_5632, // PRV2
    format_version,
    12,
};
