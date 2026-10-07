//! Separate protocol and key namespace for the direct 47-row V3 leaf wrapper.
//!
//! Its first 39 rows verify the native proof in the same STARK transaction.
//! A 39-row outer proof and post-challenge PFD1 are not part of this profile.
const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const frozen = @import("protocol.zig");
const security = @import("segment_v3_production_security_policy.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const relation = @import("../air/lang/relation.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 5;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5650_5235; // VPR5
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x5650_4b35; // VPK5
pub const PCS_CONFIG = security.REQUIRED_PCS_CONFIG;
pub const INTERACTION_POW_BITS = security.REQUIRED_INTERACTION_POW_BITS;
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (roster.COMPONENT_COUNT != 47 or
        PCS_CONFIG.securityBits() < frozen.MIN_CONFIGURED_PCS_BITS or
        INTERACTION_POW_BITS != 10 or
        PROTOCOL_ID_DOMAIN >= core.fields.m31.Modulus or
        VERIFICATION_KEY_ID_DOMAIN >= core.fields.m31.Modulus)
        @compileError("direct leaf security profile or roster drifted");
}

pub const ChainConfig = struct {
    native_pcs: core.pcs.PcsConfig,
    native_interaction_pow_bits: u32,
    wrapper_pcs: core.pcs.PcsConfig,
    wrapper_interaction_pow_bits: u32,

    pub fn validate(self: ChainConfig) !void {
        if (!std.meta.eql(self.native_pcs, PCS_CONFIG) or
            self.native_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.InsecureDirectNativeChild;
        if (!std.meta.eql(self.wrapper_pcs, PCS_CONFIG) or
            self.wrapper_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.InsecureDirectWrapper;
    }
};

pub const REQUIRED_CHAIN = ChainConfig{
    .native_pcs = PCS_CONFIG,
    .native_interaction_pow_bits = INTERACTION_POW_BITS,
    .wrapper_pcs = PCS_CONFIG,
    .wrapper_interaction_pow_bits = INTERACTION_POW_BITS,
};

/// The plan seal includes the exact ProgramV3 schedule and all 47 placements.
/// A proof verifier must also recompute the preprocessed root and admit the
/// native key independently; this function alone is not proof verification.
pub fn protocolId(plan: *const roster.Plan) !channel.Digest {
    try plan.validate();
    var words: [54]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, FORMAT_VERSION);
    put(&words, &at, roster.COMPONENT_COUNT);
    put(&words, &at, roster.TREE_COUNT);
    put(&words, &at, 120);
    put(&words, &at, frozen.FIELD_ID);
    put(&words, &at, frozen.HASH_SUITE_ID);
    inline for (.{ @as(u32, 1), @as(u32, 2) }) |role| {
        put(&words, &at, role);
        put(&words, &at, PCS_CONFIG.pow_bits);
        put(&words, &at, PCS_CONFIG.fri_config.log_blowup_factor);
        put(&words, &at, @intCast(PCS_CONFIG.fri_config.n_queries));
        put(&words, &at, PCS_CONFIG.fri_config.fold_step);
        put(&words, &at, PCS_CONFIG.fri_config.log_last_layer_degree_bound);
        put(&words, &at, 0); // no lifting
        put(&words, &at, INTERACTION_POW_BITS);
    }
    putSha(&words, &at, plan.seal);
    putSha(&words, &at, relation.registryOrderDigest());
    std.debug.assert(at == words.len);
    return channel.hashCanonicalWords(&words, PROTOCOL_ID_DOMAIN);
}

pub fn verificationKeyId(plan: *const roster.Plan, preprocessed_root: channel.Digest) !channel.Digest {
    const protocol_id = try protocolId(plan);
    var words: [16]M31 = undefined;
    for (protocol_id, 0..) |word, index| words[index] = M31.fromCanonical(word);
    for (preprocessed_root, 0..) |word, index| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalDirectPreprocessedRoot;
        words[8 + index] = M31.fromCanonical(word);
    }
    return channel.hashCanonicalWords(&words, VERIFICATION_KEY_ID_DOMAIN);
}

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}

fn putSha(words: []M31, at: *usize, digest: [32]u8) void {
    for (0..16) |index|
        put(words, at, std.mem.readInt(u16, digest[index * 2 ..][0..2], .little));
}

test "direct leaf profile excludes weak native and wrapper configurations" {
    try REQUIRED_CHAIN.validate();
    var changed = REQUIRED_CHAIN;
    changed.native_pcs.fri_config.n_queries = 70;
    try std.testing.expectError(error.InsecureDirectNativeChild, changed.validate());
    changed = REQUIRED_CHAIN;
    changed.wrapper_interaction_pow_bits = 0;
    try std.testing.expectError(error.InsecureDirectWrapper, changed.validate());
}
