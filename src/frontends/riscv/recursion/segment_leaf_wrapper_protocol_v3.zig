//! Security profile for the future V3 recursive leaf transaction.
//!
//! A strong outer wrapper cannot repair a weak child proof. The current
//! SegmentV2 development outer proof uses three queries and zero PoW; it is
//! deliberately rejected here. This profile is a new protocol namespace and
//! never reuses the frozen V1 protocol ID or the development V2 key.

const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const frozen = @import("protocol.zig");
const roster = @import("air/segment_leaf_wrapper_roster_v3.zig");
const relation = @import("../air/lang/relation.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 3;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5650_5233; // VPR3
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x5650_4b33; // VPK3
pub const TARGET_SECURITY_BITS: u32 = 120;
pub const PCS_CONFIG = frozen.PCS_CONFIG;
pub const INTERACTION_POW_BITS = frozen.INTERACTION_POW_BITS;
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (PCS_CONFIG.securityBits() < frozen.MIN_CONFIGURED_PCS_BITS or
        INTERACTION_POW_BITS != 10 or roster.COMPONENT_COUNT != 49 or
        PROTOCOL_ID_DOMAIN >= core.fields.m31.Modulus or
        VERIFICATION_KEY_ID_DOMAIN >= core.fields.m31.Modulus)
        @compileError("V3 production security profile or roster drifted");
}

pub const ProofChainConfig = struct {
    native_pcs: core.pcs.PcsConfig,
    native_interaction_pow_bits: u32,
    outer_pcs: core.pcs.PcsConfig,
    outer_interaction_pow_bits: u32,
    wrapper_pcs: core.pcs.PcsConfig,
    wrapper_interaction_pow_bits: u32,

    pub fn validate(self: ProofChainConfig) !void {
        if (!std.meta.eql(self.native_pcs, PCS_CONFIG))
            return error.V3InsecureNativeProof;
        if (self.native_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.V3InsecureNativeInteraction;
        if (!std.meta.eql(self.outer_pcs, PCS_CONFIG))
            return error.V3InsecureChildOuterProof;
        if (self.outer_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.V3InsecureChildOuterInteraction;
        if (!std.meta.eql(self.wrapper_pcs, PCS_CONFIG))
            return error.V3InsecureWrapperProof;
        if (self.wrapper_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.V3InsecureWrapperInteraction;
    }
};

pub const REQUIRED_CHAIN = ProofChainConfig{
    .native_pcs = PCS_CONFIG,
    .native_interaction_pow_bits = INTERACTION_POW_BITS,
    .outer_pcs = PCS_CONFIG,
    .outer_interaction_pow_bits = INTERACTION_POW_BITS,
    .wrapper_pcs = PCS_CONFIG,
    .wrapper_interaction_pow_bits = INTERACTION_POW_BITS,
};

/// The actual presets are configuration facts, not caller-supplied evidence.
/// The native and outer presets currently fail; a production transaction must
/// additionally verify each proof under an independently pinned key.
pub fn requireCurrentImplementation() !void {
    const native = @import("../prover.zig");
    const native_transcript = @import("../air/transcript/protocol.zig");
    const outer = @import("outer_parent_child_admission_profile.zig");
    try (ProofChainConfig{
        .native_pcs = native.SECURE_PCS_CONFIG,
        .native_interaction_pow_bits = native_transcript.INTERACTION_POW_BITS,
        .outer_pcs = outer.OUTER_PCS_CONFIG,
        .outer_interaction_pow_bits = outer.INTERACTION_POW_BITS,
        .wrapper_pcs = PCS_CONFIG,
        .wrapper_interaction_pow_bits = INTERACTION_POW_BITS,
    }).validate();
}

/// Binds a new key namespace to the exact roster, PCS profile, relation
/// registry and field/hash suite. No caller-provided profile is admitted.
pub fn protocolId(plan: *const roster.Plan) !channel.Digest {
    try plan.validate();
    var words: [62]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, FORMAT_VERSION);
    put(&words, &at, roster.COMPONENT_COUNT);
    put(&words, &at, roster.TREE_COUNT);
    put(&words, &at, TARGET_SECURITY_BITS);
    put(&words, &at, frozen.FIELD_ID);
    put(&words, &at, frozen.HASH_SUITE_ID);
    inline for (.{ @as(u32, 1), @as(u32, 2), @as(u32, 3) }) |role| {
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

/// A separate verification-key identity pins the recomputed preprocessed
/// root. Protocol identity alone is never sufficient to admit a proof.
pub fn verificationKeyId(plan: *const roster.Plan, preprocessed_root: channel.Digest) !channel.Digest {
    const protocol_id = try protocolId(plan);
    var words: [16]M31 = undefined;
    for (protocol_id, 0..) |word, index| words[index] = M31.fromCanonical(word);
    for (preprocessed_root, 0..) |word, index| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalV3PreprocessedRoot;
        words[8 + index] = M31.fromCanonical(word);
    }
    return channel.hashCanonicalWords(&words, VERIFICATION_KEY_ID_DOMAIN);
}

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}

fn putSha(words: []M31, at: *usize, digest: [32]u8) void {
    for (0..16) |i| {
        const limb = std.mem.readInt(u16, digest[i * 2 ..][0..2], .little);
        put(words, at, limb);
    }
}

test "V3 production profile rejects the existing development-security V2 outer proof" {
    try REQUIRED_CHAIN.validate();
    try std.testing.expectError(error.V3InsecureNativeProof, requireCurrentImplementation());
    var weak = REQUIRED_CHAIN;
    weak.outer_pcs.fri_config.n_queries = 3;
    try std.testing.expectError(error.V3InsecureChildOuterProof, weak.validate());
    weak = REQUIRED_CHAIN;
    weak.outer_interaction_pow_bits = 0;
    try std.testing.expectError(error.V3InsecureChildOuterInteraction, weak.validate());
    weak = REQUIRED_CHAIN;
    weak.wrapper_interaction_pow_bits = 0;
    try std.testing.expectError(error.V3InsecureWrapperInteraction, weak.validate());
}
