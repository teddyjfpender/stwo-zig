//! Versioned production-security profile for the 39-row leaf outer child.
//! Its key is distinct from the development V2 publication/key namespace.

const std = @import("std");
const core = @import("stwo_core");
const frozen = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 3;
pub const PCS_CONFIG = frozen.PCS_CONFIG;
pub const INTERACTION_POW_BITS = frozen.INTERACTION_POW_BITS;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x4f33_5052; // O3PR
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x4f33_564b; // O3VK
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (PCS_CONFIG.pow_bits != 16 or PCS_CONFIG.fri_config.n_queries != 193 or
        PCS_CONFIG.fri_config.fold_step != 4 or INTERACTION_POW_BITS != 10 or
        manifest_mod.COMPONENT_COUNT != 39)
        @compileError("V3 outer security or 39-row roster drifted");
}

/// This binds only the profile and AIR manifest. The verifier independently
/// recomputes the preprocessed root and admits the actual STARK proof.
pub fn protocolId(manifest: *const manifest_mod.Manifest) !channel.Digest {
    try manifest.validate();
    var words: [28]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, FORMAT_VERSION);
    put(&words, &at, manifest_mod.COMPONENT_COUNT);
    put(&words, &at, frozen.FIELD_ID);
    put(&words, &at, frozen.HASH_SUITE_ID);
    put(&words, &at, PCS_CONFIG.pow_bits);
    put(&words, &at, @intCast(PCS_CONFIG.fri_config.n_queries));
    put(&words, &at, PCS_CONFIG.fri_config.fold_step);
    put(&words, &at, PCS_CONFIG.fri_config.log_blowup_factor);
    put(&words, &at, PCS_CONFIG.fri_config.log_last_layer_degree_bound);
    put(&words, &at, INTERACTION_POW_BITS);
    put(&words, &at, 0); // no lifting
    put(&words, &at, manifest_mod.TREE_COUNT);
    for (0..16) |i|
        put(&words, &at, std.mem.readInt(u16, manifest.seal[i * 2 ..][0..2], .little));
    std.debug.assert(at == words.len);
    return channel.hashCanonicalWords(&words, PROTOCOL_ID_DOMAIN);
}

pub fn verificationKeyId(
    manifest: *const manifest_mod.Manifest,
    preprocessed_root: channel.Digest,
) !channel.Digest {
    const protocol_id = try protocolId(manifest);
    var words: [16]M31 = undefined;
    for (protocol_id, 0..) |word, i| words[i] = M31.fromCanonical(word);
    for (preprocessed_root, 0..) |word, i| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalPreprocessedRoot;
        words[8 + i] = M31.fromCanonical(word);
    }
    return channel.hashCanonicalWords(&words, VERIFICATION_KEY_ID_DOMAIN);
}

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}
