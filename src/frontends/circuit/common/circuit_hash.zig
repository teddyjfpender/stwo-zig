//! The circuit hash: `H(log_blowup_factor || component_log_sizes ||
//! preprocessed_root)`, the identity of a circuit under a PCS config.
//!
//! Ports `config_words` of `crates/circuit_verifier/src/circuit_hash.rs` and
//! `compute_circuit_hash` of `crates/circuit_prover/src/circuit_hash.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `configWords` is the single
//! definition of the 12-byte config layout: the host hash here, the
//! in-circuit hash (`blake2s_u32s` over the same words as constants), the
//! prover transcript (M7) and the registry check all call it.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("component_list.zig");

const PerComponent = component_list.PerComponent;
const ChannelProfile = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;

/// The hash the circuit hash is taken with: the word hash of the Merkle
/// hasher circuit proofs are committed with (`Blake2sMerkleHasher`, plain
/// Blake2s).
pub const Hasher = ChannelProfile.Hasher;
pub const Blake2sHash = core.vcs.blake2_hash.Blake2sHash;

/// Bytes of `config_words`: `log_blowup_factor`, then one byte per
/// component log size.
pub const CONFIG_N_BYTES: usize = 1 + component_list.N_COMPONENTS;
pub const CONFIG_N_WORDS: usize = CONFIG_N_BYTES / 4;

comptime {
    // Packed 4 bytes per u32 with no padding.
    std.debug.assert(CONFIG_N_BYTES % 4 == 0);
}

pub const Error = error{ValueDoesNotFitInByte};

/// `config_words`: byte 0 is `log_blowup_factor`, then each component's log
/// size in `ComponentList` order, packed little-endian into u32 words.
pub fn configWords(log_blowup_factor: u32, component_log_sizes: PerComponent(u32)) Error![CONFIG_N_WORDS]u32 {
    var bytes: [CONFIG_N_BYTES]u8 = undefined;
    bytes[0] = std.math.cast(u8, log_blowup_factor) orelse return error.ValueDoesNotFitInByte;
    for (component_log_sizes.toArray(), bytes[1..]) |size, *byte| {
        byte.* = std.math.cast(u8, size) orelse return error.ValueDoesNotFitInByte;
    }
    return leU32sFromBytes(CONFIG_N_WORDS, &bytes);
}

/// `compute_circuit_hash::<Blake2sMerkleHasher>`: one Blake2s over
/// `LE(config_words) || preprocessed_root`.
pub fn hostCircuitHash(
    component_log_sizes: PerComponent(u32),
    log_blowup_factor: u32,
    preprocessed_root: Blake2sHash,
) Error!Blake2sHash {
    const words = try configWords(log_blowup_factor, component_log_sizes);
    return Hasher.hashU32sFollowedByDigest(&words, preprocessed_root);
}

/// `compute_circuit_hash` of `crates/circuit_verifier/src/circuit_hash.rs`:
/// the same hash in-circuit, the config words interned as `u32` constants in
/// order, then `blake2s_u32s(config_words || preprocessed_root)`.
pub fn circuitHash(
    comptime V: type,
    ctx: *builder.Context(V),
    component_log_sizes: PerComponent(u32),
    log_blowup_factor: u32,
    preprocessed_root: builder.blake.HashValue(builder.Var),
) (Error || builder.context.Error)!builder.blake.HashValue(builder.Var) {
    const U32Wrapper = builder.wrappers.U32Wrapper;
    var message: [CONFIG_N_WORDS + builder.blake.digest_n_words]U32Wrapper(builder.Var) = undefined;
    for (try configWords(log_blowup_factor, component_log_sizes), message[0..CONFIG_N_WORDS]) |word, *wire| {
        wire.* = try builder.wrappers.constU32(V, ctx, word);
    }
    @memcpy(message[CONFIG_N_WORDS..], &preprocessed_root.words);
    return builder.blake.blake2sU32s(V, ctx, &message, 4 * message.len);
}

/// `le_u32s_from_bytes`: consecutive little-endian u32 words.
pub fn leU32sFromBytes(comptime n_words: usize, bytes: *const [4 * n_words]u8) [n_words]u32 {
    var words: [n_words]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, bytes[4 * index ..][0..4], .little);
    return words;
}

/// The inverse of `leU32sFromBytes`, e.g. digest words back into a
/// `Blake2sHash`.
pub fn bytesFromLeU32s(comptime n_words: usize, words: [n_words]u32) [4 * n_words]u8 {
    var bytes: [4 * n_words]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[4 * index ..][0..4], word, .little);
    return bytes;
}

test "circuit hash: compute_circuit_hash_matches_golden" {
    // crates/circuit_verifier/src/circuit_hash_test.rs: the in-circuit hash of
    // these sizes, blowup 3 and root words 0..8 is the host hash.
    const sizes = PerComponent(u32){
        .eq = 17,
        .qm31_ops = 21,
        .triple_xor = 17,
        .m_31_to_u_32 = 18,
        .blake_g_gate = 20,
        .verify_bitwise_xor_8 = 16,
        .verify_bitwise_xor_12 = 20,
        .verify_bitwise_xor_4 = 8,
        .verify_bitwise_xor_7 = 14,
        .verify_bitwise_xor_9 = 18,
        .range_check_16 = 16,
    };
    const root = bytesFromLeU32s(8, .{ 0, 1, 2, 3, 4, 5, 6, 7 });
    const hash = try hostCircuitHash(sizes, 3, root);
    try std.testing.expectEqual([8]u32{
        0xa8810641, 0x52391285, 0x90b37fd2, 0x905b887a,
        0x7db7dc81, 0xa7c3a731, 0xd0d46b34, 0x8fa6a471,
    }, leU32sFromBytes(8, &hash));
}

test "circuit hash: config words reject values wider than a byte" {
    var sizes = PerComponent(u32).fromArray(.{0} ** component_list.N_COMPONENTS);
    try std.testing.expectError(error.ValueDoesNotFitInByte, configWords(256, sizes));
    sizes.range_check_16 = 300;
    try std.testing.expectError(error.ValueDoesNotFitInByte, configWords(1, sizes));
}
