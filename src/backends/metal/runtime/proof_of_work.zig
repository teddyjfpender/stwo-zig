//! Deterministic Metal nonce searches for BLAKE2s, BLAKE3 and Poseidon2-M31.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;

const BLAKE2S_IV = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

fn mix(
    state: *[16]u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    first: u32,
    second: u32,
) void {
    state[a] +%= state[b] +% first;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 12);
    state[a] +%= state[b] +% second;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 7);
}

/// State after round zero's four nonce-independent column mixes. The 40-byte
/// PoW message places its fixed 32-byte prefix in words 0..7 and its nonce in
/// words 8..9, so this prefix-only work is identical for every GPU candidate.
fn roundZeroColumnState(prefix_words: *const [8]u32) [16]u32 {
    var hash = BLAKE2S_IV;
    hash[0] ^= 0x01010020;
    var state: [16]u32 = undefined;
    @memcpy(state[0..8], hash[0..]);
    @memcpy(state[8..16], BLAKE2S_IV[0..]);
    state[12] ^= 40;
    state[14] ^= std.math.maxInt(u32);
    mix(&state, 0, 4, 8, 12, prefix_words[0], prefix_words[1]);
    mix(&state, 1, 5, 9, 13, prefix_words[2], prefix_words[3]);
    mix(&state, 2, 6, 10, 14, prefix_words[4], prefix_words[5]);
    mix(&state, 3, 7, 11, 15, prefix_words[6], prefix_words[7]);
    return state;
}

pub const Result = struct {
    nonce: u64,
    gpu_milliseconds: f64,
    dispatch_count: u32,
};

/// Canonical Stwo BLAKE2s nonce (`SimdBackend` lattice order, see
/// `core/channel/blake2s_pow_order.zig`) for the plain `Blake2sChannel`.
/// Stwo defines it only up to 32 bits.
pub fn grindBlake2sProofOfWork(
    self: *Runtime,
    prefix_words: *const [8]u32,
    pow_bits: u32,
) MetalError!Result {
    return grindBlake2sLattice(self, false, prefix_words, pow_bits);
}

/// The same search for `Blake2sM31Channel`, whose hash output words are
/// reduced mod P before the zeros are counted.
pub fn grindBlake2sM31ProofOfWork(
    self: *Runtime,
    prefix_words: *const [8]u32,
    pow_bits: u32,
) MetalError!Result {
    return grindBlake2sLattice(self, true, prefix_words, pow_bits);
}

fn grindBlake2sLattice(
    self: *Runtime,
    m31_output: bool,
    prefix_words: *const [8]u32,
    pow_bits: u32,
) MetalError!Result {
    if (pow_bits == 0 or pow_bits > 32) return MetalError.ProofOfWorkFailed;
    const round_zero_columns = roundZeroColumnState(prefix_words);
    var result: Result = .{
        .nonce = 0,
        .gpu_milliseconds = 0,
        .dispatch_count = 0,
    };
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_blake2s_pow_search(
        self.handle,
        m31_output,
        prefix_words,
        &round_zero_columns,
        pow_bits,
        &result.nonce,
        &result.gpu_milliseconds,
        &result.dispatch_count,
        &message,
        message.len,
    )) {
        std.log.err("Metal proof-of-work search failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.ProofOfWorkFailed;
    }
    if (result.dispatch_count == 0) return MetalError.ProofOfWorkFailed;
    return result;
}

/// Lowest valid nonce for the Poseidon2-M31 recursion channel.  `prefix_state`
/// is the nonce-independent sponge state exposed by the channel
/// (`Channel.powPrefixState`); the device replays the exact `mixU64` and
/// `drawU32s` permutations per candidate.  Callers must still verify the
/// returned nonce through the host channel.
fn grindChannelProofOfWork(
    comptime blake3: bool,
    self: *Runtime,
    prefix_state: *const [16]u32,
    pow_bits: u32,
) MetalError!Result {
    if (pow_bits == 0 or pow_bits > 32) return MetalError.ProofOfWorkFailed;
    var result: Result = .{ .nonce = 0, .gpu_milliseconds = 0, .dispatch_count = 0 };
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const search = if (blake3) ffi.stwo_zig_metal_blake3_pow_search else ffi.stwo_zig_metal_poseidon2_channel_pow_search;
    if (!search(
        self.handle,
        prefix_state,
        pow_bits,
        &result.nonce,
        &result.gpu_milliseconds,
        &result.dispatch_count,
        &message,
        message.len,
    )) {
        std.log.err("Metal channel proof-of-work search failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.ProofOfWorkFailed;
    }
    if (result.dispatch_count == 0) return MetalError.ProofOfWorkFailed;
    return result;
}

pub fn grindPoseidon2ChannelProofOfWork(self: *Runtime, prefix: *const [16]u32, bits: u32) MetalError!Result {
    return grindChannelProofOfWork(false, self, prefix, bits);
}

pub fn grindBlake3ProofOfWork(self: *Runtime, prefix: *const [16]u32, bits: u32) MetalError!Result {
    return grindChannelProofOfWork(true, self, prefix, bits);
}
