//! SHA-256 compression semantics shared by host execution and witness generation.
//! Arbitrary chaining state plus one64-byte block; padding belongs to the caller.
//! This pure primitive does not itself authorize a guest opcode or prove a call.
const std = @import("std");
pub const block_bytes: usize = 64;
pub const round_count: usize = 64;
pub const state_word_count: usize = 8;
pub const schedule_word_count: usize = 64;
pub const State = [state_word_count]u32;
pub const initial_state: State = .{
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
};

pub const round_constants: [round_count]u32 = .{
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
};

pub const Trace = struct {
    input: [block_bytes]u8,
    schedule: [schedule_word_count]u32,
    states: [round_count + 1]State,
    output_state: State,
};

pub fn sigmaSmall0(value: u32) u32 {
    return std.math.rotr(u32, value, 7) ^
        std.math.rotr(u32, value, 18) ^ (value >> 3);
}

pub fn sigmaSmall1(value: u32) u32 {
    return std.math.rotr(u32, value, 17) ^
        std.math.rotr(u32, value, 19) ^ (value >> 10);
}

pub fn sigmaBig0(value: u32) u32 {
    return std.math.rotr(u32, value, 2) ^
        std.math.rotr(u32, value, 13) ^
        std.math.rotr(u32, value, 22);
}

pub fn sigmaBig1(value: u32) u32 {
    return std.math.rotr(u32, value, 6) ^
        std.math.rotr(u32, value, 11) ^
        std.math.rotr(u32, value, 25);
}

pub fn choose(e: u32, f: u32, g: u32) u32 {
    return (e & f) ^ (~e & g);
}

pub fn majority(a: u32, b: u32, c: u32) u32 {
    return (a & b) ^ (a & c) ^ (b & c);
}

pub fn schedule(input: [block_bytes]u8) [schedule_word_count]u32 {
    var words: [schedule_word_count]u32 = undefined;
    for (0..16) |i| words[i] = std.mem.readInt(u32, input[i * 4 ..][0..4], .big);
    for (16..schedule_word_count) |i| words[i] = sigmaSmall1(words[i - 2]) +% words[i - 7] +% sigmaSmall0(words[i - 15]) +% words[i - 16];
    return words;
}
pub fn round(state: State, word: u32, constant: u32) State {
    const t1 = state[7] +% sigmaBig1(state[4]) +% choose(state[4], state[5], state[6]) +% constant +% word;
    const t2 = sigmaBig0(state[0]) +% majority(state[0], state[1], state[2]);
    return .{ t1 +% t2, state[0], state[1], state[2], state[3] +% t1, state[4], state[5], state[6] };
}
pub fn compress(initial: State, input: [block_bytes]u8) State {
    return run(false, initial, input);
}
pub fn witness(initial: State, input: [block_bytes]u8) Trace {
    return run(true, initial, input);
}
fn run(comptime capture: bool, initial: State, input: [block_bytes]u8) (if (capture) Trace else State) {
    const words = schedule(input);
    var state = initial;
    var states: if (capture) [round_count + 1]State else void = undefined;
    if (capture) states[0] = initial;
    for (words, round_constants, 0..) |word, constant, i| {
        state = round(state, word, constant);
        if (capture) states[i + 1] = state;
    }
    for (&state, initial) |*out, base| out.* +%= base;
    return if (capture) .{ .input = input, .schedule = words, .states = states, .output_state = state } else state;
}
pub fn stateBytes(state: State) [32]u8 {
    var result: [32]u8 = undefined;
    for (state, 0..) |word, i| std.mem.writeInt(u32, result[i * 4 ..][0..4], word, .big);
    return result;
}

test "SHA compression arbitrary chaining states match independent standard library" {
    var random = std.Random.DefaultPrng.init(0xb5e234d9);
    for (0..64) |_| {
        var input: [64]u8 = undefined;
        random.random().bytes(&input);
        var initial: State = undefined;
        for (&initial) |*word| word.* = random.random().int(u32);
        var oracle = std.crypto.hash.sha2.Sha256.init(.{});
        oracle.s = initial;
        oracle.update(&input);
        const traced = witness(initial, input);
        try std.testing.expectEqualDeep(oracle.s, compress(initial, input));
        try std.testing.expectEqualDeep(oracle.s, traced.output_state);
        try std.testing.expectEqualDeep(initial, traced.states[0]);
        var expected = traced.states[64];
        for (&expected, initial) |*out, base| out.* +%= base;
        try std.testing.expectEqualDeep(oracle.s, expected);
    }
}
test "SHA compression composes with message padding at block boundaries" {
    var message: [255]u8 = undefined;
    for (&message, 0..) |*byte, i| byte.* = @truncate(i * 73 + 19);
    for ([_]usize{ 0, 1, 55, 56, 63, 64, 65, 127, 128, 255 }) |len| {
        var padded: [320]u8 = @splat(0);
        @memcpy(padded[0..len], message[0..len]);
        padded[len] = 0x80;
        const blocks = (len + 9 + 63) / 64;
        std.mem.writeInt(u64, padded[blocks * 64 - 8 ..][0..8], @as(u64, len) * 8, .big);
        var state = initial_state;
        for (0..blocks) |i| state = compress(state, padded[i * 64 ..][0..64].*);
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(message[0..len], &expected, .{});
        try std.testing.expectEqualDeep(expected, stateBytes(state));
    }
}
