//! Constants and word operations for the pinned upstream Blake2s AIR.

const std = @import("std");

pub const STATE_SIZE: usize = 16;
pub const MESSAGE_SIZE: usize = 16;
pub const FELTS_PER_U32: usize = 2;
pub const N_ROUNDS: usize = 10;
pub const ROUND_LOG_SPLIT = [2]u32{ 3, 1 };
pub const N_ROUND_INPUT_FELTS: usize =
    (STATE_SIZE + STATE_SIZE + MESSAGE_SIZE) * FELTS_PER_U32;

pub const SIGMA = [N_ROUNDS][MESSAGE_SIZE]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

pub fn round(
    state: *[STATE_SIZE]u32,
    message: [MESSAGE_SIZE]u32,
    round_index: usize,
) void {
    std.debug.assert(round_index < N_ROUNDS);
    const schedule = SIGMA[round_index];
    g(state, .{ 0, 4, 8, 12 }, message[schedule[0]], message[schedule[1]]);
    g(state, .{ 1, 5, 9, 13 }, message[schedule[2]], message[schedule[3]]);
    g(state, .{ 2, 6, 10, 14 }, message[schedule[4]], message[schedule[5]]);
    g(state, .{ 3, 7, 11, 15 }, message[schedule[6]], message[schedule[7]]);
    g(state, .{ 0, 5, 10, 15 }, message[schedule[8]], message[schedule[9]]);
    g(state, .{ 1, 6, 11, 12 }, message[schedule[10]], message[schedule[11]]);
    g(state, .{ 2, 7, 8, 13 }, message[schedule[12]], message[schedule[13]]);
    g(state, .{ 3, 4, 9, 14 }, message[schedule[14]], message[schedule[15]]);
}

fn g(
    state: *[STATE_SIZE]u32,
    indices: [4]usize,
    message0: u32,
    message1: u32,
) void {
    const a = indices[0];
    const b = indices[1];
    const c = indices[2];
    const d = indices[3];

    state[a] = state[a] +% state[b] +% message0;
    state[d] = rotateRight(state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = rotateRight(state[b] ^ state[c], 12);
    state[a] = state[a] +% state[b] +% message1;
    state[d] = rotateRight(state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = rotateRight(state[b] ^ state[c], 7);
}

fn rotateRight(value: u32, amount: u5) u32 {
    return std.math.rotr(u32, value, amount);
}

test "Blake2s round matches the RFC 7693 compression example state" {
    var state = [STATE_SIZE]u32{
        0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19,
    };
    var message = [_]u32{0} ** MESSAGE_SIZE;
    message[0] = 0x00636261;

    round(&state, message, 0);

    try std.testing.expectEqualSlices(u32, &.{
        0x16a3253e, 0xd7b5f23b, 0x7e8be21b, 0xd9091044,
        0x016a11ff, 0x91c481a8, 0x624a7e31, 0x213311ab,
        0xb60c2bd3, 0xd3e73233, 0x509a4a6a, 0xb467285e,
        0x798ed52f, 0xee8789d7, 0x70747338, 0x2bb45c6a,
    }, &state);
}

test "Blake round split accounts for exactly ten rounds" {
    var total: usize = 0;
    for (ROUND_LOG_SPLIT) |log_split| total += @as(usize, 1) << @intCast(log_split);
    try std.testing.expectEqual(N_ROUNDS, total);
    try std.testing.expectEqual(@as(usize, 96), N_ROUND_INPUT_FELTS);
}
