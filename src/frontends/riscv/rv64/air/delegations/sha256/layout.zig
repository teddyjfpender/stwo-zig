//! One SHA-256 compression per row, fully unrolled. Every 32-bit word that a
//! round or schedule step reads through a bitwise function is held as 32
//! Boolean columns; sums are carried exactly in two 16-bit halves.
//!
//! Word indexing follows FIPS 180-4 with the working variables written as two
//! shift registers: A_j for j = -4..63 and E_j likewise, where
//!   A_{-1..-4} = H0..H3 (a, b, c, d) and E_{-1..-4} = H4..H7 (e, f, g, h),
//!   E_t = A_{t-4} + E_{t-4} + Sigma1(E_{t-1}) + Ch(E_{t-1}, E_{t-2}, E_{t-3}) + K_t + W_t,
//!   A_t = E_{t-4} + Sigma1(E_{t-1}) + Ch(...) + K_t + W_t + Sigma0(A_{t-1}) + Maj(A_{t-1}, A_{t-2}, A_{t-3}).
//! The output is H_i + {A_63, A_62, A_61, A_60, E_63, E_62, E_61, E_60}[i].
const std = @import("std");
const core = @import("stwo_core");

pub const WORD_BITS = 32;
pub const ROUNDS = 64;
/// Wire35 program kind. Secp ADD/DOUBLE own 1/2; SHA-256 owns 3.
pub const PROGRAM_KIND: u32 = 3;
/// Wire35 IDs: inputs are the 32-byte state and the two 32-byte message
/// halves, exactly the bridge coordinates 0, 1, 2. The new state is wire 3.
pub const STATE_WIRE: u32 = 0;
pub const MESSAGE_WIRES = [2]u32{ 1, 2 };
pub const OUTPUT_WIRE: u32 = 3;
pub const WIRE_ARITY = 35;

// Fixed (preprocessed, request-independent) columns.
pub const ROW = 0;
pub const FIRST = 1;
pub const LAST = 2;
pub const FIXED = 3;

// MAIN columns.
pub const ACTIVE = 0;
pub const W = 1; // W_t bit i at W + 32 t + i, t in 0..64.
pub const A = W + 64 * WORD_BITS; // A_j bit i at A + 32 (j + 4) + i, j in -4..63.
pub const E = A + 68 * WORD_BITS;
pub const SCHEDULE_CARRY = E + 68 * WORD_BITS; // t in 16..64: lo (2 bits), hi (2 bits).
pub const ROUND_CARRY = SCHEDULE_CARRY + 48 * 4; // t: E lo (3), E hi (3), A lo (3), A hi (3).
pub const FINAL_CARRY = ROUND_CARRY + ROUNDS * 12; // word i: lo, hi.
pub const OUT = FINAL_CARRY + 16; // 32 output bytes, state words little-endian.
pub const MAIN = OUT + 32;
/// Every Boolean column: ACTIVE and [W, OUT).
pub const BOOLEANS = OUT - W + 1;

// INTERACTION: two cumulative QM31 columns, one per pair of Wire35 events.
pub const INTERACTION = 8;
pub const BATCHES = 2;

pub const SCHEDULE_EQUATIONS = 48 * 2;
pub const ROUND_EQUATIONS = ROUNDS * 4;
pub const FINAL_EQUATIONS = 16;
pub const ACTIVITY_EQUATIONS = 4;
pub const CONSTRAINTS = BOOLEANS + SCHEDULE_EQUATIONS + ROUND_EQUATIONS + FINAL_EQUATIONS + ACTIVITY_EQUATIONS + BATCHES;

pub const K = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

pub inline fn w(t: usize, bit: usize) usize {
    return W + WORD_BITS * t + bit;
}
/// j is the shifted register index j + 4 in 0..68.
pub inline fn a(j4: usize, bit: usize) usize {
    return A + WORD_BITS * j4 + bit;
}
pub inline fn e(j4: usize, bit: usize) usize {
    return E + WORD_BITS * j4 + bit;
}
pub inline fn scheduleCarry(t: usize, hi: bool, bit: usize) usize {
    return SCHEDULE_CARRY + 4 * (t - 16) + (if (hi) @as(usize, 2) else 0) + bit;
}
pub inline fn roundCarry(t: usize, word: enum { e, a }, hi: bool, bit: usize) usize {
    return ROUND_CARRY + 12 * t + (if (word == .a) @as(usize, 6) else 0) + (if (hi) @as(usize, 3) else 0) + bit;
}
pub inline fn finalCarry(i: usize, hi: bool) usize {
    return FINAL_CARRY + 2 * i + @intFromBool(hi);
}
/// State word i (H0..H7) as a register column base: H0..3 = A_{-1..-4}, H4..7 = E_{-1..-4}.
pub inline fn stateWord(i: usize, bit: usize) usize {
    return if (i < 4) a(3 - i, bit) else e(3 - (i - 4), bit);
}
/// Feed-forward addend for state word i: A_63..A_60, then E_63..E_60.
pub inline fn finalWord(i: usize, bit: usize) usize {
    return if (i < 4) a(67 - i, bit) else e(67 - (i - 4), bit);
}

pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
    const modulus = core.fields.m31.Modulus;
    if (log < 5 or log > 20) return error.InvalidSha256Geometry;
    const n = @as(usize, 1) << @intCast(log);
    // At least one inactive padding row; the activity prefix ends before LAST.
    if (calls >= n or first_id == 0 or first_id >= modulus or @as(u64, first_id) + calls > modulus) return error.InvalidSha256Geometry;
    // Four Wire35 events per active row.
    if (4 * @as(u64, n) >= modulus) return error.Sha256LookupMassExceeded;
}
/// Smallest admitted log for `calls` compressions plus one padding row.
pub fn logSize(calls: usize) !u32 {
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, try std.math.add(usize, calls, 1))));
    try validateGeometry(calls, 1, log);
    return log;
}
pub fn widths() [3]usize {
    return .{ FIXED, MAIN, INTERACTION };
}
