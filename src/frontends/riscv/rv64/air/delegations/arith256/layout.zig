//! One `arith256_mod` call per row: r = (a*b + c) mod m, r = 0 when m = 0.
//!
//! Every 256-bit value is 32 little-endian byte columns. The row proves the
//! exact integer identity
//!     (1 - z) * (a*b + c) = q*m + r,        q < 2^512 (64 bytes),
//! together with r < m when z = 0, where z is the m = 0 indicator
//! (z * sum(m) = 0 and sum(m) * inv = active - z). The identity is checked as
//! 48 two-byte-coefficient groups with signed carries in [-2^14, 2^14):
//!     P_k   = (1 - z) * (sum_i a_i b_{k-i} + c_k) - sum_i q_i m_{k-i} - r_k
//!     G_j   = P_{2j} + 256 P_{2j+1}
//!     G_j + carry_{j-1} - 65536 carry_j = 0,  carry_{-1} = carry_47 = 0.
//! r < m is m - r - (active - z) = d >= 0 over 16 16-bit chunks with 15
//! Boolean borrows and no final borrow. Byte ranges of a, b, c, m, r_before
//! and r are inherited from the Word16 bridge (its BEFORE/AFTER U8 queries)
//! through Wire35; q, d and the carry bytes are range-checked here against a
//! local 256-entry BYTE table (fixed column BYTE = row mod 256, MAIN MULT).
//! See design/riscv-proving-stack/rv64-arith256-service.md for the bounds.
const std = @import("std");
const core = @import("stwo_core");

/// Wire35 program kind. Secp ADD/DOUBLE own 1/2, SHA-256 owns 3.
pub const PROGRAM_KIND: u32 = 4;
/// Wire35 IDs: the five packet coordinates' before-values (a, b, c, m and the
/// overwritten r slot) are bridge coordinates 0..4; the new r is wire 5.
pub const INPUT_WIRES = [5]u32{ 0, 1, 2, 3, 4 };
pub const OUTPUT_WIRE: u32 = 5;
pub const WIRE_ARITY = 35;

pub const LIMBS = 32;
pub const Q_LIMBS = 64;
/// Coefficients of (a*b + c) - q*m - r: k in 0..95 (q*m has degree 94).
pub const COEFFICIENTS = Q_LIMBS + LIMBS - 1;
/// Two-coefficient groups; the last holds P_94 alone.
pub const GROUPS = (COEFFICIENTS + 1) / 2;
/// Carries between groups; the final carry is the constant zero.
pub const CARRIES = GROUPS - 1;
/// Encoded carry = lo + 256 hi - CARRY_OFFSET * active, hi < 128.
pub const CARRY_OFFSET: u32 = 1 << 14;
pub const CHUNKS = 16;
pub const BORROWS = CHUNKS - 1;

// Fixed (preprocessed, request-independent) columns.
pub const ROW = 0;
pub const FIRST = 1;
pub const LAST = 2;
pub const BYTE = 3;
pub const FIXED = 4;

// MAIN columns.
pub const ACTIVE = 0;
pub const A = 1;
pub const B = A + LIMBS;
pub const C = B + LIMBS;
pub const M = C + LIMBS;
pub const R_BEFORE = M + LIMBS;
pub const R = R_BEFORE + LIMBS;
pub const QUOTIENT = R + LIMBS;
pub const Z = QUOTIENT + Q_LIMBS;
pub const INV = Z + 1;
pub const CARRY_LO = INV + 1;
pub const CARRY_HI = CARRY_LO + CARRIES;
pub const D = CARRY_HI + CARRIES;
pub const BORROW = D + LIMBS;
pub const MULT = BORROW + BORROWS;
pub const MAIN = MULT + 1;

/// Local BYTE queries per row: q (64), d (32), carry lo (47), carry hi (47)
/// and carry hi + 128 (47, bounds hi below 128), then the table entry.
pub const BYTE_QUERIES = Q_LIMBS + LIMBS + 3 * CARRIES;
pub const BYTE_FRACTIONS = BYTE_QUERIES + 1;
pub const BYTE_BATCHES = (BYTE_FRACTIONS + 1) / 2;
pub const WIRE_FRACTIONS = 6;
pub const WIRE_BATCHES = WIRE_FRACTIONS / 2;
pub const BATCHES = BYTE_BATCHES + WIRE_BATCHES;
/// One cumulative QM31 (four columns) per batch of two fractions. The BYTE
/// chain (batches 0..BYTE_BATCHES-1) closes to zero around the trace; the
/// Wire chain closes to the public claim.
pub const INTERACTION = 4 * BATCHES;
pub const BYTE_LAST = 4 * (BYTE_BATCHES - 1);
pub const WIRE_FIRST = 4 * BYTE_BATCHES;
pub const WIRE_LAST = 4 * (BATCHES - 1);

pub const BOOLEANS = 2 + BORROWS; // ACTIVE, Z, borrows
pub const ZERO_TEST = 2;
pub const ACTIVITY = 4;
pub const MAIN_CONSTRAINTS = BOOLEANS + ZERO_TEST + GROUPS + CHUNKS + ACTIVITY;
pub const CONSTRAINTS = MAIN_CONSTRAINTS + BATCHES;
pub const MIN_LOG = 8; // the BYTE table needs 256 rows
pub const MAX_LOG = 22;

comptime {
    std.debug.assert(COEFFICIENTS == 95 and GROUPS == 48 and CARRIES == 47);
    std.debug.assert(BYTE_QUERIES == 237 and BYTE_BATCHES == 119 and BATCHES == 122);
    std.debug.assert(MAIN == 401 and INTERACTION == 488 and CONSTRAINTS == 209);
}

/// Byte query `index` (0..BYTE_QUERIES): MAIN column and constant addend.
pub const Query = struct { column: usize, addend: u32 };
pub fn query(index: usize) Query {
    if (index < Q_LIMBS) return .{ .column = QUOTIENT + index, .addend = 0 };
    var i = index - Q_LIMBS;
    if (i < LIMBS) return .{ .column = D + i, .addend = 0 };
    i -= LIMBS;
    if (i < CARRIES) return .{ .column = CARRY_LO + i, .addend = 0 };
    i -= CARRIES;
    if (i < CARRIES) return .{ .column = CARRY_HI + i, .addend = 0 };
    i -= CARRIES;
    std.debug.assert(i < CARRIES);
    return .{ .column = CARRY_HI + i, .addend = 128 };
}

pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
    const modulus = core.fields.m31.Modulus;
    if (log < MIN_LOG or log > MAX_LOG) return error.InvalidArith256Geometry;
    const n = @as(usize, 1) << @intCast(log);
    // At least one inactive padding row; the activity prefix ends before LAST.
    if (calls >= n or first_id == 0 or first_id >= modulus or @as(u64, first_id) + calls > modulus) return error.InvalidArith256Geometry;
    // BYTE multiplicities and Wire35 events stay below the characteristic.
    if (@as(u64, BYTE_QUERIES) * n >= modulus or @as(u64, WIRE_FRACTIONS) * n >= modulus) return error.Arith256LookupMassExceeded;
}
/// Smallest admitted log for `calls` rows plus one padding row.
pub fn logSize(calls: usize) !u32 {
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(@as(usize, 1) << MIN_LOG, try std.math.add(usize, calls, 1))));
    try validateGeometry(calls, 1, log);
    return log;
}
pub fn widths() [3]usize {
    return .{ FIXED, MAIN, INTERACTION };
}
