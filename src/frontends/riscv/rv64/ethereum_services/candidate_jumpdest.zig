//! Execution-only CANDIDATE service `jumpdest_bitmap` (tag 0x0003_0040) for
//! profile `ethereum_services_v3_candidate`: EVM JUMPDEST analysis.
//!
//! ABI (autoresearch/guest_efficiency/CONTEXT.md, notes/jumpdest-service.md):
//! `a0` = 8-byte aligned packet of three little-endian u64 `code, len, bitmap`;
//! `a7` = tag; all registers preserved; the packet is unchanged.
//! - `code` is 64-byte aligned, `bitmap` 8-byte aligned, `len` a nonzero
//!   multiple of 8 and at most `MAX_CODE_BYTES` (word granularity keeps the
//!   proof free of byte masks; 64-byte alignment keeps the eight code words of
//!   one bitmap word inside one address carry). Guests pass the code length
//!   rounded up to 8 over a zero-padded copy: zero bytes are never JUMPDESTs
//!   and only affect bits at or past the true length, which evmone's
//!   `check_jumpdest` never reads (it bounds-checks against the code size).
//! - Reads the `len / 8` code words at `code` and writes exactly `ceil(len/64)`
//!   words at `bitmap`: bit `i % 64` of word `i / 64` is 1 iff `i < len`,
//!   `code[i] == 0x5b` (JUMPDEST) and `i` is not PUSH1..PUSH32 immediate data
//!   (an opcode `0x60 + k` at `j` makes `j+1 .. j+1+k` data; data running past
//!   `len` is simply cut off). This is evmone's `BitsetSpan` layout.
//! - The code range, the bitmap range and the packet are pairwise disjoint.
//! - Every check precedes any write: a trapping call changes nothing.
//! - Reported `bytes` = `len`.
const std = @import("std");
const memory = @import("../memory.zig");

pub const TAG: u64 = 0x0003_0040;
/// EIP-3860 caps initcode at 49,152 bytes and EIP-170 code at 24,576; one MiB
/// leaves room for any future limit while bounding a call's rows.
pub const MAX_CODE_BYTES: u64 = 1 << 20;
pub const Error = memory.Error || error{ CandidateLengthLimit, CandidateAliasing };

pub const OP_JUMPDEST: u8 = 0x5b;
pub const OP_PUSH1: u8 = 0x60;
pub const OP_PUSH32: u8 = 0x7f;

/// Reference JUMPDEST analysis (evmone `analyze_jumpdests`). `out` must hold
/// `ceil(code.len / 64)` words; every word is written.
pub fn bitmap(code: []const u8, out: []u64) void {
    std.debug.assert(out.len == (code.len + 63) / 64);
    @memset(out, 0);
    var i: usize = 0;
    while (i < code.len) {
        const op = code[i];
        if (op >= OP_PUSH1 and op <= OP_PUSH32) {
            i += @as(usize, op - OP_PUSH1) + 2;
        } else {
            if (op == OP_JUMPDEST) out[i / 64] |= @as(u64, 1) << @intCast(i % 64);
            i += 1;
        }
    }
}

fn disjoint(a: u64, a_len: u64, b: u64, b_len: u64) bool {
    return a + a_len <= b or b + b_len <= a;
}

/// Execute one call on the packet at `pointer` (already checked 8-aligned).
/// Returns the reported byte count.
pub fn execute(a: std.mem.Allocator, pointer: u64, mem: *memory.Memory, packet: [3]u64) Error!u64 {
    const code = packet[0];
    const len = packet[1];
    const out = packet[2];
    if (len == 0 or len % 8 != 0 or len > MAX_CODE_BYTES) return error.CandidateLengthLimit;
    if (code & 63 != 0 or out & 7 != 0) return error.MisalignedAddress;
    const code_words = len / 8;
    const out_words = (len + 63) / 64;
    _ = try memory.endAddress(code, 8 * code_words);
    _ = try memory.endAddress(out, 8 * out_words);
    if (!disjoint(code, 8 * code_words, out, 8 * out_words) or
        !disjoint(pointer, 24, out, 8 * out_words) or
        !disjoint(pointer, 24, code, 8 * code_words)) return error.CandidateAliasing;
    try mem.mappings.check(code, 8 * code_words, .read);
    try mem.mappings.check(out, 8 * out_words, .write);
    const bytes = try a.alloc(u8, @intCast(8 * code_words));
    defer a.free(bytes);
    for (0..@intCast(code_words)) |w| {
        const word = mem.backing.load(code + 8 * w, 8).value;
        std.mem.writeInt(u64, bytes[8 * w ..][0..8], word, .little);
    }
    const words = try a.alloc(u64, @intCast(out_words));
    defer a.free(words);
    bitmap(bytes, words);
    try mem.backing.storeWords(out, words);
    return len;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "jumpdest bitmap: push data is skipped, truncated push at the end, word layout" {
    // 0x5b JUMPDEST at 0; PUSH2 0x5b 0x5b at 1..3 (data); JUMPDEST at 4;
    // PUSH1 at 5 with data 0x5b at 6; 0x5b at 7 is a real JUMPDEST.
    const code = [_]u8{ 0x5b, 0x61, 0x5b, 0x5b, 0x5b, 0x60, 0x5b, 0x5b };
    var out: [1]u64 = undefined;
    bitmap(&code, &out);
    try testing.expectEqual(@as(u64, 0b1001_0001), out[0]);
    // PUSH32 at 62 swallows everything after it, including the next word.
    var long: [130]u8 = @splat(OP_JUMPDEST);
    long[62] = OP_PUSH32;
    var out3: [3]u64 = undefined;
    bitmap(&long, &out3);
    try testing.expectEqual(@as(u64, (1 << 62) - 1), out3[0]);
    // 62 + 33 = 95 is the first byte after the data.
    try testing.expectEqual(~@as(u64, 0) << 31, out3[1]);
    try testing.expectEqual(@as(u64, 0b11), out3[2]);
    // A PUSH at the very end with missing data.
    const tail = [_]u8{ 0x5b, 0x7f };
    var out1: [1]u64 = undefined;
    bitmap(&tail, &out1);
    try testing.expectEqual(@as(u64, 1), out1[0]);
}

fn reference(code: []const u8, i: usize) bool {
    // Independent formulation: walk opcodes and test whether `i` is one.
    var j: usize = 0;
    while (j < code.len) {
        if (j == i) return code[j] == OP_JUMPDEST;
        if (j > i) return false;
        const op = code[j];
        j += if (op >= OP_PUSH1 and op <= OP_PUSH32) @as(usize, op) - 0x5e else 1;
    }
    return false;
}

test "jumpdest bitmap agrees with an independent walk on random codes" {
    var prng = std.Random.DefaultPrng.init(0x5b5b);
    const r = prng.random();
    var code: [300]u8 = undefined;
    var out: [5]u64 = undefined;
    for (0..2000) |_| {
        const n = r.intRangeAtMost(usize, 1, code.len);
        // Bias towards the interesting opcodes.
        for (code[0..n]) |*b| b.* = switch (r.uintLessThan(u8, 4)) {
            0 => OP_JUMPDEST,
            1 => r.intRangeAtMost(u8, OP_PUSH1, OP_PUSH32),
            else => r.int(u8),
        };
        const words = (n + 63) / 64;
        bitmap(code[0..n], out[0..words]);
        for (0..64 * words) |i| {
            const bit = out[i / 64] >> @intCast(i % 64) & 1 == 1;
            try testing.expectEqual(i < n and reference(code[0..n], i), bit);
        }
    }
}
