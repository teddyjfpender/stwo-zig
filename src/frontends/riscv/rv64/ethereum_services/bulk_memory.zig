//! ADMITTED bulk-memory services for profile `ethereum_services_v3`.
//!
//! The executor admits exactly what the prover's bulk-memory bridges can
//! prove (design/riscv-proving-stack/rv64-bulk-memory-service.md):
//! - `a0` = 8-aligned packet, `a7` = tag; all registers preserved;
//! - memcpy 0x30001: packet `dst, src, len`; memset 0x30002: `dst, byte, len`;
//!   memcmp 0x30003: `a, b, len, result` (little-endian u64);
//! - `len` a nonzero multiple of 8, at most 1 MiB; `dst` (memcpy/memset) and
//!   `a`, `b` (memcmp) 8-aligned; the memcpy source may have any alignment;
//!   no address wrap;
//! - packet words readable (memcmp: the result word also writable); source
//!   words readable; destination words readable AND writable (the RAM tuple of
//!   a service write carries R = W = 1);
//! - every aligned word the call touches (packet, every source word that
//!   holds a source byte, destination words; memcmp: both full ranges) belongs
//!   to exactly one of these ranges: every access of one call shares the
//!   ECALL's RAM tick, so an alias is unprovable;
//! - memset writes `byte & 0xff`; memcmp writes -1, 0 or 1 (as i64) by the
//!   first differing byte, reading only the words up to and including the
//!   first differing word.
//! Every check precedes any change: a trapping call changes nothing.
const std = @import("std");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");
const machine = @import("../machine.zig");
const Word = @import("../word.zig").Word;

/// The tape/retirement view of one call: the ECALL step itself.
pub const BulkCall = struct {
    clock: u64,
    pc: u64,
    pointer: u64,
    tag: u64,
    pub fn retirement(self: BulkCall) machine.Retirement {
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(self.tag), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
/// Session event: the call, its packet and the written words' values before
/// the call (borrowed from the session; valid until its next step): the
/// destination words (memcpy/memset) or the single result word (memcmp).
pub const Event = struct { call: BulkCall, packet: Packet, dst_before: []const u64 };

pub const MEMCPY_TAG = profile.MEMCPY_TAG;
pub const MEMSET_TAG = profile.MEMSET_TAG;
pub const MEMCMP_TAG = profile.MEMCMP_TAG;
pub const MAX_BYTES: u64 = 1 << 20;
pub const Kind = enum { memcpy, memset, memcmp };
pub const Error = memory.Error || error{ UnsupportedService, BulkMemoryLength, BulkMemoryOverlap };
/// `word1` is the source (memcpy), fill word (memset) or `b` (memcmp).
/// memcmp: `result` is the written value and `examined` the number of word
/// pairs read (index of the first differing word + 1, or `len / 8`).
pub const Packet = struct { dst: u64, word1: u64, len: u64, result: i64 = 0, examined: u64 = 0 };

pub fn kindOf(tag: u64) ?Kind {
    return switch (tag) {
        MEMCPY_TAG => .memcpy,
        MEMSET_TAG => .memset,
        MEMCMP_TAG => .memcmp,
        else => null,
    };
}
pub fn tagOf(kind: Kind) u64 {
    return switch (kind) {
        .memcpy => MEMCPY_TAG,
        .memset => MEMSET_TAG,
        .memcmp => MEMCMP_TAG,
    };
}
fn overlaps(a: u64, a_len: u64, b: u64, b_len: u64) bool {
    return @as(u65, a) < @as(u65, b) + b_len and @as(u65, b) < @as(u65, a) + a_len;
}
/// Aligned source words of a memcpy: every word holding a byte of
/// `[src, src + len)`; `len / 8` words when aligned, one more otherwise.
pub fn sourceWords(src: u64, len: u64) struct { base: u64, count: u64 } {
    return .{ .base = src & ~@as(u64, 7), .count = len / 8 + @intFromBool(src & 7 != 0) };
}
pub fn packetWords(kind: Kind) u64 {
    return if (kind == .memcmp) 4 else 3;
}
/// Validates the call exactly as the prover admits it; returns the packet.
pub fn admit(mem: *memory.Memory, kind: Kind, pointer: u64) Error!Packet {
    const packet_bytes = 8 * packetWords(kind);
    if (pointer & 7 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(pointer, packet_bytes);
    try mem.mappings.check(pointer, packet_bytes, .read);
    if (kind == .memcmp) try mem.mappings.check(pointer + 24, 8, .write);
    const p = Packet{ .dst = try mem.load(pointer, 8), .word1 = try mem.load(pointer + 8, 8), .len = try mem.load(pointer + 16, 8) };
    if (p.len == 0 or p.len % 8 != 0 or p.len > MAX_BYTES) return error.BulkMemoryLength;
    if (p.dst & 7 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(p.dst, p.len);
    try mem.mappings.check(p.dst, p.len, .read);
    if (kind != .memcmp) try mem.mappings.check(p.dst, p.len, .write);
    if (overlaps(pointer, packet_bytes, p.dst, p.len)) return error.BulkMemoryOverlap;
    switch (kind) {
        .memset => {},
        .memcpy => {
            const s = sourceWords(p.word1, p.len);
            _ = try memory.endAddress(s.base, 8 * s.count);
            try mem.mappings.check(s.base, 8 * s.count, .read);
            if (overlaps(pointer, packet_bytes, s.base, 8 * s.count) or overlaps(p.dst, p.len, s.base, 8 * s.count)) return error.BulkMemoryOverlap;
        },
        .memcmp => {
            if (p.word1 & 7 != 0) return error.MisalignedAddress;
            _ = try memory.endAddress(p.word1, p.len);
            try mem.mappings.check(p.word1, p.len, .read);
            if (overlaps(pointer, packet_bytes, p.word1, p.len) or overlaps(p.dst, p.len, p.word1, p.len)) return error.BulkMemoryOverlap;
        },
    }
    return p;
}
/// The memcmp result of two words compared byte by byte in memory order.
pub fn compareWords(a: u64, b: u64) i64 {
    if (a == b) return 0;
    const diff = a ^ b;
    const shift: u6 = @intCast(@ctz(diff) & ~@as(u32, 7));
    return if ((a >> shift) & 0xff < (b >> shift) & 0xff) -1 else 1;
}
/// The destination word `j` of a memcpy from source words `w[j]`, `w[j + 1]`
/// at byte shift `r = src & 7`.
pub fn shifted(lo: u64, hi: u64, r: u3) u64 {
    if (r == 0) return lo;
    const s: u6 = @as(u6, r) * 8;
    return (lo >> s) | (hi << @intCast(64 - @as(u7, s)));
}
/// Executes one admitted call (the caller retires the ECALL afterwards).
pub fn execute(a: std.mem.Allocator, mem: *memory.Memory, kind: Kind, pointer: u64) Error!Packet {
    var before: std.ArrayList(u64) = .empty;
    defer before.deinit(a);
    return executeRecording(a, mem, kind, pointer, &before);
}
/// As `execute`, also leaving the written words' previous values in `before`.
pub fn executeRecording(a: std.mem.Allocator, mem: *memory.Memory, kind: Kind, pointer: u64, before: *std.ArrayList(u64)) Error!Packet {
    var p = try admit(mem, kind, pointer);
    if (kind == .memcmp) {
        const n = p.len / 8;
        var j: u64 = 0;
        while (j < n) : (j += 1) {
            p.result = compareWords(mem.backing.load(p.dst + 8 * j, 8).value, mem.backing.load(p.word1 + 8 * j, 8).value);
            if (p.result != 0) break;
        }
        p.examined = @min(j + 1, n);
        try before.resize(a, 1);
        before.items[0] = mem.backing.load(pointer + 24, 8).value;
        try mem.storeWords(pointer + 24, &.{@bitCast(p.result)});
        return p;
    }
    try before.resize(a, @intCast(p.len / 8));
    for (before.items, 0..) |*w, j| w.* = mem.backing.load(p.dst + 8 * j, 8).value;
    const words = try a.alloc(u64, @intCast(p.len / 8));
    defer a.free(words);
    switch (kind) {
        .memcpy => {
            const s = sourceWords(p.word1, p.len);
            const r: u3 = @truncate(p.word1);
            for (words, 0..) |*w, j| {
                const lo = mem.backing.load(s.base + 8 * j, 8).value;
                const hi = if (r == 0) 0 else mem.backing.load(s.base + 8 * j + 8, 8).value;
                w.* = shifted(lo, hi, r);
            }
        },
        .memset => @memset(words, @as(u64, @as(u8, @truncate(p.word1))) * 0x0101010101010101),
        .memcmp => unreachable,
    }
    try mem.storeWords(p.dst, words);
    return p;
}

test "admitted bulk memory: copy, fill, and every trap leaves memory unchanged" {
    const t = std.testing;
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 0x1000, .permissions = .{ .read = true, .write = true } });
    try mem.map(.{ .start = 0x3000, .size = 0x1000, .permissions = .{ .read = true } });
    for (0..16) |i| try mem.store(0x1100 + 8 * i, 8, 0x1111 * (i + 1));
    try mem.storeWords(0x1000, &.{ 0x1200, 0x1100, 32 });
    _ = try execute(t.allocator, &mem, .memcpy, 0x1000);
    for (0..4) |i| try t.expectEqual(@as(u64, 0x1111 * (i + 1)), try mem.load(0x1200 + 8 * i, 8));
    try mem.storeWords(0x1000, &.{ 0x1300, 0x1AB, 16 });
    _ = try execute(t.allocator, &mem, .memset, 0x1000);
    try t.expectEqual(@as(u64, 0xABABABABABABABAB), try mem.load(0x1308, 8));
    const Case = struct { packet: [3]u64, kind: Kind, err: anyerror };
    const cases = [_]Case{
        .{ .packet = .{ 0x1200, 0x1100, 0 }, .kind = .memcpy, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1200, 0x1100, 12 }, .kind = .memcpy, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1200, 0x1100, (1 << 20) + 8 }, .kind = .memcpy, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1204, 0x1100, 8 }, .kind = .memcpy, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1108, 0x1100, 16 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1100, 0x1108, 16 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        // Unaligned source sharing one aligned word with the destination.
        .{ .packet = .{ 0x1110, 0x1101, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1100, 0x1107, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1200, 0x1013, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x0FF8, 0x1100, 16 }, .kind = .memset, .err = error.UnmappedAddress },
        .{ .packet = .{ 0x3000, 0x1100, 8 }, .kind = .memcpy, .err = error.AccessDenied },
        .{ .packet = .{ 0x1010, 0x1100, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1200, 0x1010, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0xFFFF_FFFF_FFFF_FFF8, 0x1100, 16 }, .kind = .memcpy, .err = error.AddressOverflow },
        // Unaligned source whose last source word is unmapped.
        .{ .packet = .{ 0x1200, 0x1FF1, 8 }, .kind = .memcpy, .err = error.UnmappedAddress },
    };
    for (cases) |c| {
        try mem.storeWords(0x1000, &c.packet);
        var before: [64]u64 = undefined;
        for (&before, 0..) |*w, i| w.* = try mem.load(0x1000 + 8 * i, 8);
        try t.expectError(c.err, execute(t.allocator, &mem, c.kind, 0x1000));
        for (before, 0..) |w, i| try t.expectEqual(w, try mem.load(0x1000 + 8 * i, 8));
    }
    // A read-only source is admitted.
    try mem.storeWords(0x1000, &.{ 0x1200, 0x3000, 8 });
    _ = try execute(t.allocator, &mem, .memcpy, 0x1000);
    try t.expectError(error.MisalignedAddress, execute(t.allocator, &mem, .memcpy, 0x1004));
}

test "admitted bulk memory: unaligned memcpy matches a byte copy for every shift" {
    const t = std.testing;
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 0x1000, .permissions = .{ .read = true, .write = true } });
    for (1..8) |r| for ([_]u64{ 8, 16, 40 }) |len| {
        for (0..64) |i| try mem.store(0x1100 + i, 1, (i * 37 + r) & 0xff);
        for (0..64) |i| try mem.store(0x1400 + i, 1, 0xEE);
        try mem.storeWords(0x1000, &.{ 0x1400, 0x1100 + r, len });
        _ = try execute(t.allocator, &mem, .memcpy, 0x1000);
        for (0..len) |i| try t.expectEqual(try mem.load(0x1100 + r + i, 1), try mem.load(0x1400 + i, 1));
        try t.expectEqual(@as(u64, 0xEE), try mem.load(0x1400 + len, 1));
    };
}

test "admitted bulk memory: memcmp result, examined words and traps" {
    const t = std.testing;
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 0x1000, .permissions = .{ .read = true, .write = true } });
    try mem.map(.{ .start = 0x3000, .size = 0x1000, .permissions = .{ .read = true } });
    for (0..8) |i| {
        try mem.store(0x1100 + 8 * i, 8, 0x0123_4567_89AB_CDEF +% i);
        try mem.store(0x1200 + 8 * i, 8, 0x0123_4567_89AB_CDEF +% i);
    }
    try mem.storeWords(0x1000, &.{ 0x1100, 0x1200, 64, 7 });
    var p = try execute(t.allocator, &mem, .memcmp, 0x1000);
    try t.expectEqual(@as(i64, 0), p.result);
    try t.expectEqual(@as(u64, 8), p.examined);
    try t.expectEqual(@as(u64, 0), try mem.load(0x1018, 8));
    // First difference in word 2, byte 3 (a < b); a later word differs the other way.
    try mem.store(0x1200 + 16 + 3, 1, (try mem.load(0x1100 + 16 + 3, 1)) + 1);
    try mem.store(0x1100 + 40, 1, 0xFF);
    p = try execute(t.allocator, &mem, .memcmp, 0x1000);
    try t.expectEqual(@as(i64, -1), p.result);
    try t.expectEqual(@as(u64, 3), p.examined);
    try t.expectEqual(@as(u64, std.math.maxInt(u64)), try mem.load(0x1018, 8));
    try mem.storeWords(0x1000, &.{ 0x1200, 0x1100, 64, 0 });
    p = try execute(t.allocator, &mem, .memcmp, 0x1000);
    try t.expectEqual(@as(i64, 1), p.result);
    try t.expectEqual(compareWords(0x00FF, 0x0100), @as(i64, 1));
    try t.expectEqual(compareWords(0x0100, 0x00FF), @as(i64, -1));
    const Case = struct { packet: [4]u64, pointer: u64 = 0x1000, err: anyerror };
    const cases = [_]Case{
        .{ .packet = .{ 0x1100, 0x1200, 0, 0 }, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1100, 0x1200, 20, 0 }, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1101, 0x1200, 8, 0 }, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1100, 0x1204, 8, 0 }, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1100, 0x1100, 8, 0 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1100, 0x1108, 16, 0 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1018, 0x1200, 8, 0 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1100, 0x0FF8, 16, 0 }, .err = error.UnmappedAddress },
    };
    for (cases) |c| {
        try mem.storeWords(c.pointer, &c.packet);
        var before: [64]u64 = undefined;
        for (&before, 0..) |*w, i| w.* = try mem.load(0x1000 + 8 * i, 8);
        try t.expectError(c.err, execute(t.allocator, &mem, .memcmp, c.pointer));
        for (before, 0..) |w, i| try t.expectEqual(w, try mem.load(0x1000 + 8 * i, 8));
    }
    // Read-only ranges are admitted; a read-only result word is not.
    try mem.storeWords(0x1000, &.{ 0x3000, 0x3100, 8, 0 });
    _ = try execute(t.allocator, &mem, .memcmp, 0x1000);
}
