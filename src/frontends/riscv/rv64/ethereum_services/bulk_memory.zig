//! ADMITTED bulk-memory services for profile `ethereum_services_v3`.
//!
//! The executor admits exactly what the prover's bulk-memory bridges can
//! prove (design/riscv-proving-stack/rv64-bulk-memory-service.md):
//! - `a0` = 8-aligned packet `dst, src|byte, len` (little-endian u64), `a7` =
//!   0x30001 (memcpy) or 0x30002 (memset); all registers preserved;
//! - `len` a nonzero multiple of 8, at most 1 MiB; `dst` (and `src`) 8-aligned,
//!   no address wrap;
//! - packet words readable; source words readable; destination words readable
//!   AND writable (the RAM tuple of a service write carries R = W = 1);
//! - packet, source and destination words pairwise disjoint (every access of
//!   one call shares the ECALL's RAM tick, so an alias is unprovable);
//! - memset writes `byte & 0xff`.
//! Every check precedes any change: a trapping call changes nothing.
const std = @import("std");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");

pub const MEMCPY_TAG = profile.MEMCPY_TAG;
pub const MEMSET_TAG = profile.MEMSET_TAG;
pub const MAX_BYTES: u64 = 1 << 20;
pub const Kind = enum { memcpy, memset };
pub const Error = memory.Error || error{ UnsupportedService, BulkMemoryLength, BulkMemoryOverlap };
pub const Packet = struct { dst: u64, word1: u64, len: u64 };

pub fn kindOf(tag: u64) ?Kind {
    return switch (tag) {
        MEMCPY_TAG => .memcpy,
        MEMSET_TAG => .memset,
        else => null,
    };
}
fn overlaps(a: u64, a_len: u64, b: u64, b_len: u64) bool {
    return @as(u65, a) < @as(u65, b) + b_len and @as(u65, b) < @as(u65, a) + a_len;
}
/// Validates the call exactly as the prover admits it; returns the packet.
pub fn admit(mem: *memory.Memory, kind: Kind, pointer: u64) Error!Packet {
    if (pointer & 7 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(pointer, 24);
    try mem.mappings.check(pointer, 24, .read);
    const p = Packet{ .dst = try mem.load(pointer, 8), .word1 = try mem.load(pointer + 8, 8), .len = try mem.load(pointer + 16, 8) };
    if (p.len == 0 or p.len % 8 != 0 or p.len > MAX_BYTES) return error.BulkMemoryLength;
    if (p.dst & 7 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(p.dst, p.len);
    try mem.mappings.check(p.dst, p.len, .read);
    try mem.mappings.check(p.dst, p.len, .write);
    if (overlaps(pointer, 24, p.dst, p.len)) return error.BulkMemoryOverlap;
    if (kind == .memcpy) {
        if (p.word1 & 7 != 0) return error.MisalignedAddress;
        _ = try memory.endAddress(p.word1, p.len);
        try mem.mappings.check(p.word1, p.len, .read);
        if (overlaps(pointer, 24, p.word1, p.len) or overlaps(p.dst, p.len, p.word1, p.len)) return error.BulkMemoryOverlap;
    }
    return p;
}
/// Executes one admitted call (the caller retires the ECALL afterwards).
pub fn execute(a: std.mem.Allocator, mem: *memory.Memory, kind: Kind, pointer: u64) Error!Packet {
    const p = try admit(mem, kind, pointer);
    const words = try a.alloc(u64, @intCast(p.len / 8));
    defer a.free(words);
    switch (kind) {
        .memcpy => for (words, 0..) |*w, j| {
            w.* = mem.backing.load(p.word1 + 8 * j, 8).value;
        },
        .memset => @memset(words, @as(u64, @as(u8, @truncate(p.word1))) * 0x0101010101010101),
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
        .{ .packet = .{ 0x1200, 0x1104, 8 }, .kind = .memcpy, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1108, 0x1100, 16 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1100, 0x1108, 16 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x0FF8, 0x1100, 16 }, .kind = .memset, .err = error.UnmappedAddress },
        .{ .packet = .{ 0x3000, 0x1100, 8 }, .kind = .memcpy, .err = error.AccessDenied },
        .{ .packet = .{ 0x1010, 0x1100, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1200, 0x1010, 8 }, .kind = .memcpy, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0xFFFF_FFFF_FFFF_FFF8, 0x1100, 16 }, .kind = .memcpy, .err = error.AddressOverflow },
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
