//! Word-keyed decoded-instruction cache for the RV32IM runner.
//!
//! The cache is keyed by the fetched word rather than the program counter, so
//! writes to executable memory cannot reuse stale decoded state.

const std = @import("std");
const DecodedInst = @import("decode.zig").DecodedInst;

const N_ENTRIES: usize = 1 << 14;
const INDEX_MASK: u32 = N_ENTRIES - 1;

const Entry = struct {
    word: u32 = 0,
    decoded: DecodedInst = undefined,
    valid: bool = false,
};

pub const Cache = struct {
    entries: []Entry,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Cache {
        const entries = try allocator.alloc(Entry, N_ENTRIES);
        for (entries) |*entry| entry.valid = false;
        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *Cache) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub inline fn decode(self: *Cache, word: u32) !DecodedInst {
        const entry = &self.entries[index(word)];
        if (entry.valid and entry.word == word) return entry.decoded;
        const decoded = try DecodedInst.decode(word);
        entry.* = .{ .word = word, .decoded = decoded, .valid = true };
        return decoded;
    }

    inline fn index(word: u32) usize {
        const mixed = word ^ (word >> 7) ^ (word >> 17);
        return @intCast(mixed & INDEX_MASK);
    }
};

test "decode cache keys entries by the fetched instruction word" {
    var cache = try Cache.init(std.testing.allocator);
    defer cache.deinit();

    const first = try cache.decode(0x0010_0093); // ADDI x1, x0, 1.
    const second = try cache.decode(0x0020_0093); // ADDI x1, x0, 2.
    const first_again = try cache.decode(0x0010_0093);
    try std.testing.expectEqual(@as(i32, 1), first.imm);
    try std.testing.expectEqual(@as(i32, 2), second.imm);
    try std.testing.expectEqual(first, first_again);
}

test "decode cache does not retain illegal words" {
    var cache = try Cache.init(std.testing.allocator);
    defer cache.deinit();

    try std.testing.expectError(error.IllegalInstruction, cache.decode(0));
    try std.testing.expectError(error.IllegalInstruction, cache.decode(0));
}
