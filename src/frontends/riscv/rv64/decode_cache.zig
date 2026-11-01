//! Fixed-capacity word-keyed cache, following the RV32 stale-code rule.
//! Decode is shared with the uncached path; no second instruction semantics.
const std = @import("std");
const isa = @import("decode.zig");
const Entry = struct { word: u32 = 0, instruction: isa.Instruction = undefined, valid: bool = false };
pub const Error = std.mem.Allocator.Error || error{InvalidCacheSize};
pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    /// Fixed at init; a cache never mixes decodes of two instruction sets.
    isa: isa.Isa = .rv64im,

    pub fn init(allocator: std.mem.Allocator, count: usize) Error!Cache {
        return initIsa(allocator, count, .rv64im);
    }
    pub fn initIsa(allocator: std.mem.Allocator, count: usize, set: isa.Isa) Error!Cache {
        if (count == 0 or count > 65536 or !std.math.isPowerOfTwo(count)) return error.InvalidCacheSize;
        const entries = try allocator.alloc(Entry, count);
        for (entries) |*entry| entry.valid = false;
        return .{ .allocator = allocator, .entries = entries, .isa = set };
    }

    pub fn deinit(self: *Cache) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn decode(self: *Cache, word: u32) isa.Error!isa.Instruction {
        const mixed = word ^ (word >> 7) ^ (word >> 17);
        const entry = &self.entries[@as(usize, mixed) & (self.entries.len - 1)];
        if (entry.valid and entry.word == word) return entry.instruction;
        const instruction = try isa.decodeFor(self.isa, word);
        entry.* = .{ .word = word, .instruction = instruction, .valid = true };
        return instruction;
    }
};
