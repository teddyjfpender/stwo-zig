//! M8 T10 (STWO_RV64_M8_CAPTURE_RECORDER): presized open-addressing stable
//! grouping for narrow-capture provider facts. Producer scheduling only.
//!
//! Output contract (pinned by prepared_recorder_test.zig against the std
//! AutoHashMap groupers in alu_dedup.zig / binary_dedup.zig /
//! shift_dedup.zig): unique facts in FIRST-OCCURRENCE order, each with its
//! occurrence count; equality is field equality, exactly the AutoHashMap key
//! semantics. Only the storage differs: a table sized once from the caller's
//! input-count bound to a power of two >= 2 * count (load <= 1/2, never
//! rehashed), a u64 slot = (hash high 32 bits << 32) | (1 + unique index),
//! linear probing, and a splitmix hash over the integer fields instead of
//! Wyhash (the tag skips nearly every non-matching fact read). Fact/weight
//! buffers take a power-of-two size class so the large-block recycler reuses
//! the previous segment's already-faulted block, then shrink in place.
//! [M T10 prof1, 26235159 inflight 4, legacy]: ALU AutoHashMap grouping was
//! 7.51 s summed over 49 segments (~94 ns/fact, the serial long pole of the
//! narrow capture); see prepared.zig captureRecorder for the A/B.
const std = @import("std");

inline fn mix(x: u64) u64 {
    // splitmix64 finalizer: full avalanche, 2 multiplies.
    var z = x;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

inline fn lane(v: anytype) u64 {
    return switch (@typeInfo(@TypeOf(v))) {
        .int => |info| @as(std.meta.Int(.unsigned, info.bits), @bitCast(v)),
        .@"enum" => @intFromEnum(v),
        .bool => @intFromBool(v),
        else => @compileError("stable_dedup: unsupported field type " ++ @typeName(@TypeOf(v))),
    };
}

/// Hash of the fact's integer/enum/bool fields.
pub inline fn hashFact(fact: anytype) u64 {
    var h: u64 = 0x9e3779b97f4a7c15;
    inline for (@typeInfo(@TypeOf(fact)).@"struct".fields) |field| h = mix(h ^ lane(@field(fact, field.name)));
    return h;
}

pub inline fn eqlFact(x: anytype, y: @TypeOf(x)) bool {
    inline for (@typeInfo(@TypeOf(x)).@"struct".fields) |field| {
        if (@field(x, field.name) != @field(y, field.name)) return false;
    }
    return true;
}

/// Incremental grouper. `init(capacity)` must be given an upper bound on the
/// number of `add` calls (the caller knows it exactly); it is never exceeded.
/// With `deduplicate = false` every fact is kept with weight 1 (the legacy
/// non-deduplicating `collect` route).
pub fn Grouper(comptime Fact: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        table: []u64,
        mask: usize,
        /// Full power-of-two size-class buffers (the large-block recycler
        /// reuses the previous segment's already-faulted block); `finish`
        /// shrinks them in place to `unique`.
        facts: []Fact,
        weights: []u32,
        unique: usize = 0,
        capacity: usize,
        deduplicate: bool,

        pub fn init(a: std.mem.Allocator, capacity: usize, deduplicate: bool) !Self {
            if (capacity >= std.math.maxInt(u32)) return error.OutOfMemory;
            const slots: usize = if (deduplicate) try std.math.ceilPowerOfTwo(usize, @max(16, 2 * capacity)) else 0;
            const class = try std.math.ceilPowerOfTwo(usize, @max(16, capacity));
            const table = try a.alloc(u64, slots);
            errdefer a.free(table);
            @memset(table, 0);
            const facts = try a.alloc(Fact, class);
            errdefer a.free(facts);
            const weights = try a.alloc(u32, class);
            return .{ .allocator = a, .table = table, .mask = if (slots == 0) 0 else slots - 1, .facts = facts, .weights = weights, .capacity = capacity, .deduplicate = deduplicate };
        }

        pub inline fn add(self: *Self, fact: Fact) void {
            if (!self.deduplicate) {
                std.debug.assert(self.unique < self.capacity);
                self.facts[self.unique] = fact;
                self.weights[self.unique] = 1;
                self.unique += 1;
                return;
            }
            const h = hashFact(fact);
            const tag = h & 0xffff_ffff_0000_0000;
            var slot: usize = @intCast(h & self.mask);
            while (true) {
                const held = self.table[slot];
                if (held == 0) {
                    std.debug.assert(self.unique < self.capacity);
                    self.table[slot] = tag | (self.unique + 1);
                    self.facts[self.unique] = fact;
                    self.weights[self.unique] = 1;
                    self.unique += 1;
                    return;
                }
                if (held & 0xffff_ffff_0000_0000 == tag) {
                    const index: usize = @intCast((held & 0xffff_ffff) - 1);
                    if (eqlFact(self.facts[index], fact)) {
                        self.weights[index] += 1;
                        return;
                    }
                }
                slot = (slot + 1) & self.mask;
            }
        }

        /// Exact-length owned slices; the grouper is consumed (no deinit
        /// afterwards, also on error).
        pub fn finish(self: *Self) !struct { facts: []Fact, weights: []u32 } {
            const a = self.allocator;
            const unique = self.unique;
            const facts_buffer = self.facts;
            const weights_buffer = self.weights;
            a.free(self.table);
            self.* = undefined;
            const facts = shrink(Fact, a, facts_buffer, unique) catch |err| {
                a.free(weights_buffer);
                return err;
            };
            errdefer a.free(facts);
            const weights = try shrink(u32, a, weights_buffer, unique);
            return .{ .facts = facts, .weights = weights };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.table);
            self.allocator.free(self.facts);
            self.allocator.free(self.weights);
            self.* = undefined;
        }
    };
}

fn shrink(comptime T: type, a: std.mem.Allocator, buffer: []T, len: usize) ![]T {
    if (len == buffer.len) return buffer;
    if (a.resize(buffer, len)) return buffer[0..len];
    const exact = a.dupe(T, buffer[0..len]) catch |err| {
        a.free(buffer);
        return err;
    };
    a.free(buffer);
    return exact;
}

/// Distinct-u64 counter (the `unique_memory_words` census), same count as an
/// AutoHashMap(u64, void) set. `capacity` bounds the number of `add` calls.
pub const DistinctWords = struct {
    allocator: std.mem.Allocator,
    table: []u64,
    mask: usize,
    distinct: u32 = 0,
    pub fn init(a: std.mem.Allocator, capacity: usize) !DistinctWords {
        const slots = try std.math.ceilPowerOfTwo(usize, @max(16, 2 * capacity));
        const table = try a.alloc(u64, slots);
        @memset(table, 0);
        return .{ .allocator = a, .table = table, .mask = slots - 1 };
    }
    /// Keys are stored as key+1 (0 = empty); `key` must not be maxInt(u64)
    /// (callers pass 8-byte-aligned words, so it never is).
    pub inline fn add(self: *DistinctWords, key: u64) void {
        std.debug.assert(key != std.math.maxInt(u64));
        const stored = key + 1;
        var slot: usize = @intCast(mix(stored) & self.mask);
        while (true) {
            const held = self.table[slot];
            if (held == 0) {
                self.table[slot] = stored;
                self.distinct += 1;
                return;
            }
            if (held == stored) return;
            slot = (slot + 1) & self.mask;
        }
    }
    pub fn deinit(self: *DistinctWords) void {
        self.allocator.free(self.table);
        self.* = undefined;
    }
};
