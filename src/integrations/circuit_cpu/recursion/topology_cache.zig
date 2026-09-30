//! A byte-bounded LRU of per-topology artifacts (design §3.5, §9.3).
//!
//! Keyed by `TopologyKey`. An entry holds what every proof of one topology
//! shares, for example a leaf's preprocessed circuit, preprocessed root and
//! circuit hash. The cache observes nothing about the entries except their
//! size, so it cannot change proof bytes.
//!
//! Publication is transactional: a caller builds an entry, finishes the proof
//! that needs it, and only then publishes it, so a failed proof leaves no
//! entry. Eviction removes least-recently-used entries until both limits
//! hold; it never evicts the entry being published. Hit, miss and eviction
//! counts are observable (`stats`).
//!
//! Pointers returned by `get` and `publish` stay valid until the next
//! `publish` or `deinit`. The cache is single-threaded.

const std = @import("std");
const TopologyKey = @import("topology_key.zig").TopologyKey;

pub const Limits = struct {
    /// Design §6.5: one leaf and one fold topology cover current mainnet
    /// and SN work.
    max_entries: usize = 2,
    max_bytes: usize = std.math.maxInt(usize),
};

pub const Stats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    entries: usize = 0,
    bytes: usize = 0,
};

pub const Error = error{
    /// The key already has an entry; publish only after a miss.
    DuplicateKey,
    /// The entry alone exceeds `max_bytes` (or `max_entries` is 0); the
    /// caller keeps it.
    EntryExceedsLimits,
} || std.mem.Allocator.Error;

/// `Entry` must declare `deinit(*Entry, std.mem.Allocator) void` and
/// `byteSize(*const Entry) usize`.
pub fn TopologyCache(comptime Entry: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            key: TopologyKey,
            entry: *Entry,
            bytes: usize,
        };

        allocator: std.mem.Allocator,
        limits: Limits,
        /// Least recently used first.
        slots: std.ArrayList(Slot) = .empty,
        stats: Stats = .{},

        pub fn init(allocator: std.mem.Allocator, limits: Limits) Self {
            return .{ .allocator = allocator, .limits = limits };
        }

        pub fn deinit(self: *Self) void {
            for (self.slots.items) |slot| self.destroy(slot);
            self.slots.deinit(self.allocator);
            self.* = undefined;
        }

        /// The entry of `key`, now the most recently used; counts a hit or
        /// a miss.
        pub fn get(self: *Self, key: TopologyKey) ?*const Entry {
            const index = self.find(key) orelse {
                self.stats.misses += 1;
                return null;
            };
            self.stats.hits += 1;
            const slot = self.slots.orderedRemove(index);
            self.slots.appendAssumeCapacity(slot);
            return slot.entry;
        }

        /// Takes ownership of `entry` as the most recently used entry of
        /// `key`, then evicts least-recently-used entries until the limits
        /// hold. On error the caller keeps `entry`.
        pub fn publish(self: *Self, key: TopologyKey, entry: Entry) Error!*const Entry {
            if (self.find(key) != null) return error.DuplicateKey;
            const bytes = entry.byteSize();
            if (bytes > self.limits.max_bytes or self.limits.max_entries == 0) return error.EntryExceedsLimits;
            try self.slots.ensureUnusedCapacity(self.allocator, 1);
            const owned = try self.allocator.create(Entry);
            owned.* = entry;
            self.slots.appendAssumeCapacity(.{ .key = key, .entry = owned, .bytes = bytes });
            self.stats.entries += 1;
            self.stats.bytes += bytes;
            while (self.stats.entries > self.limits.max_entries or self.stats.bytes > self.limits.max_bytes) {
                const evicted = self.slots.orderedRemove(0);
                self.destroy(evicted);
                self.stats.evictions += 1;
            }
            return owned;
        }

        fn find(self: *const Self, key: TopologyKey) ?usize {
            for (self.slots.items, 0..) |slot, index| if (slot.key.eql(key)) return index;
            return null;
        }

        fn destroy(self: *Self, slot: Slot) void {
            self.stats.entries -= 1;
            self.stats.bytes -= slot.bytes;
            slot.entry.deinit(self.allocator);
            self.allocator.destroy(slot.entry);
        }
    };
}

const TestEntry = struct {
    values: []u8,

    fn make(allocator: std.mem.Allocator, len: usize) !TestEntry {
        return .{ .values = try allocator.alloc(u8, len) };
    }

    pub fn deinit(self: *TestEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
    }

    pub fn byteSize(self: *const TestEntry) usize {
        return self.values.len;
    }
};

fn testKey(byte: u8) TopologyKey {
    return .{ .digest = [_]u8{byte} ** 32 };
}

test "topology cache: hits, misses and least-recently-used eviction by count" {
    const allocator = std.testing.allocator;
    var cache = TopologyCache(TestEntry).init(allocator, .{ .max_entries = 2 });
    defer cache.deinit();

    try std.testing.expect(cache.get(testKey(1)) == null);
    _ = try cache.publish(testKey(1), try TestEntry.make(allocator, 10));
    _ = try cache.publish(testKey(2), try TestEntry.make(allocator, 20));
    // Touch 1 so that 2 is the least recently used.
    try std.testing.expectEqual(@as(usize, 10), cache.get(testKey(1)).?.values.len);
    _ = try cache.publish(testKey(3), try TestEntry.make(allocator, 30));
    try std.testing.expect(cache.get(testKey(2)) == null);
    try std.testing.expect(cache.get(testKey(1)) != null);
    try std.testing.expect(cache.get(testKey(3)) != null);
    try std.testing.expectEqual(Stats{ .hits = 3, .misses = 2, .evictions = 1, .entries = 2, .bytes = 40 }, cache.stats);
}

test "topology cache: the byte budget evicts others, never the new entry" {
    const allocator = std.testing.allocator;
    var cache = TopologyCache(TestEntry).init(allocator, .{ .max_entries = 8, .max_bytes = 50 });
    defer cache.deinit();
    _ = try cache.publish(testKey(1), try TestEntry.make(allocator, 20));
    _ = try cache.publish(testKey(2), try TestEntry.make(allocator, 20));
    _ = try cache.publish(testKey(3), try TestEntry.make(allocator, 40));
    try std.testing.expectEqual(@as(usize, 1), cache.stats.entries);
    try std.testing.expectEqual(@as(u64, 2), cache.stats.evictions);
    try std.testing.expect(cache.get(testKey(3)) != null);

    var too_big = try TestEntry.make(allocator, 51);
    defer too_big.deinit(allocator);
    try std.testing.expectError(error.EntryExceedsLimits, cache.publish(testKey(4), too_big));
    var duplicate = try TestEntry.make(allocator, 1);
    defer duplicate.deinit(allocator);
    try std.testing.expectError(error.DuplicateKey, cache.publish(testKey(3), duplicate));
    try std.testing.expectEqual(@as(usize, 40), cache.stats.bytes);
}
