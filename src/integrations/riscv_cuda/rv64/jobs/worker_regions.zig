//! Persistent-region ownership: bounded placement, pinning, retirement and LRU eviction.
const std = @import("std");

const Arena = @import("arena.zig").Arena;
pub const Regions = struct {
    words: usize = 0,
    entries: std.ArrayListUnmanaged(Entry) = .empty, // sorted by offset
    tick: u64 = 0,
    evictions: u64 = 0,
    evicted_words: u64 = 0,
    high_water: usize = 0,

    pub const Entry = struct { key: [32]u8, offset: usize, words: usize, requested: usize, last_use: u64, pins: u32 = 0, retired: bool = false };
    pub const Acquired = struct { offset: usize, fresh: bool };

    pub fn deinit(self: *Regions, a: std.mem.Allocator) void {
        self.entries.deinit(a);
    }
    pub fn find(self: *const Regions, key: [32]u8) ?usize {
        for (self.entries.items, 0..) |e, i| if (!e.retired and std.mem.eql(u8, &e.key, &key)) return i;
        return null;
    }
    /// Find or place `key`; pins it (one `unpin` per successful acquire).
    pub fn acquire(self: *Regions, a: std.mem.Allocator, key: [32]u8, requested: usize) !Acquired {
        if (requested == 0) return error.InvalidAllocation;
        self.tick += 1;
        if (self.find(key)) |i| {
            const e = &self.entries.items[i];
            if (e.requested != requested) return error.PersistentGeometryMismatch;
            e.last_use = self.tick;
            e.pins += 1;
            return .{ .offset = e.offset, .fresh = false };
        }
        const words = std.mem.alignForward(usize, requested, Arena.granule);
        if (words > self.words) return error.PersistentRegionExceedsBudget;
        try self.entries.ensureUnusedCapacity(a, 1);
        // Fail without evicting when even evicting every unpinned region cannot make room.
        if (self.gap(words, true) == null) return error.PersistentBudgetExhausted;
        while (true) {
            if (self.gap(words, false)) |g| {
                self.entries.insertAssumeCapacity(g.index, .{ .key = key, .offset = g.offset, .words = words, .requested = requested, .last_use = self.tick, .pins = 1 });
                self.high_water = @max(self.high_water, g.offset + words);
                return .{ .offset = g.offset, .fresh = true };
            }
            var victim: ?usize = null;
            for (self.entries.items, 0..) |e, i| {
                if (e.pins != 0 or e.retired) continue;
                if (victim == null or e.last_use < self.entries.items[victim.?].last_use) victim = i;
            }
            const v = victim orelse return error.PersistentBudgetExhausted;
            self.evictions += 1;
            self.evicted_words += self.entries.items[v].words;
            _ = self.entries.orderedRemove(v);
        }
    }
    /// First fit. `evictable_free`: treat unpinned live regions as free (feasibility only).
    fn gap(self: *const Regions, words: usize, evictable_free: bool) ?struct { index: usize, offset: usize } {
        var end: usize = 0;
        for (self.entries.items, 0..) |e, i| {
            if (evictable_free and e.pins == 0 and !e.retired) continue;
            if (e.offset - end >= words) return .{ .index = i, .offset = end };
            end = e.offset + e.words;
        }
        if (self.words - end >= words) return .{ .index = self.entries.items.len, .offset = end };
        return null;
    }
    pub fn unpin(self: *Regions, key: [32]u8) void {
        for (self.entries.items) |*e| if (std.mem.eql(u8, &e.key, &key) and e.pins != 0) {
            e.pins -= 1;
            return;
        };
    }
    /// A failed fill: keep the space occupied forever, never hand it out again.
    pub fn retire(self: *Regions, key: [32]u8) void {
        if (self.find(key)) |i| self.entries.items[i].retired = true;
    }
    pub fn used(self: *const Regions) usize {
        var n: usize = 0;
        for (self.entries.items) |e| n += e.words;
        return n;
    }
};
