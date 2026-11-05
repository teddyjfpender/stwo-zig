//! Producer-only distinct aligned RAM-word count. The direct bitmap covers
//! guest addresses below4GiB; the exact far-key fallback keeps all u64 words.
//! No iteration order is exposed, and no membership enters proof authority.
const std = @import("std");
const LEAF_ADDRESS_BITS = 22;
const DIRECT_ADDRESS_BITS = 32;
const LEAVES = 1 << (DIRECT_ADDRESS_BITS - LEAF_ADDRESS_BITS);
const Leaf = [1 << (LEAF_ADDRESS_BITS - 3 - 6)]u64;
pub const Set = struct {
    direct: [LEAVES]?*Leaf = @splat(null),
    far: std.AutoHashMapUnmanaged(u64, void) = .empty,
    direct_count: usize = 0,
    cached_index: usize = LEAVES,
    cached: ?*Leaf = null,
    pub fn deinit(self: *Set, a: std.mem.Allocator) void {
        for (self.direct) |leaf| if (leaf) |p| a.destroy(p);
        self.far.deinit(a);
        self.* = undefined;
    }
    pub fn count(self: *const Set) usize {
        return self.direct_count + self.far.count();
    }
    pub fn insert(self: *Set, a: std.mem.Allocator, address: u64) !void {
        std.debug.assert(address & 7 == 0);
        if (address >= @as(u64, 1) << DIRECT_ADDRESS_BITS) return self.far.put(a, address, {});
        const index: usize = @intCast(address >> LEAF_ADDRESS_BITS);
        const leaf = if (self.cached_index == index) self.cached.? else blk: {
            if (self.direct[index] == null) {
                const p = try a.create(Leaf);
                p.* = @splat(0);
                self.direct[index] = p;
            }
            self.cached_index = index;
            self.cached = self.direct[index];
            break :blk self.cached.?;
        };
        const word: usize = @intCast((address & ((1 << LEAF_ADDRESS_BITS) - 1)) >> 3);
        const mask = @as(u64, 1) << @as(u6, @truncate(word));
        const previous = leaf[word >> 6];
        self.direct_count += @intFromBool(previous & mask == 0);
        leaf[word >> 6] = previous | mask;
    }
};

test "word bitmap equals hashing on repeated, boundary and far addresses" {
    const a = std.testing.allocator;
    var set = Set{};
    defer set.deinit(a);
    var reference: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer reference.deinit(a);
    const boundaries = [_]u64{ 0, 8, (1 << 22) - 8, 1 << 22, (1 << 32) - 8, 1 << 32, std.math.maxInt(u64) - 7 };
    for (boundaries ++ boundaries) |address| {
        try set.insert(a, address);
        try reference.put(a, address, {});
        try std.testing.expectEqual(reference.count(), set.count());
    }
    var rng = std.Random.DefaultPrng.init(0x574f52445f534554);
    for (0..200_000) |_| {
        const r = rng.random();
        const region = boundaries[r.uintLessThan(usize, boundaries.len)];
        const address = (region +% r.uintLessThan(u64, 1 << 16)) & ~@as(u64, 7);
        try set.insert(a, address);
        try reference.put(a, address, {});
    }
    try std.testing.expectEqual(reference.count(), set.count());
}
fn allocationCase(a: std.mem.Allocator) !void {
    var set = Set{};
    defer set.deinit(a);
    for ([_]u64{ 0, 8, 1 << 22, (1 << 32) - 8, 1 << 32, std.math.maxInt(u64) - 7 }) |address| try set.insert(a, address);
    try std.testing.expectEqual(@as(usize, 6), set.count());
}
test "word bitmap releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
