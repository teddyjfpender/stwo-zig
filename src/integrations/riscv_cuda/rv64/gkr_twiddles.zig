//! Immutable canonical transform setup; never contains request/transcript data.
const std = @import("std");
const core = @import("stwo_core");
const tw = @import("stwo_prover_engine").poly.twiddles;
const M = core.fields.m31.M31;
const Tree = tw.TwiddleTree([]M);
pub const Borrow = struct {
    values: []const M,
    allocator: std.mem.Allocator,
    owned: ?Tree = null,
    cache_hit: bool,
    pub fn deinit(self: *Borrow) void {
        if (self.owned) |*tree| tw.deinitM31(self.allocator, tree);
        self.* = undefined;
    }
};
pub const Cache = struct {
    allocator: std.mem.Allocator,
    cap: usize = 32 * 1024 * 1024,
    tree: ?Tree = null,
    retained_bytes: usize = 0,
    pub fn deinit(self: *Cache) void {
        if (self.tree) |*tree| tw.deinitM31(self.allocator, tree);
        self.* = undefined;
    }
    /// Called on the session owner thread. A borrow lasts through the existing
    /// ingress join; the next acquire may replace the one retained tower.
    pub fn acquire(self: *Cache, log: u32) !Borrow {
        if (log == 0 or log > 30) return error.InvalidTwiddleLog;
        const root = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset;
        if (self.tree) |tree| {
            if (root.logSize() <= tree.root_coset.logSize()) {
                const sub = try tree.subtree(root.logSize());
                if (std.meta.eql(sub.root_coset, root)) return .{ .values = sub.twiddles, .allocator = self.allocator, .cache_hit = true };
            }
        }
        const bytes = try std.math.mul(usize, root.size(), 2 * @sizeOf(M));
        if (bytes > self.cap) {
            const tree = try tw.precomputeM31(self.allocator, root);
            return .{ .values = tree.twiddles, .allocator = self.allocator, .owned = tree, .cache_hit = false };
        }
        if (self.tree) |*tree| tw.deinitM31(self.allocator, tree);
        self.tree = null;
        self.retained_bytes = 0;
        const tree = try tw.precomputeM31(self.allocator, root);
        self.tree = tree;
        self.retained_bytes = bytes;
        return .{ .values = tree.twiddles, .allocator = self.allocator, .cache_hit = false };
    }
};
test "GKR immutable setup cache matches independent canonical towers and bounds retention" {
    const a = std.testing.allocator;
    var cache = Cache{ .allocator = a, .cap = 8192 };
    defer cache.deinit();
    for ([_]u32{ 10, 8, 10, 11, 9, 12, 11 }) |log| {
        var actual = try cache.acquire(log);
        defer actual.deinit();
        var expected = try tw.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        defer tw.deinitM31(a, &expected);
        try std.testing.expectEqualSlices(M, expected.twiddles, actual.values);
        try std.testing.expect(cache.retained_bytes <= cache.cap);
        if (log == 12) try std.testing.expect(actual.owned != null);
    }
    var repeated = try cache.acquire(11);
    defer repeated.deinit();
    try std.testing.expect(repeated.cache_hit);
    try std.testing.expectError(error.InvalidTwiddleLog, cache.acquire(0));
}
