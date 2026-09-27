//! Host setup membership only. These hashes neither admit proof bytes nor
//! derive keys. Constructors independently derive all specs before pinning.
const std = @import("std");
const core = @import("stwo_core");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    version: u32,
    count: usize,
    base: usize,
    tree: [][32]u8,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, version: u32, specs: anytype, maximum: usize) !Owned {
        if (maximum == 0 or specs.len > maximum or specs.len > std.math.maxInt(u32)) return error.CompactFixedInventoryLimit;
        var base: usize = 1;
        while (base < specs.len) base = try std.math.mul(usize, base, 2);
        const tree = try a.alloc([32]u8, try std.math.mul(usize, 2, base));
        errdefer a.free(tree);
        @memset(tree, @splat(0));
        for (specs, 0..) |spec, i| tree[base + i] = try leaf(version, specs.len, @intCast(i), spec);
        var cursor = base;
        while (cursor > 1) {
            cursor -= 1;
            tree[cursor] = pair(version, tree[2 * cursor], tree[2 * cursor + 1]);
        }
        return .{ .allocator = a, .version = version, .count = specs.len, .base = base, .tree = tree, .root = tree[1] };
    }
    pub fn require(self: *const Owned, index: u32, spec: anytype, independently_expected_root: [32]u8) !void {
        if (index >= self.count or self.base == 0 or !std.math.isPowerOfTwo(self.base) or self.base < self.count or self.tree.len != try std.math.mul(usize, 2, self.base) or !std.meta.eql(self.root, independently_expected_root)) return error.UntrustedCompactFixedInventory;
        var digest = try leaf(self.version, self.count, index, spec);
        var cursor = self.base + index;
        while (cursor > 1) {
            digest = if (cursor & 1 == 0) pair(self.version, digest, self.tree[cursor + 1]) else pair(self.version, self.tree[cursor - 1], digest);
            cursor /= 2;
        }
        if (!std.meta.eql(digest, independently_expected_root)) return error.MutatedCompactFixedSpec;
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.tree);
        self.* = undefined;
    }
};
fn leaf(version: u32, count: usize, index: u32, spec: anytype) ![32]u8 {
    if (comptime @hasField(@TypeOf(spec), "schedule")) if (spec.schedule.len != 0) return error.ClosedCompactFixedInventoryHasNoSchedule;
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x43465349, version, @intCast(count), index });
    c.mixRoot(try spec.geometry.identity());
    c.mixRoot(spec.expected_id);
    return c.digestBytes();
}
fn pair(version: u32, left: [32]u8, right: [32]u8) [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x43465350, version });
    c.mixRoot(left);
    c.mixRoot(right);
    return c.digestBytes();
}
