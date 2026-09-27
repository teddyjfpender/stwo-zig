//! Pure inventory hashing over digest metadata, never protocol Key receipts.
const std = @import("std");
const core = @import("stwo_core");
const Inventory = @import("../recursion/block_v5_compact_fixed_spec_inventory_v1.zig");
const Metadata = struct {
    geometry: struct {
        word: u32,
        pub fn identity(self: *const @This()) ![32]u8 {
            var c = core.channel.blake3.Channel{};
            c.mixU32s(&.{ 0x54455354, self.word });
            return c.digestBytes();
        }
    },
    expected_id: [32]u8,
};
fn records() [17]Metadata {
    var values: [17]Metadata = undefined;
    for (&values, 0..) |*value, i| value.* = .{ .geometry = .{ .word = @intCast(i) }, .expected_id = @splat(@intCast(i + 1)) };
    return values;
}
test "compact memory fixed assembly: bounded selected inventory exact17 no rounding or host authority" {
    const values = records();
    var inventory = try Inventory.Owned.init(std.testing.allocator, 19, &values, values.len);
    defer inventory.deinit();
    try std.testing.expectEqual(@as(usize, 17), inventory.count);
    const independent = inventory.root;
    for (values, 0..) |value, i| try inventory.require(@intCast(i), value, independent);
    try std.testing.expectError(error.UntrustedCompactFixedInventory, inventory.require(17, values[0], independent));
    var other = try Inventory.Owned.init(std.testing.allocator, 16, &values, values.len);
    defer other.deinit();
    try std.testing.expect(!std.meta.eql(independent, other.root));
}
test "compact memory fixed assembly: re-sealed selector key identity order and inventory mutations reject original pin" {
    const values = records();
    var inventory = try Inventory.Owned.init(std.testing.allocator, 19, &values, values.len);
    defer inventory.deinit();
    const independent = inventory.root;
    var changed = values[7];
    changed.geometry.word ^= 1;
    try std.testing.expectError(error.MutatedCompactFixedSpec, inventory.require(7, changed, independent));
    changed = values[7];
    changed.expected_id[0] ^= 1;
    try std.testing.expectError(error.MutatedCompactFixedSpec, inventory.require(7, changed, independent));
    try std.testing.expectError(error.MutatedCompactFixedSpec, inventory.require(7, values[8], independent));
    inventory.tree[inventory.base + 6][0] ^= 1;
    try std.testing.expectError(error.MutatedCompactFixedSpec, inventory.require(7, values[7], independent));
    var resealed_values = values;
    resealed_values[7] = changed;
    var resealed = try Inventory.Owned.init(std.testing.allocator, 19, &resealed_values, values.len);
    defer resealed.deinit();
    try std.testing.expectError(error.UntrustedCompactFixedInventory, resealed.require(7, changed, independent));
}
fn oom(a: std.mem.Allocator) !void {
    const values = records();
    var owned = try Inventory.Owned.init(a, 19, &values, 17);
    defer owned.deinit();
    try owned.require(16, values[16], owned.root);
}
test "compact memory fixed assembly: inventory bounds empty absence and allocation failures" {
    const values = records();
    try std.testing.expectError(error.CompactFixedInventoryLimit, Inventory.Owned.init(std.testing.allocator, 19, &values, 16));
    var empty = try Inventory.Owned.init(std.testing.allocator, 19, &[_]Metadata{}, 1);
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.count);
    try std.testing.expectError(error.UntrustedCompactFixedInventory, empty.require(0, values[0], empty.root));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, oom, .{});
}
