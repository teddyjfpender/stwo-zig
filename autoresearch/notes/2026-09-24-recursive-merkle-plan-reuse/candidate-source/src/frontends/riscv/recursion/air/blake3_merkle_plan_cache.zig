//! Two canonical hash graphs, independent of witness bytes and namespaces.
//! Returned views last until the next get/deinit; callers finish emission first.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("blake3_hash_plan.zig");

pub const Pair = struct { leaf: *const graph.Plan, node: *const graph.Plan };
pub const Cache = struct {
    allocator: std.mem.Allocator,
    node: ?graph.Plan = null,
    leaf: ?graph.Plan = null,
    builds: usize = 0,

    pub fn init(a: std.mem.Allocator) Cache {
        return .{ .allocator = a };
    }
    pub fn deinit(self: *Cache) void {
        if (self.leaf) |*plan| plan.deinit();
        if (self.node) |*plan| plan.deinit();
        self.* = undefined;
    }
    pub fn retainedCount(self: *const Cache) usize {
        return @as(usize, @intFromBool(self.node != null)) + @intFromBool(self.leaf != null);
    }
    pub fn get(self: *Cache, leaf_len: usize) !Pair {
        if (self.node == null) {
            const len = try (core.channel.blake3.Frame{ .node = .{ .left = @splat(0), .right = @splat(0) } }).encodedSize();
            self.node = try graph.build(self.allocator, len);
            self.builds += 1;
        }
        if (self.node.?.input_len == leaf_len) return .{ .leaf = &self.node.?, .node = &self.node.? };
        if (self.leaf == null or self.leaf.?.input_len != leaf_len) {
            // Build before replacing: failure preserves the previous plan.
            const replacement = try graph.build(self.allocator, leaf_len);
            if (self.leaf) |*old| old.deinit();
            self.leaf = replacement;
            self.builds += 1;
        }
        return .{ .leaf = &self.leaf.?, .node = &self.node.? };
    }
};
