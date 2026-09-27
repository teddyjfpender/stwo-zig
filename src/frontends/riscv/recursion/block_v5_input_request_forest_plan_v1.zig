//! Exact original B5WM/v2 request topology. Derived solely from independently
//! expected job windows and typed leaf policy, never proof files/manifests.
//! Interior fan-in<=4; one final carrier node consumes the unique summary root.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Input = @import("block_v5_input_tail_public_v1.zig");
const Leaf = @import("block_v5_tail_linked_public_windows_receiver_v2.zig");
pub const FAN_IN = 4;
pub const VERSION: u32 = 1;
pub const Ref = union(enum) { leaf: u32, node: u32 };
pub const Range = struct { first: u32, count: u32, leaves: u32 };
pub const Node = struct {
    kind: enum(u32) { merge, carrier },
    children: [FAN_IN]Ref,
    child_count: u32,
    range: Range,
};
pub const Limits = struct { max_leaves: usize = 1 << 20, max_nodes: usize = 1 << 20 };
fn combine(ranges: []const Range) !Range {
    if (ranges.len == 0 or ranges.len > FAN_IN) return error.InvalidInputRequestForest;
    var cursor = ranges[0].first;
    var leaves: u32 = 0;
    for (ranges) |range| {
        if (range.count == 0 or range.leaves == 0 or range.first != cursor) return error.InvalidInputRequestForest;
        cursor = try std.math.add(u32, cursor, range.count);
        leaves = try std.math.add(u32, leaves, range.leaves);
    }
    return .{ .first = ranges[0].first, .count = cursor - ranges[0].first, .leaves = leaves };
}
pub const Geometry = struct {
    allocator: std.mem.Allocator,
    leaves: []Range,
    nodes: []Node,
    root: u32,
    digest: [32]u8,
    pub fn deinit(self: *Geometry) void {
        self.allocator.free(self.leaves);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
    pub fn range(self: *const Geometry, ref: Ref) !Range {
        return switch (ref) {
            .leaf => |index| if (index < self.leaves.len) self.leaves[index] else error.InvalidInputRequestForest,
            .node => |index| if (index < self.nodes.len) self.nodes[index].range else error.InvalidInputRequestForest,
        };
    }
};
/// Pure exact topology oracle: every leaf covers original global window indices;
/// no rounded count, repeated leaf, skipped index or received node is admitted.
pub fn derive(a: std.mem.Allocator, ranges: []const Range, total_windows: u32, limits: Limits) !Geometry {
    if (ranges.len == 0 or ranges.len > limits.max_leaves or limits.max_nodes == 0 or total_windows == 0 or total_windows >= 1 << 30 or ranges.len > std.math.maxInt(u32)) return error.InputRequestForestResourceLimit;
    var cursor: u32 = 0;
    for (ranges) |range| {
        if (range.first != cursor or range.count == 0 or range.count > 4 or range.leaves != 1) return error.InvalidInputRequestForest;
        cursor = try std.math.add(u32, cursor, range.count);
    }
    if (cursor != total_windows) return error.InvalidInputRequestForest;
    const leaves = try a.dupe(Range, ranges);
    errdefer a.free(leaves);
    var nodes: std.ArrayList(Node) = .empty;
    errdefer nodes.deinit(a);
    var current: std.ArrayList(Ref) = .empty;
    defer current.deinit(a);
    for (ranges, 0..) |_, index| try current.append(a, .{ .leaf = @intCast(index) });
    while (current.items.len > 1) {
        var next: std.ArrayList(Ref) = .empty;
        errdefer next.deinit(a);
        var first: usize = 0;
        while (first < current.items.len) {
            const end = @min(first + FAN_IN, current.items.len);
            const count = end - first;
            // Carry a short remainder into the next level. Proving it here
            // would consume an extra parent without increasing capacity; the
            // final <=4 refs are merged once, in their original exact order.
            if (count < FAN_IN and current.items.len > FAN_IN) {
                try next.appendSlice(a, current.items[first..end]);
                first = end;
                continue;
            }
            var children: [FAN_IN]Ref = @splat(.{ .leaf = 0 });
            @memcpy(children[0..count], current.items[first..end]);
            var child_ranges: [FAN_IN]Range = undefined;
            for (children[0..count], child_ranges[0..count]) |child, *range| range.* = switch (child) {
                .leaf => |i| leaves[i],
                .node => |i| nodes.items[i].range,
            };
            if (nodes.items.len >= limits.max_nodes) return error.InputRequestForestResourceLimit;
            const index: u32 = @intCast(nodes.items.len);
            try nodes.append(a, .{ .kind = .merge, .children = children, .child_count = @intCast(count), .range = try combine(child_ranges[0..count]) });
            try next.append(a, .{ .node = index });
            first = end;
        }
        current.deinit(a);
        current = next;
    }
    const summary = current.items[0];
    const summary_range = switch (summary) {
        .leaf => |i| leaves[i],
        .node => |i| nodes.items[i].range,
    };
    if (summary_range.first != 0 or summary_range.count != total_windows or summary_range.leaves != ranges.len) return error.InvalidInputRequestForest;
    if (nodes.items.len >= limits.max_nodes) return error.InputRequestForestResourceLimit;
    const root: u32 = @intCast(nodes.items.len);
    try nodes.append(a, .{ .kind = .carrier, .children = .{ summary, .{ .leaf = 0 }, .{ .leaf = 0 }, .{ .leaf = 0 } }, .child_count = 1, .range = summary_range });
    const owned = try nodes.toOwnedSlice(a);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354946, VERSION, total_windows, @intCast(leaves.len), @intCast(owned.len), root });
    for (owned) |node| {
        channel.mixU32s(&.{ @intFromEnum(node.kind), node.range.first, node.range.count, node.range.leaves, node.child_count });
        for (node.children[0..node.child_count]) |child| switch (child) {
            .leaf => |i| channel.mixU32s(&.{ 0, i }),
            .node => |i| channel.mixU32s(&.{ 1, i }),
        };
    }
    return .{ .allocator = a, .leaves = leaves, .nodes = owned, .root = root, .digest = channel.digestBytes() };
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    input: *Input.Owned,
    expected_input: Input.Pin,
    /// Independently admitted original child Prepared/key/schedule owners must
    /// outlive this borrow and all forest readers. No envelope grants custody.
    policies: []const Leaf.Policy,
    geometry: Geometry,
    limits: Limits,
    pub const complete_source_authority = false;
    pub fn init(a: std.mem.Allocator, input: *Input.Owned, expected_input: Input.Pin, policies: []const Leaf.Policy, limits: Limits) !Owned {
        try input.require(expected_input);
        if (policies.len == 0 or policies.len > limits.max_leaves) return error.InputRequestForestResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const retained = input.retain();
        errdefer retained.deinit();
        const ranges = try a.alloc(Range, policies.len);
        defer a.free(ranges);
        for (policies, ranges) |policy, *range| {
            try policy.public.validate();
            if (policy.public.input != input or !std.meta.eql(policy.public.input_expected, expected_input) or policy.public.expected != input.job) return error.InvalidInputRequestForest;
            range.* = .{ .first = policy.public.first_window, .count = @intCast(policy.public.instances.len), .leaves = 1 };
        }
        const geometry = try derive(a, ranges, @intCast(input.job.expected().windows.len), limits);
        return .{ .allocator = a, .allocation_owner = lease, .input = retained, .expected_input = expected_input, .policies = policies, .geometry = geometry, .limits = limits };
    }
    pub fn validate(self: *const Owned) !void {
        try self.input.require(self.expected_input);
        var expected = try Owned.init(self.allocator, self.input, self.expected_input, self.policies, self.limits);
        defer expected.deinit();
        if (!std.meta.eql(self.geometry.digest, expected.geometry.digest) or self.geometry.root != expected.geometry.root or self.geometry.leaves.len != expected.geometry.leaves.len or self.geometry.nodes.len != expected.geometry.nodes.len) return error.MutatedInputRequestForest;
        for (self.geometry.leaves, expected.geometry.leaves) |a, b| if (!std.meta.eql(a, b)) return error.MutatedInputRequestForest;
        for (self.geometry.nodes, expected.geometry.nodes) |a, b| if (!std.meta.eql(a, b)) return error.MutatedInputRequestForest;
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.allocation_owner;
        self.geometry.deinit();
        self.input.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
