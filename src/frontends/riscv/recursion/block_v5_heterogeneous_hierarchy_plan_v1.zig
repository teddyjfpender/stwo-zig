//! Exact, unpadded Coverage topology. This is independent policy, never a
//! completion receipt. Native spans are optional actual descendant ranges.
const std = @import("std");
const core = @import("stwo_core");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Full = @import("block_v5_heterogeneous_policy_v1.zig").Policy;
const Spans = @import("block_v5_pc_clock_span_v1.zig");
pub const VERSION: u32 = 1;
pub const Ref = Coverage.Ref;
pub const Bounds = struct { first: u32, count: u32, schema: [Coverage.KIND_COUNT]u32 };
pub const Limits = struct { max_nodes: usize = 32768, max_leaves: usize = 32768, max_export_cells: usize = 1 << 22, max_total_export_cells: usize = 1 << 26, max_total_source_cells: usize = 1 << 26 };
pub const Plan = struct {
    full: Full,
    expected_coverage: [32]u8,
    limits: Limits = .{},
    pub fn validate(self: Plan) !void {
        try self.full.validate();
        const meta = self.full.plan.meta;
        try checkTopology(self.full.children[0].arena.child_allocator, meta.physical, meta.nodes, meta.root, meta.fan_in, self.limits);
        if (!std.meta.eql(self.expected_coverage, self.full.plan.pinned_digest) or meta.physical.len > self.limits.max_leaves or meta.nodes.len > self.limits.max_nodes or self.limits.max_export_cells == 0) return error.UntrustedHeterogeneousHierarchy;
        var total_cells: usize = 0;
        for (meta.nodes, 0..) |node, index| {
            if (node.child_count < 2 or node.child_count > @intFromEnum(meta.fan_in) or node.child_count > 4) return error.InvalidHeterogeneousHierarchyTopology;
            var derived = Bounds{ .first = node.first_leaf, .count = 0, .schema = @splat(0) };
            for (node.children[0..node.child_count]) |child| {
                if (child == .node and child.node >= index) return error.InvalidHeterogeneousHierarchyTopology;
                const child_bounds = try self.bounds(child);
                if (child_bounds.first != try std.math.add(u32, derived.first, derived.count)) return error.InvalidHeterogeneousHierarchyTopology;
                derived.count = try std.math.add(u32, derived.count, child_bounds.count);
                for (&derived.schema, child_bounds.schema) |*sum, count| sum.* = try std.math.add(u32, sum.*, count);
            }
            if (derived.count != node.leaf_count or !std.meta.eql(derived.schema, node.schema_counts)) return error.InvalidHeterogeneousHierarchyTopology;
            _ = try self.bounds(.{ .node = @intCast(index) });
            var cells: usize = 0;
            for (self.full.children[node.first_leaf..][0..node.leaf_count]) |child| cells = try std.math.add(usize, cells, child.cells.len);
            total_cells = try std.math.add(usize, total_cells, cells);
            if (cells > self.limits.max_export_cells or total_cells > self.limits.max_total_export_cells) return error.HeterogeneousHierarchyResourceLimit;
            _ = try self.span(.{ .node = @intCast(index) });
        }
        const root = try self.bounds(meta.root);
        if (root.first != 0 or root.count != self.full.children.len) return error.IncompleteHeterogeneousHierarchy;
        const native = (try self.span(meta.root)) orelse return error.MissingHeterogeneousNativeSpan;
        if (native.first_index != 0 or native.segment_count != native.job_segment_count) return error.IncompleteHeterogeneousNativeSpan;
    }
    pub fn bounds(self: Plan, ref: Ref) !Bounds {
        return switch (ref) {
            .leaf => |index| block: {
                if (index >= self.full.children.len) return error.InvalidHeterogeneousHierarchyTopology;
                var counts: [Coverage.KIND_COUNT]u32 = @splat(0);
                counts[@intFromEnum(self.full.children[index].physical.kind)] = 1;
                break :block .{ .first = index, .count = 1, .schema = counts };
            },
            .node => |index| block: {
                if (index >= self.full.plan.meta.nodes.len) return error.InvalidHeterogeneousHierarchyTopology;
                const node = self.full.plan.meta.nodes[index];
                if (node.first_leaf > self.full.children.len or node.leaf_count > self.full.children.len - node.first_leaf) return error.InvalidHeterogeneousHierarchyTopology;
                break :block .{ .first = node.first_leaf, .count = node.leaf_count, .schema = node.schema_counts };
            },
        };
    }
    pub fn span(self: Plan, ref: Ref) !?Spans.Span {
        const extent = try self.bounds(ref);
        var output: ?Spans.Span = null;
        for (self.full.children[extent.first..][0..extent.count]) |child| if (child.span) |child_span| {
            output = if (output) |previous| try Spans.merge(&.{ previous, child_span }) else child_span;
        };
        return output;
    }
    pub fn nodeIdentity(self: Plan, index: u32) ![32]u8 {
        if (index >= self.full.plan.meta.nodes.len) return error.InvalidHeterogeneousHierarchyTopology;
        const node = self.full.plan.meta.nodes[index];
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354854, VERSION, index, node.first_leaf, node.leaf_count, node.child_count }); // B5HT
        channel.mixRoot(self.expected_coverage);
        channel.mixRoot(self.full.plan.meta.seal_digest);
        channel.mixU32s(&node.schema_counts);
        for (node.children[0..node.child_count]) |child| channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(child)), switch (child) {
            .leaf, .node => |value| value,
        } });
        const node_span = try self.span(.{ .node = index });
        channel.mixU32s(&.{@intFromBool(node_span != null)});
        if (node_span) |native| channel.mixRoot(try native.identity());
        return channel.digestBytes();
    }
};
/// Exact tree shape/census, independent of proof/source authority. Each actual
/// physical leaf has exactly one incoming edge; carried tails are not padded.
pub fn checkTopology(a: std.mem.Allocator, physical: []const Coverage.Physical, nodes: []const Coverage.Node, root: Ref, fan_in: Coverage.FanIn, limits: Limits) !void {
    if (physical.len == 0 or physical.len > limits.max_leaves or nodes.len > limits.max_nodes) return error.HeterogeneousHierarchyResourceLimit;
    const leaf_uses = try a.alloc(u32, physical.len);
    defer a.free(leaf_uses);
    @memset(leaf_uses, 0);
    const node_uses = try a.alloc(u32, nodes.len);
    defer a.free(node_uses);
    @memset(node_uses, 0);
    for (nodes, 0..) |node, index| {
        if (node.child_count < 2 or node.child_count > @intFromEnum(fan_in) or node.child_count > 4 or node.first_leaf > physical.len or node.leaf_count > physical.len - node.first_leaf) return error.InvalidHeterogeneousHierarchyTopology;
        var derived = Bounds{ .first = node.first_leaf, .count = 0, .schema = @splat(0) };
        for (node.children[0..node.child_count]) |ref| {
            const child = switch (ref) {
                .leaf => |ordinal| block: {
                    if (ordinal >= physical.len) return error.InvalidHeterogeneousHierarchyTopology;
                    leaf_uses[ordinal] = try std.math.add(u32, leaf_uses[ordinal], 1);
                    var schema: [Coverage.KIND_COUNT]u32 = @splat(0);
                    schema[@intFromEnum(physical[ordinal].kind)] = 1;
                    break :block Bounds{ .first = ordinal, .count = 1, .schema = schema };
                },
                .node => |ordinal| block: {
                    if (ordinal >= index) return error.InvalidHeterogeneousHierarchyTopology;
                    node_uses[ordinal] = try std.math.add(u32, node_uses[ordinal], 1);
                    break :block Bounds{ .first = nodes[ordinal].first_leaf, .count = nodes[ordinal].leaf_count, .schema = nodes[ordinal].schema_counts };
                },
            };
            if (child.first != try std.math.add(u32, derived.first, derived.count)) return error.InvalidHeterogeneousHierarchyTopology;
            derived.count = try std.math.add(u32, derived.count, child.count);
            for (&derived.schema, child.schema) |*sum, count| sum.* = try std.math.add(u32, sum.*, count);
        }
        if (derived.count != node.leaf_count or !std.meta.eql(derived.schema, node.schema_counts)) return error.InvalidHeterogeneousHierarchyTopology;
    }
    switch (root) {
        .leaf => |ordinal| {
            if (physical.len != 1 or nodes.len != 0 or ordinal != 0) return error.IncompleteHeterogeneousHierarchy;
            return;
        },
        .node => |ordinal| {
            if (ordinal >= nodes.len or nodes[ordinal].first_leaf != 0 or nodes[ordinal].leaf_count != physical.len) return error.IncompleteHeterogeneousHierarchy;
            for (node_uses, 0..) |uses, index| if (uses != @as(u32, @intFromBool(index != ordinal))) return error.IncompleteHeterogeneousHierarchy;
            for (leaf_uses) |uses| if (uses != 1) return error.IncompleteHeterogeneousHierarchy;
        },
    }
}
