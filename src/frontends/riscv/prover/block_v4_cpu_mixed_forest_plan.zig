//! Deterministic radix-four exact forest. Four aligned real children use one
//! local quartet verifier proof; residual pairs use the existing binary proof.
//! This is topology only: keys, proofs and final roster remain receiver-owned.
const std = @import("std");
const spans = @import("../recursion/span_statement_blake3.zig");
const binary = @import("block_v4_cpu_parallel_forest_plan.zig");

pub const Child = struct { node: binary.Ref, slots: spans.SlotSpan };
pub const Kind = enum { pair, quartet };
pub const Task = struct {
    index: u32,
    kind: Kind,
    children: [4]Child,
    slots: spans.SlotSpan,
    pub fn childCount(self: Task) usize {
        return if (self.kind == .pair) 2 else 4;
    }
};
pub const Root = Child;
pub const Plan = struct {
    a: std.mem.Allocator,
    tasks: []Task,
    roots: []Root,
    pub fn deinit(self: *Plan) void {
        self.a.free(self.tasks);
        self.a.free(self.roots);
        self.* = undefined;
    }
};

const Pending = struct {
    count: u8 = 0,
    children: [4]Child = undefined,
};
const Builder = struct {
    a: std.mem.Allocator,
    tasks: std.ArrayList(Task) = .empty,
    pending: [spans.MAX_SLOT_HEIGHT + 1]Pending = [_]Pending{.{}} ** (spans.MAX_SLOT_HEIGHT + 1),

    fn push(self: *Builder, child: Child) !void {
        const height = child.slots.height;
        if (height + 2 >= self.pending.len) return error.MixedForestHeightOverflow;
        const bucket = &self.pending[height];
        if (bucket.count != 0 and bucket.children[bucket.count - 1].slots.endExclusive() != child.slots.first)
            return error.MixedForestOutOfOrder;
        bucket.children[bucket.count] = child;
        bucket.count += 1;
        if (bucket.count != 4) return;
        const quartet = bucket.children;
        bucket.count = 0;
        const next = try self.make(.quartet, quartet);
        try self.push(next);
    }

    fn make(self: *Builder, kind: Kind, children: [4]Child) !Child {
        const count: usize = if (kind == .pair) 2 else 4;
        const height = children[0].slots.height;
        var next = children[0].slots.first;
        for (children[0..count]) |child| {
            if (child.slots.height != height or child.slots.first != next)
                return error.InvalidMixedForestChildren;
            next = child.slots.endExclusive();
        }
        const parent_height = height + @as(u8, if (kind == .pair) 1 else 2);
        const slots = try spans.SlotSpan.init(children[0].slots.first, parent_height);
        if (slots.endExclusive() != next or slots.first % slots.capacity() != 0)
            return error.InvalidMixedForestAlignment;
        const index: u32 = @intCast(self.tasks.items.len);
        try self.tasks.append(self.a, .{ .index = index, .kind = kind, .children = children, .slots = slots });
        return .{ .node = .{ .parent = index }, .slots = slots };
    }

    fn flushPairs(self: *Builder) !void {
        for (0..self.pending.len - 1) |height| {
            const bucket = &self.pending[height];
            while (bucket.count >= 2) {
                const left = bucket.children[0];
                const right = bucket.children[1];
                for (2..bucket.count) |index| bucket.children[index - 2] = bucket.children[index];
                bucket.count -= 2;
                const joined = try self.make(.pair, .{ left, right, undefined, undefined });
                try self.push(joined);
            }
        }
    }
};

/// No dummy leaf is ever introduced. Residual dyadic roots retain the same
/// descending-height exact roster as the binary planner for a given count.
pub fn plan(a: std.mem.Allocator, segment_count: u32) !Plan {
    if (segment_count == 0 or segment_count > 1024) return error.InvalidMixedForestSegmentCount;
    var builder = Builder{ .a = a };
    defer builder.tasks.deinit(a);
    for (0..segment_count) |index| try builder.push(.{
        .node = .{ .leaf = @intCast(index) },
        .slots = try spans.SlotSpan.init(@intCast(index), 0),
    });
    try builder.flushPairs();
    const roots = try a.alloc(Root, @popCount(segment_count));
    errdefer a.free(roots);
    var next: u64 = 0;
    var count: usize = 0;
    for (0..builder.pending.len) |offset| {
        const level = builder.pending.len - offset - 1;
        const bucket = builder.pending[level];
        if (bucket.count > 1) return error.IncompleteMixedForestCarry;
        if (bucket.count == 1) {
            const root = bucket.children[0];
            if (root.slots.first != next or count >= roots.len)
                return error.InvalidMixedForestRootOrder;
            roots[count] = root;
            next = root.slots.endExclusive();
            count += 1;
        }
    }
    if (count != roots.len or next != segment_count)
        return error.InvalidMixedForestRootCoverage;
    return .{ .a = a, .tasks = try builder.tasks.toOwnedSlice(a), .roots = roots };
}

test "218 real leaves plan quartet parents with exact binary residual roots" {
    const a = std.testing.allocator;
    var mixed = try plan(a, 218);
    defer mixed.deinit();
    var pair_count: usize = 0;
    var quartet_count: usize = 0;
    for (mixed.tasks, 0..) |task, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), task.index);
        for (task.children[0..task.childCount()]) |child| switch (child.node) {
            .leaf => |leaf_index| try std.testing.expect(leaf_index < 218),
            .parent => |parent_index| try std.testing.expect(parent_index < task.index),
        };
        if (task.kind == .pair) pair_count += 1 else quartet_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), mixed.roots.len);
    const first = [_]u64{ 0, 128, 192, 208, 216 };
    const height = [_]u8{ 7, 6, 4, 3, 1 };
    for (mixed.roots, first, height) |root, f, h| {
        try std.testing.expectEqual(f, root.slots.first);
        try std.testing.expectEqual(h, root.slots.height);
    }
    try std.testing.expectEqual(@as(usize, 70), quartet_count);
    try std.testing.expectEqual(@as(usize, 3), pair_count);
    try std.testing.expectEqual(@as(usize, 73), mixed.tasks.len);
}

test "mixed planner selects quartet only for four aligned real children" {
    const cases = [_]struct { leaves: u32, quartets: usize, pairs: usize, roots: usize }{
        .{ .leaves = 1, .quartets = 0, .pairs = 0, .roots = 1 },
        .{ .leaves = 2, .quartets = 0, .pairs = 1, .roots = 1 },
        .{ .leaves = 3, .quartets = 0, .pairs = 1, .roots = 2 },
        .{ .leaves = 4, .quartets = 1, .pairs = 0, .roots = 1 },
        .{ .leaves = 5, .quartets = 1, .pairs = 0, .roots = 2 },
        .{ .leaves = 6, .quartets = 1, .pairs = 1, .roots = 2 },
        .{ .leaves = 8, .quartets = 2, .pairs = 1, .roots = 1 },
    };
    for (cases) |case| {
        var found = try plan(std.testing.allocator, case.leaves);
        defer found.deinit();
        var quartets: usize = 0;
        var pairs: usize = 0;
        for (found.tasks) |task| if (task.kind == .quartet) {
            quartets += 1;
        } else {
            pairs += 1;
        };
        try std.testing.expectEqual(case.quartets, quartets);
        try std.testing.expectEqual(case.pairs, pairs);
        try std.testing.expectEqual(case.roots, found.roots.len);
    }
}
