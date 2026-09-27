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
                const joined = try self.make(.pair, .{ left, right, .{ .node = .{ .leaf = 0 }, .slots = try spans.SlotSpan.init(0, 0) }, .{ .node = .{ .leaf = 0 }, .slots = try spans.SlotSpan.init(0, 0) } });
                try self.push(joined);
            }
        }
    }
};

/// No dummy leaf is ever introduced. Residual dyadic roots retain the same
/// descending-height exact roster as the binary planner for a given count.
pub fn plan(a: std.mem.Allocator, segment_count: u32, maximum_count: u32) !Plan {
    // Resource policy is explicit. The public PC/index algebra is bounded below
    // 2^30 separately; no arbitrary 1024-leaf cryptographic ceiling is inherited.
    if (segment_count == 0 or segment_count >= 1 << 30) return error.InvalidMixedForestSegmentCount;
    if (segment_count > maximum_count) return error.V5ExactForestResourceLimit;
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
