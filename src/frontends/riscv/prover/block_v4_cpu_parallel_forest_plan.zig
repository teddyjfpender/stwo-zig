//! Deterministic exact-count parent DAG. This is a scheduling hint only:
//! every produced node still needs its admitted key and fresh proof check.
const std = @import("std");
const span = @import("../recursion/span_statement_blake3.zig");

pub const Ref = union(enum) { leaf: u32, parent: u32 };
pub const Task = struct {
    index: u32,
    left: Ref,
    right: Ref,
    slots: span.SlotSpan,
};
pub const Root = struct { node: Ref, slots: span.SlotSpan };

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

/// Parent indices match the existing streaming frontier's carry/postorder.
/// Workers may complete ready tasks out of order but must publish results at
/// these indices and prove the exact named span. There are no padding leaves.
pub fn plan(a: std.mem.Allocator, segment_count: u32) !Plan {
    if (segment_count == 0 or segment_count > 1024)
        return error.InvalidParallelForestSegmentCount;
    var tasks: std.ArrayList(Task) = .empty;
    defer tasks.deinit(a);
    var refs: [span.MAX_SLOT_HEIGHT + 1]?Ref = @splat(null);
    var slots: [span.MAX_SLOT_HEIGHT + 1]?span.SlotSpan = @splat(null);
    for (0..segment_count) |index| {
        var right: Ref = .{ .leaf = @intCast(index) };
        var right_slots = try span.SlotSpan.init(@intCast(index), 0);
        var height: usize = 0;
        while (refs[height]) |left| {
            const left_slots = slots[height].?;
            if (left_slots.height != right_slots.height or
                left_slots.endExclusive() != right_slots.first or
                height + 1 >= refs.len)
                return error.InvalidParallelForestCarry;
            const parent_slots = try span.SlotSpan.init(left_slots.first, @intCast(height + 1));
            const task_index: u32 = @intCast(tasks.items.len);
            try tasks.append(a, .{ .index = task_index, .left = left, .right = right, .slots = parent_slots });
            refs[height] = null;
            slots[height] = null;
            right = .{ .parent = task_index };
            right_slots = parent_slots;
            height += 1;
        }
        refs[height] = right;
        slots[height] = right_slots;
    }
    if (tasks.items.len != @as(usize, segment_count - @popCount(segment_count)))
        return error.InvalidParallelForestTaskCount;
    const roots = try a.alloc(Root, @popCount(segment_count));
    errdefer a.free(roots);
    var next: u64 = 0;
    var count: usize = 0;
    for (0..refs.len) |offset| {
        const level = refs.len - offset - 1;
        if (refs[level]) |node| {
            const root_slots = slots[level].?;
            if (root_slots.first != next) return error.InvalidParallelForestRootOrder;
            roots[count] = .{ .node = node, .slots = root_slots };
            count += 1;
            next = root_slots.endExclusive();
        }
    }
    if (count != roots.len or next != segment_count)
        return error.InvalidParallelForestRootCoverage;
    return .{ .a = a, .tasks = try tasks.toOwnedSlice(a), .roots = roots };
}

test "218 exact leaves plan 213 dyadic parents and five roots without padding" {
    const a = std.testing.allocator;
    var dag = try plan(a, 218);
    defer dag.deinit();
    try std.testing.expectEqual(@as(usize, 213), dag.tasks.len);
    try std.testing.expectEqual(@as(usize, 5), dag.roots.len);
    const expected_first = [_]u64{ 0, 128, 192, 208, 216 };
    const expected_height = [_]u8{ 7, 6, 4, 3, 1 };
    for (dag.roots, expected_first, expected_height) |root, first, height| {
        try std.testing.expectEqual(first, root.slots.first);
        try std.testing.expectEqual(height, root.slots.height);
    }
    for (dag.tasks, 0..) |task, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), task.index);
        for ([_]Ref{ task.left, task.right }) |dependency| switch (dependency) {
            .leaf => |leaf_index| try std.testing.expect(leaf_index < 218),
            .parent => |parent_index| try std.testing.expect(parent_index < task.index),
        };
    }
}
