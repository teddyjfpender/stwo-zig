//! Enqueue-only trace commitment for job paths. Same transforms, same order,
//! same Merkle kernel as trace_commit.zig's non-streamed beta=1 path
//! (separate compact coefficients + stwo_lde_n2b_columns_on), so the root is
//! byte-identical. Differences are custody only: no lease, no join, no D2H.
//! The root stays in the tree buffer (`rootPointer`) for the device channel;
//! coefficients stay in the caller's buffer for PCS.
//!
//! The evaluation input may be a separate image (MAIN: the INTER kernels still
//! read it after the commit) or the coefficient buffer itself (INTER, FIXED:
//! interpolated in place, which B2N supports for exactly aliased strides).
const std = @import("std");
const Abi = @import("../abi.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");

/// Class-static inputs, staged once: per-sorted-column log sizes (read by the
/// LDE wrapper from device memory) and the eval-height twiddle tree.
pub const Statics = struct {
    sorted_logs: [*]const u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    itwiddles: [*]const u32,
    itwiddle_words: u32,
};

pub const Commit = struct {
    /// Evaluations in sorted commit layout (`plan.offsets`); may alias `coefficients`.
    evaluations: [*]const u32,
    coefficients: [*]u32,
    /// Merkle tree + prefix banks (`plan.tree_words + plan.prefix_words`),
    /// allocated by the caller below its transient buffers so the worker's
    /// LIFO arena reclaims the LDE scratch this call frees.
    tree: K.Buffer,
    statics: Statics,
};

pub fn rootPointer(plan: *const Plan.TreePlan, tree: K.Buffer) [*]const u32 {
    return tree.at(plan.rootOffset());
}

/// Words of the host sorted-log table for `plan` (staged as a class static).
pub fn sortedLogs(plan: *const Plan.TreePlan, out: []u32) void {
    std.debug.assert(out.len == plan.order.len);
    for (out, plan.order) |*log, original| log.* = plan.logs[original];
}

/// Enqueues interpolation, LDE and Merkle hashing. The LDE scratch is
/// allocated and freed (stream ordered, LIFO) inside; `commit.tree` must live
/// until PCS has opened it. The root is `rootPointer(plan, commit.tree)`.
pub fn enqueue(device: *K.Device, plan: *const Plan.TreePlan, commit: Commit) !void {
    if (plan.beta != 1) return error.UnsupportedOuterJobBlowup;
    const s = commit.statics;
    // 1. Coefficients: one compact B2N per height group, in sorted order.
    for (plan.groups) |group| {
        const rows: u64 = @as(u64, 1) << @intCast(group.log);
        if (rows / 2 > s.itwiddle_words) return error.InvalidOuterTwiddles;
        var launches: u32 = 0;
        try device.check(device.kernels.b2n(
            commit.evaluations + group.coefficient_offset,
            @intCast(rows),
            commit.coefficients + group.coefficient_offset,
            @intCast(rows),
            group.log,
            group.count,
            s.itwiddles + (s.itwiddle_words - rows / 2),
            @intCast(rows / 2),
            @intCast(rows / 2),
            device.stream,
            &launches,
        ));
        device.counters.internal += launches -| 1;
    }
    // 2. Evaluations at blowup, one LDE call per height group.
    const capacity = plan.tree_words + plan.prefix_words;
    if (commit.tree.words < capacity) return error.OuterTreeBufferTooSmall;
    const scratch = try device.alloc(@intCast(plan.evaluation_words));
    defer device.free(scratch);
    var segments: [64]Abi.MixedSegment = undefined;
    if (plan.groups.len > segments.len) return error.InvalidOuterTreePlan;
    for (plan.groups, 0..) |group, i| {
        const coefficient_rows: u64 = @as(u64, 1) << @intCast(group.log);
        const log = group.log + plan.beta;
        const rows: u64 = @as(u64, 1) << @intCast(log);
        if (rows / 2 > s.twiddle_words) return error.InvalidOuterTwiddles;
        var launches: u32 = 0;
        try device.check(device.kernels.n2b_columns(
            commit.coefficients + group.coefficient_offset,
            @intCast(coefficient_rows),
            s.sorted_logs + group.first,
            scratch.at(group.evaluation_offset),
            @intCast(rows),
            log,
            group.count,
            s.twiddles + (s.twiddle_words - rows / 2),
            @intCast(rows / 2),
            @intCast(rows / 2),
            device.stream,
            &launches,
        ));
        device.counters.internal += launches -| 1;
        segments[i] = .{ .columns = scratch.at(group.evaluation_offset), .stride_words = rows, .capacity_words = rows * group.count, .source_size = @intCast(rows) };
    }
    // 3. Merkle tree + prefix banks; the root is the tree's last 8 words.
    try device.check(device.kernels.tree(device.ctx, K.lane, &segments, @intCast(plan.groups.len), plan.eval_log, commit.tree.ptr, capacity));
}

// ---------------------------------------------------------------------------
// Host test double: records every call so the enqueue order, strides and
// twiddle tails are checked against trace_commit.zig without a GPU.
const testing = std.testing;
const Fake = struct {
    var calls: std.ArrayList([]const u8) = .empty;
    var last_tree_capacity: u64 = 0;
    var last_segments: u32 = 0;
    var arena_words: usize = 0;
    var heap: [1 << 14]u32 = undefined;
    fn note(name: []const u8) void {
        calls.append(testing.allocator, name) catch unreachable;
    }
    fn b2n(_: [*]const u32, stride: usize, _: [*]u32, out_stride: usize, log: u32, _: u32, _: [*]const u32, words: u32, size: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        if (stride != out_stride or stride != @as(usize, 1) << @intCast(log) or words != size or words * 2 != stride) return 1;
        launches.* = 2;
        note("b2n");
        return 0;
    }
    fn n2b(_: [*]const u32, stride: usize, _: [*]const u32, _: [*]u32, eval_stride: usize, log: u32, _: u32, _: [*]const u32, words: u32, _: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        if (eval_stride != @as(usize, 1) << @intCast(log) or eval_stride != 2 * stride or words * 2 != eval_stride) return 1;
        launches.* = 1;
        note("n2b");
        return 0;
    }
    fn tree(_: *anyopaque, lane: u32, _: [*]const Abi.MixedSegment, n: u32, _: u32, _: [*]u32, capacity: u64) callconv(.c) c_int {
        if (lane != 0) return 1;
        last_segments = n;
        last_tree_capacity = capacity;
        note("tree");
        return 0;
    }
    fn alloc(_: *anyopaque, words: usize) anyerror!K.Buffer {
        const at = arena_words;
        arena_words += words;
        if (arena_words > heap.len) return error.OutOfMemory;
        return .{ .ptr = heap[at..].ptr, .words = words };
    }
    fn free(_: *anyopaque, _: K.Buffer) void {}
    fn mix(_: *anyopaque, _: [*]const u32, _: u32, _: bool) anyerror!void {}
    fn draw(_: *anyopaque, _: u32, _: [*]u32) anyerror!void {}
};

test "enqueue-only commit follows the legacy group order and leaves the root on device" {
    const a = testing.allocator;
    defer Fake.calls.deinit(a);
    var plan = try Plan.TreePlan.init(a, &.{ 5, 4, 5, 4, 6 }, 1);
    defer plan.deinit(a);
    var kernels: K.Kernels = undefined;
    kernels.b2n = Fake.b2n;
    kernels.n2b_columns = Fake.n2b;
    kernels.tree = Fake.tree;
    var dummy: u8 = 0;
    const vtable = K.Device.VTable{ .alloc = Fake.alloc, .free = Fake.free, .mix = Fake.mix, .draw = Fake.draw };
    var device = K.Device{ .ctx = &dummy, .stream = &dummy, .impl = &dummy, .vtable = &vtable, .kernels = &kernels };
    var tw: [128]u32 = undefined;
    var logs: [5]u32 = undefined;
    sortedLogs(&plan, &logs);
    try testing.expectEqualSlices(u32, &.{ 4, 4, 5, 5, 6 }, &logs);
    var coefficients: [160]u32 = undefined;
    const tree = try device.alloc(@intCast(plan.tree_words + plan.prefix_words));
    try enqueue(&device, &plan, .{ .evaluations = &coefficients, .coefficients = &coefficients, .tree = tree, .statics = .{ .sorted_logs = &logs, .twiddles = &tw, .twiddle_words = 128, .itwiddles = &tw, .itwiddle_words = 128 } });
    const expected = [_][]const u8{ "b2n", "b2n", "b2n", "n2b", "n2b", "n2b", "tree" };
    try testing.expectEqual(expected.len, Fake.calls.items.len);
    for (expected, Fake.calls.items) |e, actual| try testing.expectEqualStrings(e, actual);
    try testing.expectEqual(@as(u32, 3), Fake.last_segments);
    try testing.expectEqual(plan.tree_words + plan.prefix_words, Fake.last_tree_capacity);
    try testing.expectEqual(@as([*]const u32, tree.ptr + (plan.tree_words - 8)), rootPointer(&plan, tree));
    try testing.expectEqual(@as(u32, 7), device.counters.api);
    try testing.expectEqual(@as(u32, 3), device.counters.internal);
}
