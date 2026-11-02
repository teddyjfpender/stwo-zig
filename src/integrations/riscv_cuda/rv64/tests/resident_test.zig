const std = @import("std");
const R = @import("../resident.zig");
const Abi = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Context = struct {
    const Lane = struct { owner: usize, index: u32 };
    pub fn lane(_: *@This(), index: u32) !Lane {
        if (index >= 2) return error.InvalidLane;
        return .{ .owner = 1, .index = index };
    }
    pub fn validateLane(_: *@This(), _: Lane) !void {}
    pub fn deviceSlicePointer(_: *@This(), comptime F: type, s: Slice, n: usize) ![*]F {
        if (s.owner != 1 or s.generation != 2 or n > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
const Fake = struct {
    var calls: usize = 0;
    var failure: bool = false;
    pub fn stwo_rv64_gkr_project_on(_: *anyopaque, lane: u32, _: Abi.Plane, _: Abi.Plane, _: Abi.Plane, _: u32, _: u32, _: [*]const u32, _: Abi.Plane, _: Abi.Plane, _: [*]u32) c_int {
        std.debug.assert(lane == 1);
        calls += 1;
        return if (failure) 1 else 0;
    }
    pub fn stwo_rv64_gkr_layer_on(_: *anyopaque, _: u32, _: Abi.Plane, _: Abi.Plane, _: u32, _: u32, _: Abi.Plane, _: Abi.Plane) c_int {
        calls += 1;
        return 0;
    }
    pub fn stwo_rv64_gkr_fold_on(_: *anyopaque, _: u32, _: Abi.Plane, _: Abi.Plane, _: u32, _: [*]const u32, _: Abi.Plane, _: Abi.Plane) c_int {
        calls += 1;
        return 0;
    }
    pub fn stwo_rv64_gkr_eq_on(_: *anyopaque, _: u32, _: [*]const u32, _: u32, _: Abi.Plane) c_int {
        calls += 1;
        return 0;
    }
    pub fn stwo_rv64_gkr_sum_on(_: *anyopaque, _: u32, _: Abi.Plane, _: Abi.Plane, _: u32, _: Abi.Plane, _: [*]const u32, _: Abi.Plane, _: Abi.Plane, _: Abi.Plane) c_int {
        calls += 1;
        return 0;
    }
    pub fn stwo_rv64_gkr_fold_sum_on(_: *anyopaque, lane: u32, _: Abi.Plane, _: Abi.Plane, count: u32, _: [*]const u32, _: Abi.Plane, _: Abi.Plane, _: Abi.Plane, _: [*]const u32, _: Abi.Plane, _: Abi.Plane, _: Abi.Plane) c_int {
        std.debug.assert(lane == 1 and count >= 8);
        calls += 1;
        return if (failure) 1 else 0;
    }
    pub fn stwo_rv64_sumcheck_tail_on(_: *anyopaque, lane: u32, jobs: [*]const Abi.TailJob, count: u32) c_int {
        std.debug.assert(lane == 1 and count > 0 and count <= 8);
        for (jobs[0..count]) |j| std.debug.assert(j.count >= 4 and j.out_n.coordinates == 8 and j.reserved == 0);
        calls += 1;
        return if (failure) 1 else 0;
    }
    pub const stwo_rv64_gkr_eq_fused_on = stwo_rv64_gkr_eq_on;
    pub const stwo_rv64_gkr_sum_split_on = stwo_rv64_gkr_sum_on;
};
fn slice() Slice {
    return .{ .address = 4096, .len = 4096, .owner = 1, .generation = 2 };
}
fn plane(c: u32) R.Plane {
    return .{ .data = slice(), .stride = 16, .coordinates = c };
}
fn leaf(n: u32) R.Fraction {
    return .{ .n = plane(1), .d = plane(8), .count = n };
}
fn fraction(n: u32) R.Fraction {
    return .{ .n = plane(8), .d = plane(8), .count = n };
}
test "RV64 CUDA commands validate generations use assigned lane and poison launch failure" {
    Fake.calls = 0;
    Fake.failure = false;
    var context = Context{};
    var commands = R.Commands(Context, Fake){ .context = &context, .lane_index = 1 };
    try commands.project(plane(3), plane(1), plane(1), 3, slice(), leaf(16), slice());
    try commands.layer(fraction(16), 2, fraction(4));
    try commands.fold(fraction(16), slice(), fraction(8));
    try commands.eq(slice(), 3, plane(8));
    try commands.sum(fraction(16), plane(8), slice(), plane(8), plane(8), plane(8));
    try std.testing.expectEqual(@as(usize, 5), Fake.calls);
    try std.testing.expectEqual(@as(u64, 7), commands.launches);
    var retired = plane(8);
    retired.data.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.eq(slice(), 3, retired));
    try std.testing.expectEqual(@as(usize, 5), Fake.calls);
    Fake.failure = true;
    try std.testing.expectError(error.CudaEnqueueFailed, commands.project(plane(3), plane(1), plane(1), 3, slice(), leaf(16), slice()));
    try std.testing.expectError(error.JobPoisoned, commands.eq(slice(), 3, plane(8)));
    try std.testing.expectEqual(@as(usize, 6), Fake.calls);
}

test "RV64 CUDA malformed plane and job geometry never enqueue" {
    Fake.calls = 0;
    Fake.failure = false;
    var context = Context{};
    var commands = R.Commands(Context, Fake){ .context = &context, .lane_index = 1 };
    try std.testing.expectError(error.InvalidPlane, commands.project(plane(3), plane(1), plane(1), 3, slice(), fraction(16), slice()));
    try std.testing.expectError(error.InvalidGeometry, commands.layer(fraction(16), 2, fraction(8)));
    try std.testing.expectError(error.InvalidGeometry, commands.fold(fraction(15), slice(), fraction(7)));
    try std.testing.expectError(error.InvalidPlane, commands.eq(slice(), 28, plane(8)));
    try std.testing.expectError(error.InvalidGeometry, commands.sum(fraction(2), plane(8), slice(), plane(8), plane(8), plane(8)));
    try std.testing.expectEqual(@as(usize, 0), Fake.calls);
}

test "RV64 CUDA fused Eq command records grouped dispatch count" {
    Fake.calls = 0;
    Fake.failure = false;
    var context = Context{};
    var commands = R.Commands(Context, Fake){ .context = &context, .lane_index = 1, .fused_eq = true };
    try commands.eq(slice(), 5, plane(8));
    try std.testing.expectEqual(@as(u64, 2), commands.launches);
}

test "RV64 CUDA fused fold sum validates shape generation and enqueue failure" {
    Fake.calls = 0;
    Fake.failure = false;
    var context = Context{};
    var commands = R.Commands(Context, Fake){ .context = &context, .lane_index = 1 };
    try commands.foldSum(leaf(16), slice(), fraction(8), plane(8), slice(), plane(8), plane(8), plane(8));
    try std.testing.expectEqual(@as(u64, 1), commands.launches);
    try std.testing.expectError(error.InvalidGeometry, commands.foldSum(fraction(4), slice(), fraction(2), plane(8), slice(), plane(8), plane(8), plane(8)));
    try std.testing.expectError(error.InvalidGeometry, commands.foldSum(fraction(16), slice(), fraction(4), plane(8), slice(), plane(8), plane(8), plane(8)));
    var stale = slice();
    stale.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.foldSum(fraction(16), stale, fraction(8), plane(8), slice(), plane(8), plane(8), plane(8)));
    var short_eq = plane(8);
    short_eq.stride = 1;
    try std.testing.expectError(error.InvalidPlane, commands.foldSum(fraction(16), slice(), fraction(8), short_eq, slice(), plane(8), plane(8), plane(8)));
    try std.testing.expectEqual(@as(usize, 1), Fake.calls);
    Fake.failure = true;
    try std.testing.expectError(error.CudaEnqueueFailed, commands.foldSum(fraction(16), slice(), fraction(8), plane(8), slice(), plane(8), plane(8), plane(8)));
    try std.testing.expectError(error.JobPoisoned, commands.foldSum(fraction(16), slice(), fraction(8), plane(8), slice(), plane(8), plane(8), plane(8)));
}

fn tailJob() R.TailJob {
    return .{ .input = leaf(16), .output = fraction(2), .eq = plane(8), .point = slice(), .lambda = slice(), .state = slice(), .records = slice(), .mask = slice(), .variables = 3, .first = 0 };
}
test "RV64 CUDA tail batch binds all jobs before dispatch and poisons native failure" {
    Fake.calls = 0;
    Fake.failure = false;
    var context = Context{};
    var commands = R.Commands(Context, Fake){ .context = &context, .lane_index = 1 };
    try commands.tailBatch(&.{ tailJob(), tailJob() });
    try std.testing.expectEqual(@as(usize, 1), Fake.calls);
    try std.testing.expectEqual(@as(u64, 1), commands.launches);
    var jobs: [8]R.TailJob = @splat(tailJob());
    jobs[7].state.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.tailBatch(&jobs));
    jobs[7] = tailJob();
    jobs[7].first = 1;
    try std.testing.expectError(error.InvalidGeometry, commands.tailBatch(&jobs));
    try std.testing.expectError(error.InvalidGeometry, commands.tailBatch(&.{}));
    const too_many: [9]R.TailJob = @splat(tailJob());
    try std.testing.expectError(error.InvalidGeometry, commands.tailBatch(&too_many));
    try std.testing.expectEqual(@as(usize, 1), Fake.calls);
    Fake.failure = true;
    try std.testing.expectError(error.CudaEnqueueFailed, commands.tail(tailJob()));
    try std.testing.expectError(error.JobPoisoned, commands.tail(tailJob()));
}
