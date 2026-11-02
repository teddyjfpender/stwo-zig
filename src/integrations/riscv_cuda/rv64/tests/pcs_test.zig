//! Typed metadata tests only. Real numerical and alias gates run on NVIDIA.
const std = @import("std");
const P = @import("../pcs.zig");
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
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, s: Slice, n: usize) ![*]T {
        if (s.owner != 1 or s.generation != 2 or n > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
const Api = struct {
    var calls: usize = 0;
    var fail: bool = false;
    pub fn stwo_rv64_fri_fold_on(_: *anyopaque, lane: u32, p: *const Abi.FriFold) c_int {
        std.debug.assert(lane == 1 and p.input.coordinates == 8 and p.steps == 4 and p.count == 32);
        calls += 1;
        return if (fail) 1 else 0;
    }
    pub fn stwo_rv64_fri_leaves_on(_: *anyopaque, lane: u32, input: Abi.Plane, count: u32, leaf_log: u32, prefixed: u32, _: [*]u32, hashes: u64) c_int {
        std.debug.assert(lane == 1 and input.coordinates == 8 and count == 32 and leaf_log == 4 and prefixed == 1 and hashes == 2);
        calls += 1;
        return if (fail) 1 else 0;
    }
};
fn slice(address: usize) Slice {
    return .{ .address = address, .len = 4096, .owner = 1, .generation = 2 };
}
fn plane(address: usize) R.Plane {
    return .{ .data = slice(address), .stride = 32, .coordinates = 8 };
}
fn job() P.Fold {
    return .{ .input = plane(4096), .output = plane(8192), .twiddles = slice(12288), .alpha = slice(16384), .offsets = .{ 0, 32, 64, 96 }, .count = 32, .steps = 4, .first_is_circle = true };
}
test "OM31 PCS generation and shape preflight preserve assigned-lane custody" {
    Api.calls = 0;
    Api.fail = false;
    var ctx = Context{};
    var commands = P.Commands(Context, Api){ .context = &ctx, .lane_index = 1 };
    try commands.fold(job());
    try commands.leaves(plane(4096), 32, 4, true, slice(8192));
    try std.testing.expectEqual(@as(usize, 2), Api.calls);
    try std.testing.expectEqual(@as(u64, 2), commands.launches);
    var retired = job();
    retired.alpha.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.fold(retired));
    var malformed = job();
    malformed.offsets[3] = 4096;
    try std.testing.expectError(error.InvalidGeometry, commands.fold(malformed));
    malformed = job();
    malformed.accumulate_circle = true;
    try std.testing.expectError(error.InvalidGeometry, commands.fold(malformed));
    try std.testing.expectEqual(@as(usize, 2), Api.calls);
}
test "OM31 PCS malformed hash capacity and failed enqueue never publish a usable job" {
    Api.calls = 0;
    Api.fail = true;
    var ctx = Context{};
    var commands = P.Commands(Context, Api){ .context = &ctx, .lane_index = 1 };
    var short = slice(8192);
    short.len = 15;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.leaves(plane(4096), 32, 4, true, short));
    try std.testing.expectEqual(@as(usize, 0), Api.calls);
    try std.testing.expectError(error.CudaEnqueueFailed, commands.fold(job()));
    try std.testing.expectError(error.JobPoisoned, commands.leaves(plane(4096), 32, 4, true, slice(8192)));
    try std.testing.expectEqual(@as(usize, 1), Api.calls);
}
