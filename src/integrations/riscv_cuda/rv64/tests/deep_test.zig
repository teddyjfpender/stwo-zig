//! No cryptographic expectations are manufactured here: GPU/native oracles
//! qualify arithmetic. These tests qualify enqueue custody and poisoning.
const std = @import("std");
const D = @import("../deep.zig");
const Abi = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Context = struct {
    pub fn lane(_: *@This(), index: u32) !struct { owner: usize } {
        if (index != 1) return error.InvalidLane;
        return .{ .owner = 1 };
    }
    pub fn validateLane(_: *@This(), _: anytype) !void {}
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, s: Slice, n: usize) ![*]T {
        if (s.owner != 1 or s.generation != 2 or n > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
const Api = struct {
    var calls: usize = 0;
    var fail: bool = false;
    pub fn stwo_rv64_deep_prepare_on(_: *anyopaque, _: u32, _: *const Abi.DeepPrepare) c_int {
        calls += 1;
        return if (fail) 1 else 0;
    }
    pub fn stwo_rv64_deep_combine_on(_: *anyopaque, _: u32, _: *const Abi.DeepCombine) c_int {
        calls += 1;
        return if (fail) 1 else 0;
    }
};
fn slice() Slice {
    return .{ .address = 4096, .len = 4096, .owner = 1, .generation = 2 };
}
fn prepare() D.Prepare {
    const s = slice();
    return .{ .trees = .{ s, null, null, null }, .sources = s, .terms = s, .groups = s, .points = s, .values = s, .alpha = s, .weights = s, .linear = s, .coefficients = s, .valid = s, .verdict = s, .source_count = 1, .term_count = 1, .group_count = 1 };
}
fn combine() D.Combine {
    const s = slice();
    return .{ .groups = s, .points = s, .linear = s, .evaluations = s, .domain_xy = s, .valid = s, .output = .{ .data = s, .stride = 32, .coordinates = 8 }, .verdict = s, .group_count = 1, .output_log = 5 };
}
test "DEEP rejects retired and undersized inputs before enqueue and poisons failed jobs" {
    Api.calls = 0;
    Api.fail = false;
    var ctx = Context{};
    var commands = D.Commands(Context, Api){ .context = &ctx, .lane_index = 1 };
    var input = prepare();
    input.values.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.prepare(input));
    input = prepare();
    input.source_count = 65537;
    try std.testing.expectError(error.InvalidGeometry, commands.prepare(input));
    var finish = combine();
    finish.domain_xy.len = 63;
    try std.testing.expectError(error.InvalidDeviceAddress, commands.combine(finish));
    finish = combine();
    finish.output.coordinates = 4;
    try std.testing.expectError(error.InvalidPlane, commands.combine(finish));
    try std.testing.expectEqual(@as(usize, 0), Api.calls);
    try commands.prepare(prepare());
    try commands.combine(combine());
    Api.fail = true;
    try std.testing.expectError(error.CudaEnqueueFailed, commands.combine(combine()));
    try std.testing.expectError(error.JobPoisoned, commands.prepare(prepare()));
    try std.testing.expectEqual(@as(usize, 3), Api.calls);
}
