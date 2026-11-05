const std = @import("std");
const C = @import("../channel.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Context = struct {
    const Lane = struct { owner: usize };
    pub fn lane(_: *@This(), i: u32) !Lane {
        if (i != 1) return error.InvalidLane;
        return .{ .owner = 1 };
    }
    pub fn validateLane(_: *@This(), _: Lane) !void {}
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, s: Slice, n: usize) ![*]T {
        if (s.owner != 1 or s.generation != 2 or n > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
const Api = struct {
    var calls: usize = 0;
    var fail = false;
    pub fn stwo_rv64_channel_init_on(_: *anyopaque, _: u32, _: [*]u32, _: [*]const u32, _: u64) c_int {
        calls += 1;
        return if (fail) 1 else 0;
    }
    pub fn stwo_rv64_channel_mix_on(_: *anyopaque, _: u32, _: [*]u32, step: u32, chain: u64, _: u64, input: ?[*]const u32, count: u32, _: u32, _: [*]u32) c_int {
        std.debug.assert(step == 0 and chain == 10 and input == null and count == 0);
        calls += 1;
        return if (fail) 1 else 0;
    }
    pub fn stwo_rv64_channel_draw_on(_: *anyopaque, _: u32, _: [*]u32, step: u32, chain: u64, _: u64, count: u32, _: [*]u32, _: [*]u32) c_int {
        std.debug.assert(step == 1 and chain == 11 and count == 3);
        calls += 1;
        return if (fail) 1 else 0;
    }
};
fn slice(address: usize, n: usize) Slice {
    return .{ .address = address, .len = n, .owner = 1, .generation = 2 };
}
test "OM31 channel keeps schedule authority and checks terminal status before publication" {
    var ctx = Context{};
    Api.calls = 0;
    Api.fail = false;
    var c = C.Commands(Context, Api){ .context = &ctx, .lane_index = 1, .state = slice(4096, 16) };
    try std.testing.expectError(error.ChannelNotInitialized, c.mix(null, false, 11, slice(8192, 16)));
    try c.initialize(slice(12288, 9), 10);
    try std.testing.expectError(error.ChannelAlreadyInitialized, c.initialize(slice(12288, 9), 10));
    try c.mix(null, false, 11, slice(8192, 16));
    var retired = slice(16384, 24);
    retired.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, c.draw(3, retired, 12, slice(8192, 16)));
    try std.testing.expectEqual(@as(u32, 1), c.step);
    try c.draw(3, slice(16384, 24), 12, slice(8192, 16));
    var completed = C.Snapshot{ .digest = @splat(0), .draws = 3, .cursor = 2, .status = 0, .reserved = 0, .chain = 12, .padding = .{ 0, 0 } };
    try c.validateCompleted(completed);
    completed.status = 1;
    try std.testing.expectError(error.InvalidDeviceTranscript, c.validateCompleted(completed));
    completed.status = 0;
    completed.chain = 11;
    try std.testing.expectError(error.InvalidDeviceTranscript, c.validateCompleted(completed));
    try std.testing.expectEqual(@as(usize, 3), Api.calls);
}
test "OM31 channel enqueue failure is sticky and never advances scheduled chain" {
    var ctx = Context{};
    Api.calls = 0;
    Api.fail = false;
    var c = C.Commands(Context, Api){ .context = &ctx, .lane_index = 1, .state = slice(4096, 16) };
    try c.initialize(slice(12288, 9), 10);
    Api.fail = true;
    try std.testing.expectError(error.CudaEnqueueFailed, c.mix(null, false, 11, slice(8192, 16)));
    try std.testing.expectEqual(@as(u32, 0), c.step);
    try std.testing.expectEqual(@as(u64, 10), c.chain);
    try std.testing.expectError(error.JobPoisoned, c.mix(null, false, 11, slice(8192, 16)));
    try std.testing.expectEqual(@as(usize, 2), Api.calls);
}
