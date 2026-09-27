//! Merkle adapter for the shared authenticated digest frame router.
const std = @import("std");
const core = @import("stwo_core");
const frame_route = @import("blake3_frame_route.zig");
const route = @import("blake3_byte_route.zig");
pub const Caller = frame_route.Caller;
pub const Plan = frame_route.Plan;
pub fn frameLength() usize {
    return (core.channel.blake3.Frame{ .node = .{ .left = @splat(0), .right = @splat(0) } }).encodedSize() catch unreachable;
}
pub fn build(a: std.mem.Allocator, circuit: u32, callers: [2]Caller) !Plan {
    return frame_route.build(a, circuit, .{ .node = .{ .left = @splat(0), .right = @splat(0) } }, &.{
        .{ .role = .left, .caller = callers[0] },
        .{ .role = .right, .caller = callers[1] },
    }) catch |err| switch (err) {
        error.InvalidBlake3FrameCaller => error.InvalidBlake3NodeCaller,
        else => return err,
    };
}
pub fn witnessRow(schedule: route.Schedule, callers: [2]Caller, digests: [2][32]u8) !route.Row {
    return frame_route.witnessRow(schedule, &callers, &digests) catch |err| switch (err) {
        error.InvalidBlake3FrameCaller => error.InvalidBlake3NodeCaller,
        else => return err,
    };
}
