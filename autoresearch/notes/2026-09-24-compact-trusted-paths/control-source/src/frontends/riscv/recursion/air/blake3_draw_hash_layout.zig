//! Canonical equal-length draw geometry shared by queries and secure retries.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("blake3_hash_plan.zig");
pub const Counts = struct { g: usize, xor: usize };
pub fn build(a: std.mem.Allocator) !graph.Plan {
    const message = core.channel.blake3.Frame{ .draw = .{ .state = @splat(0), .index = 0 } };
    return graph.build(a, try message.encodedSize());
}
pub fn counts(plan: *const graph.Plan, frames: usize) !Counts {
    return .{ .g = try std.math.mul(usize, frames, plan.g.len), .xor = try std.math.mul(usize, frames, plan.xor.len) };
}
pub fn required(a: std.mem.Allocator, frames: usize) !Counts {
    var plan = try build(a);
    defer plan.deinit();
    return counts(&plan, frames);
}
