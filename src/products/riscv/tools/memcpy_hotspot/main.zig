//! Existing bounded observation command; application owns admission and output.
const std = @import("std");
const app = @import("app.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    try app.run(allocator, args[1..]);
}
