const std = @import("std");
const stage101 = @import("stage101_leaf_autoresearch_v1");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len == 0) return error.InvalidArguments;
    try stage101.run(allocator, arguments[1..]);
}

comptime {
    if (stage101.PRODUCTION_ACTIVE)
        @compileError("Stage101 Metal autoresearch command activated");
}
