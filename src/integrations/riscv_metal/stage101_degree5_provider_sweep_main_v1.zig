const std = @import("std");
const sweep = @import("stage101_degree5_provider_sweep_v1");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len == 0) return error.InvalidArguments;
    try sweep.run(allocator, arguments[1..]);
}

comptime {
    if (sweep.PRODUCTION_ACTIVE or sweep.COMPLETE_LEAF_PROOF)
        @compileError("D5 provider sweep activated as a leaf product");
}
