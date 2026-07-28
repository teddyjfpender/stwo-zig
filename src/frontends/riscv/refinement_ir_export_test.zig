//! Dedicated build root for exporting the production symbolic AIR.

const std = @import("std");
const extract = @import("air/extract/mod.zig");

test "refinement export: emit production symbolic AIR" {
    const path = std.posix.getenv("RISCV_AIR_IR_DIR") orelse
        return error.MissingRefinementIrDirectory;
    try extract.checkDifferential(std.testing.allocator);
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    try extract.emitAll(std.testing.allocator, dir);
}
