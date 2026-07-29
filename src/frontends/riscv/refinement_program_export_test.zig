//! Dedicated build root for the unsigned LUI AIR IR v2 semantic program.

const std = @import("std");
const program_json = @import("air/extract/program_json.zig");

pub const OUTPUT_ENV = "RISCV_AIR_PROGRAM_IR_DIR";

test "refinement AIR IR v2 export: emit unsigned LUI production program" {
    const path = std.posix.getenv(OUTPUT_ENV) orelse
        return error.MissingAirProgramIrDirectory;
    var dir = try std.fs.cwd().makeOpenPath(path, .{ .iterate = true });
    defer dir.close();
    var entries = dir.iterate();
    if (try entries.next() != null) return error.AirProgramIrDirectoryNotEmpty;

    const file = try dir.createFile("lui.unsigned.json", .{ .exclusive = true });
    defer file.close();
    var output_buffer: [1 << 16]u8 = undefined;
    var writer = file.writer(&output_buffer);
    try program_json.emitLui(std.testing.allocator, &writer.interface);
    try writer.interface.flush();
}
