//! Dedicated build root for all unsigned AIR IR v2 semantic programs.

const std = @import("std");
const program_json = @import("air/extract/program_json.zig");
const opcode_manifest = @import("opcode_manifest.zig");

pub const OUTPUT_ENV = "RISCV_AIR_PROGRAM_IR_DIR";

test "refinement AIR IR v2 export: emit every unsigned production program" {
    const path = std.posix.getenv(OUTPUT_ENV) orelse
        return error.MissingAirProgramIrDirectory;
    var dir = try std.fs.cwd().makeOpenPath(path, .{ .iterate = true });
    defer dir.close();
    var entries = dir.iterate();
    if (try entries.next() != null) return error.AirProgramIrDirectoryNotEmpty;

    for (opcode_manifest.entries) |opcode| {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "{s}.unsigned.json",
            .{opcode.mnemonic},
        );
        const file = try dir.createFile(name, .{ .exclusive = true });
        defer file.close();
        var encoded = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer encoded.deinit();
        try program_json.emitOpcode(
            std.testing.allocator,
            &encoded.writer,
            opcode,
        );
        try file.writeAll(encoded.written());
    }
}
