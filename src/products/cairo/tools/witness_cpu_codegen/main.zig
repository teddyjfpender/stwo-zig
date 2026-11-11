//! Command boundary for deterministic Cairo CPU witness writer generation.

const std = @import("std");
const c_writer = @import("c_writer.zig");
const model = @import("model.zig");
const registry = @import("registry.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) return error.InvalidArguments;

    var bundle = try model.Bundle.read(allocator, args[1]);
    defer bundle.deinit();
    try std.fs.cwd().makePath(args[2]);
    try emitRegistry(allocator, args[2], bundle.programs);
    for (bundle.programs) |witness_program| {
        try validateLabel(witness_program.label);
        const filename = try std.fmt.allocPrint(
            allocator,
            "{s}.c",
            .{witness_program.label},
        );
        defer allocator.free(filename);
        const path = try std.fs.path.join(
            allocator,
            &.{ args[2], filename },
        );
        defer allocator.free(path);
        const source = try std.fs.cwd().createFile(
            path,
            .{ .truncate = true },
        );
        defer source.close();
        var buffer: [256 * 1024]u8 = undefined;
        var writer = source.writer(&buffer);
        try c_writer.emit(&writer.interface, witness_program);
        try writer.interface.flush();
    }
}

fn emitRegistry(
    allocator: std.mem.Allocator,
    directory: []const u8,
    programs: []const model.Program,
) !void {
    const path = try std.fs.path.join(
        allocator,
        &.{ directory, "registry.zig" },
    );
    defer allocator.free(path);
    const output = try std.fs.cwd().createFile(
        path,
        .{ .truncate = true },
    );
    defer output.close();
    var buffer: [256 * 1024]u8 = undefined;
    var writer = output.writer(&buffer);
    try registry.emit(&writer.interface, programs);
    try writer.interface.flush();
}

fn validateLabel(label: []const u8) !void {
    for (label) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and
            byte != '_')
            return error.InvalidLabel;
    }
}
