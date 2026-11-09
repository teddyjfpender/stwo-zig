//! Atomic, exclusive publication for proof and report artifacts.

const std = @import("std");
const builtin = @import("builtin");

pub fn temporaryPathAlloc(
    allocator: std.mem.Allocator,
    output_path: []const u8,
    label: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.stwz-{x}-{s}.tmp", .{
        output_path,
        std.crypto.random.int(u64),
        label,
    });
}

/// Publishes a sibling temporary file without replacing an existing output.
pub fn publishExclusive(temporary_path: []const u8, output_path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        try std.os.windows.MoveFileEx(
            temporary_path,
            output_path,
            std.os.windows.MOVEFILE_WRITE_THROUGH,
        );
        return;
    }
    try std.posix.link(temporary_path, output_path);
    std.fs.cwd().deleteFile(temporary_path) catch {};
}

pub fn writeExclusive(
    allocator: std.mem.Allocator,
    output_path: []const u8,
    bytes: []const u8,
) !void {
    if (output_path.len == 0) return error.InvalidOutputPath;
    const temporary_path = try temporaryPathAlloc(allocator, output_path, "write");
    defer allocator.free(temporary_path);
    defer std.fs.cwd().deleteFile(temporary_path) catch {};

    const file = try std.fs.cwd().createFile(temporary_path, .{
        .exclusive = true,
        .mode = 0o600,
    });
    var open = true;
    defer if (open) file.close();
    try file.writeAll(bytes);
    try file.sync();
    file.close();
    open = false;
    try publishExclusive(temporary_path, output_path);
}

test "atomic file: publish is exclusive and leaves no partial output" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(output);

    try writeExclusive(std.testing.allocator, output, "first");
    try std.testing.expectError(
        error.PathAlreadyExists,
        writeExclusive(std.testing.allocator, output, "second"),
    );
    const actual = try std.fs.cwd().readFileAlloc(std.testing.allocator, output, 32);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("first", actual);
}
