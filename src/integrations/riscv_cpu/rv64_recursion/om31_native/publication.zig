const std = @import("std");

/// The readable directory handle is intentional: Linux O_PATH descriptors
/// cannot fsync. Separate node filenames give each lane its own pending path.
pub fn write(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var readable = try dir.openDir(".", .{ .iterate = true });
    defer readable.close();
    var buffer: [96]u8 = undefined;
    const pending = try std.fmt.bufPrint(&buffer, ".{s}.pending", .{name});
    var file = try readable.createFile(pending, .{});
    var open = true;
    defer if (open) file.close();
    errdefer readable.deleteFile(pending) catch {};
    try file.writeAll(bytes);
    try file.sync();
    file.close();
    open = false;
    try readable.rename(pending, name);
    try std.posix.fsync(readable.fd);
}

test "recursion publication replaces stale pending bytes and syncs readable directory" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = ".node.proof.pending", .data = "interrupted" });
    try write(temporary.dir, "node.proof", "verified");
    try write(temporary.dir, "node.proof", "freshly reverified");
    const bytes = try temporary.dir.readFileAlloc(std.testing.allocator, "node.proof", 100);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("freshly reverified", bytes);
    try std.testing.expectError(error.FileNotFound, temporary.dir.access(".node.proof.pending", .{}));
}

test "recursion publication failure removes pending bytes without replacing receiver path" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.makeDir("node.proof");
    if (write(temporary.dir, "node.proof", "not published")) |_| return error.ExpectedPublicationFailure else |_| {}
    try std.testing.expectError(error.FileNotFound, temporary.dir.access(".node.proof.pending", .{}));
    var directory = try temporary.dir.openDir("node.proof", .{});
    directory.close();
}
