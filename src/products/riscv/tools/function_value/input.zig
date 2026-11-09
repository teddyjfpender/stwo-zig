//! Function-value inputs retain absolute-path, regular-file and size admission.
const std = @import("std");

pub fn readPathAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const metadata = try file.stat();
    if (metadata.kind != .file or metadata.size > maximum)
        return error.InvalidInputFile;
    return file.readToEndAlloc(allocator, maximum);
}

test "function-value input rejects oversized and nonregular files" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "input", .data = "abc" });
    const directory = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(directory);
    const path = try std.fs.path.join(std.testing.allocator, &.{ directory, "input" });
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.InvalidInputFile, readPathAlloc(std.testing.allocator, path, 2));
    try std.testing.expectError(error.InvalidInputFile, readPathAlloc(std.testing.allocator, directory, 3));
    const bytes = try readPathAlloc(std.testing.allocator, path, 3);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("abc", bytes);
}
