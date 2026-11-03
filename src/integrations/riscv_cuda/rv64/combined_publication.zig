//! Durable final acceptance metadata. Existing forensic files are never replaced.
const std = @import("std");
pub fn write(path: []const u8, json: []const u8) !void {
    // Linux O_PATH descriptors cannot be fsync'd.
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer dir.close();
    var file = try dir.createFile("combined-entry.json", .{ .exclusive = true, .truncate = false });
    defer file.close();
    try file.writeAll(json);
    try std.posix.fsync(file.handle);
    try std.posix.fsync(dir.fd);
}
