//! Directory-relative durable exclusive publication; one transaction owner.

const std = @import("std");

pub fn writeExclusive(directory: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try directory.createFile(name, .{ .exclusive = true });
    errdefer directory.deleteFile(name) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
