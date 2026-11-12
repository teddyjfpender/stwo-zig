//! Generic physical-cell accounting and durable artifact publication.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
pub const SourceCells = struct { fixed: u64, main: u64, interaction: u64 };
pub fn sourceCells(a: std.mem.Allocator, setup: *const A.Prepared, public: A.Public) !SourceCells {
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    const main = try setup.logs(a, public, 1);
    defer a.free(main);
    const inter = try setup.logs(a, public, 2);
    defer a.free(inter);
    var result = SourceCells{ .fixed = 0, .main = 0, .interaction = 0 };
    for (fixed) |column| result.fixed += @as(u64, 1) << @intCast(column.log_size);
    for (main) |log| result.main += @as(u64, 1) << @intCast(log);
    for (inter) |log| result.interaction += @as(u64, 1) << @intCast(log);
    return result;
}
pub fn writeExclusive(directory: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try directory.createFile(name, .{ .exclusive = true });
    errdefer directory.deleteFile(name) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}

pub fn replaceSummary(directory: std.fs.Dir, json: []const u8) !void {
    var file = try directory.createFile("summary.pending", .{});
    var open = true;
    defer if (open) file.close();
    errdefer directory.deleteFile("summary.pending") catch {};
    try file.writeAll(json);
    try file.sync();
    file.close();
    open = false;
    try directory.rename("summary.pending", "summary.json");
}

test "artifact publication refuses an existing destination without deleting it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeExclusive(tmp.dir, "proof", "original");
    try std.testing.expectError(error.PathAlreadyExists, writeExclusive(tmp.dir, "proof", "replacement"));
    const bytes = try tmp.dir.readFileAlloc(std.testing.allocator, "proof", 64);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("original", bytes);
}

test "artifact summary replaces the complete old file and retires its staging name" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try replaceSummary(tmp.dir, "long previous summary");
    try replaceSummary(tmp.dir, "new");
    const bytes = try tmp.dir.readFileAlloc(std.testing.allocator, "summary.json", 64);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("new", bytes);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("summary.pending", .{}));
}

test "failed artifact summary publication removes staging and preserves the destination" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("summary.json");
    if (replaceSummary(tmp.dir, "candidate")) |_| return error.ExpectedPublicationFailure else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("summary.pending", .{}));
    var destination = try tmp.dir.openDir("summary.json", .{});
    destination.close();
}
