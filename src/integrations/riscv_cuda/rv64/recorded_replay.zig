//! Test-harness input admission; absence of one capture role is not corruption.
const std = @import("std");
const Dataset = @import("recording_dataset.zig");

pub fn paths(a: std.mem.Allocator, root: []const u8, role: Dataset.Role) !Dataset.Paths {
    return Dataset.replay(a, root, role) catch |err| switch (err) {
        error.NoRecordingDatasets => error.SkipZigTest,
        else => return err,
    };
}

test "recorded replay admission: absent role skips while provided data remains mandatory" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    try std.testing.expectError(error.SkipZigTest, paths(a, root, .pack));
    const id = Dataset.Identity{ .execution = @splat(1), .program = @splat(2), .input = @splat(3), .attempt = @splat(4), .purpose = .execution };
    const owner = try Dataset.Dataset.create(a, root, id);
    defer owner.destroy() catch unreachable;
    _ = try owner.write(.nodes, "node-0.gnr", "valid");
    try std.testing.expectError(error.RecordingIncomplete, paths(a, root, .nodes));
    try owner.finish(true);
    try std.testing.expectError(error.SkipZigTest, paths(a, root, .pack));
    var selected = try paths(a, root, .nodes);
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 1), selected.items.len);
    var dir = try std.fs.cwd().openDir(selected.items[0], .{});
    defer dir.close();
    var file = try dir.createFile("node-0.gnr", .{});
    defer file.close();
    try file.writeAll("changed");
    try std.testing.expectError(error.RecordingInventoryMismatch, paths(a, root, .nodes));
}
