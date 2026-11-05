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

/// Metadata-only preflight occurs before the strict receiver constructs any
/// verifier graph. Each later read still requires nonnull bytes, closing races
/// with deletion without ever permitting a proving fallback.
pub fn requireExisting(dir: std.fs.Dir, plan: @import("ready_dag.zig").Plan) !void {
    for (plan.nodes[0..plan.count], 0..) |node, id| {
        var buffer: [64]u8 = undefined;
        const name = if (node.isLeaf()) try std.fmt.bufPrint(&buffer, "leaf-{d:0>6}.proof", .{node.first_leaf}) else try std.fmt.bufPrint(&buffer, "fold-{d:0>6}.proof", .{id});
        try requireFile(dir, name);
    }
    try requireFile(dir, "root.proof");
    try requireFile(dir, "tree.json");
}
fn requireFile(dir: std.fs.Dir, name: []const u8) !void {
    const stat = dir.statFile(name) catch |err| switch (err) {
        error.FileNotFound => return error.MissingRecursiveNodeProof,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidRecursiveNodeProof;
}

test "strict recursion receiver preflights every original node and rejects missing final fold" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const plan = try @import("ready_dag.zig").Plan.init(5);
    for (plan.nodes[0..plan.count], 0..) |node, id| {
        var buffer: [64]u8 = undefined;
        const name = if (node.isLeaf()) try std.fmt.bufPrint(&buffer, "leaf-{d:0>6}.proof", .{node.first_leaf}) else try std.fmt.bufPrint(&buffer, "fold-{d:0>6}.proof", .{id});
        try temporary.dir.writeFile(.{ .sub_path = name, .data = "physical node" });
    }
    try temporary.dir.writeFile(.{ .sub_path = "root.proof", .data = "physical root" });
    try std.testing.expectError(error.MissingRecursiveNodeProof, requireExisting(temporary.dir, plan));
    try temporary.dir.writeFile(.{ .sub_path = "tree.json", .data = "physical tree" });
    try requireExisting(temporary.dir, plan);
    try temporary.dir.deleteFile("fold-000008.proof");
    try std.testing.expectError(error.MissingRecursiveNodeProof, requireExisting(temporary.dir, plan));
    try temporary.dir.makeDir("fold-000008.proof");
    try std.testing.expectError(error.InvalidRecursiveNodeProof, requireExisting(temporary.dir, plan));
}

/// Binds exported root/tree copies to the freshly reconstructed artifacts,
/// without admitting producer metadata or rewriting the original directory.
pub fn requireBytes(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, expected: []const u8) !void {
    const actual = try dir.readFileAlloc(a, name, expected.len);
    defer a.free(actual);
    if (!std.mem.eql(u8, expected, actual)) return error.RecursiveReceiverArtifactMismatch;
}

test "strict receiver binds physical root and tree copies without rewriting" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "root.proof", .data = "proof" });
    try requireBytes(std.testing.allocator, temporary.dir, "root.proof", "proof");
    try std.testing.expectError(error.RecursiveReceiverArtifactMismatch, requireBytes(std.testing.allocator, temporary.dir, "root.proof", "proog"));
    try temporary.dir.writeFile(.{ .sub_path = "tree.json", .data = "tree" });
    try std.testing.expectError(error.RecursiveReceiverArtifactMismatch, requireBytes(std.testing.allocator, temporary.dir, "tree.json", "tref"));
}
