//! Real exclusive file I/O and rollback faults, using transport bytes only.
//! No proof, capture, PCS tree or verification receipt is created.
const std = @import("std");
const Publication = @import("block_v5_cpu_scoped_publication_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");

fn missing(dir: std.fs.Dir, comptime recipe: Publication.Recipe, index: u32) !void {
    var buffer: [128]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, dir.openFile(try Publication.path(recipe, &buffer, index), .{}));
}
fn retained(dir: std.fs.Dir, filename: []const u8, expected: []const u8) !void {
    const raw = try Files.readPinned(std.testing.allocator, dir, filename, expected.len, Files.hash(expected), 256);
    defer std.testing.allocator.free(raw);
    try std.testing.expectEqualStrings(expected, raw);
}
fn retainedNode(dir: std.fs.Dir, comptime recipe: Publication.Recipe, index: u32, expected: []const u8) !void {
    var buffer: [128]u8 = undefined;
    try retained(dir, try Publication.path(recipe, &buffer, index), expected);
}

const Callback = struct {
    count: usize = 0,
    stop: u32,
    fn put(self: *@This(), index: u32, successfully_created: usize) !void {
        // The just-published artifact is already in cleanup inventory, even
        // when this observational callback fails before it records metadata.
        try std.testing.expectEqual(@as(usize, index) + 1, successfully_created);
        self.count += 1;
        if (index == self.stop) return error.CallbackFailure;
    }
};
fn callbackFailure(dir: std.fs.Dir, comptime recipe: Publication.Recipe, callback: *Callback) !void {
    var transaction = try Publication.ForRecipe(recipe).Tracker.init(dir, 3, 3);
    errdefer transaction.rollback();
    for (0..3) |index| {
        try transaction.publish(@intCast(index), "new transport");
        try callback.put(@intCast(index), transaction.created);
    }
    transaction.commit();
}
test "cpu scoped publication: callback failure removes every successful prefix including current file for both recipes" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        for (0..3) |stop| {
            var directory = std.testing.tmpDir(.{});
            defer directory.cleanup();
            var callback = Callback{ .stop = @intCast(stop) };
            try std.testing.expectError(error.CallbackFailure, callbackFailure(directory.dir, recipe, &callback));
            try std.testing.expectEqual(stop + 1, callback.count);
            for (0..3) |index| try missing(directory.dir, recipe, @intCast(index));
        }
    }
}

fn laterFailure(dir: std.fs.Dir, comptime recipe: Publication.Recipe) !void {
    var transaction = try Publication.ForRecipe(recipe).Tracker.init(dir, 4, 4);
    errdefer transaction.rollback();
    for (0..3) |index| try transaction.publish(@intCast(index), "new transport");
    // Models a later verification, metadata allocation or final-owner failure.
    return error.LaterFailure;
}
test "cpu scoped publication: later failure rolls back only new destinations and preserves original future inputs" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var buffer: [128]u8 = undefined;
        try Files.publish(directory.dir, try Publication.path(recipe, &buffer, 3), "existing future");
        try Files.publish(directory.dir, "original-leaf.proof", "original input");
        try std.testing.expectError(error.LaterFailure, laterFailure(directory.dir, recipe));
        for (0..3) |index| try missing(directory.dir, recipe, @intCast(index));
        try retainedNode(directory.dir, recipe, 3, "existing future");
        try retained(directory.dir, "original-leaf.proof", "original input");
    }
}

fn collisionFailure(dir: std.fs.Dir, comptime recipe: Publication.Recipe) !void {
    var transaction = try Publication.ForRecipe(recipe).Tracker.init(dir, 3, 3);
    errdefer transaction.rollback();
    try transaction.publish(0, "new transport");
    try transaction.publish(1, "replacement");
    return error.ExpectedCollision;
}
test "cpu scoped publication: collisions preserve preexisting destinations and other recipe files" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        const other: Publication.Recipe = if (recipe == .complete) .requesters else .complete;
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var buffer: [128]u8 = undefined;
        try Files.publish(directory.dir, try Publication.path(recipe, &buffer, 1), "original destination");
        try Files.publish(directory.dir, try Publication.path(other, &buffer, 0), "other recipe");
        try std.testing.expectError(error.ExistingV5BundleArtifact, collisionFailure(directory.dir, recipe));
        try missing(directory.dir, recipe, 0);
        try retainedNode(directory.dir, recipe, 1, "original destination");
        try retainedNode(directory.dir, other, 0, "other recipe");
    }
}

test "cpu scoped publication: failed private inode creation never advances or removes existing files" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var buffer: [128]u8 = undefined;
        const filename = try Publication.path(recipe, &buffer, 0);
        var temporary_buffer: [160]u8 = undefined;
        const temporary = try std.fmt.bufPrint(&temporary_buffer, "{s}.part", .{filename});
        try directory.dir.writeFile(.{ .sub_path = temporary, .data = "existing private input" });
        var transaction = try Publication.ForRecipe(recipe).Tracker.init(directory.dir, 1, 1);
        try std.testing.expectError(error.PathAlreadyExists, transaction.publish(0, "new transport"));
        try std.testing.expectEqual(@as(usize, 0), transaction.created);
        transaction.rollback();
        transaction.rollback();
        try retained(directory.dir, temporary, "existing private input");
        try missing(directory.dir, recipe, 0);
    }
}

test "cpu scoped publication: resource and sequential guards precede filesystem access and closed tracker rejects reuse" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        const Tracker = Publication.ForRecipe(recipe).Tracker;
        try std.testing.expectError(error.CpuScopedPublicationResourceLimit, Tracker.init(undefined, 0, 0));
        try std.testing.expectError(error.CpuScopedPublicationResourceLimit, Tracker.init(undefined, 3, 2));
        try std.testing.expectError(error.CpuScopedPublicationResourceLimit, Tracker.init(undefined, @as(usize, std.math.maxInt(u32)) + 1, std.math.maxInt(usize)));
        var transaction = try Tracker.init(undefined, 1, 1);
        try std.testing.expectError(error.InvalidCpuScopedPublicationOrder, transaction.publish(1, "out of order"));
        transaction.rollback(); // Empty success prefix never touches undefined dir.
        try std.testing.expectError(error.ClosedCpuScopedPublication, transaction.publish(0, "closed"));
        var empty = try Tracker.init(undefined, 0, 1);
        try std.testing.expectError(error.InvalidCpuScopedPublicationOrder, empty.publish(0, "past census"));
        empty.commit();
        empty.rollback();
    }
}

test "cpu scoped publication: success commit disarms rollback and preserves complete recipe namespace" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var transaction = try Publication.ForRecipe(recipe).Tracker.init(directory.dir, 2, 2);
        try transaction.publish(0, "first transport");
        try std.testing.expectError(error.InvalidCpuScopedPublicationOrder, transaction.publish(0, "duplicate"));
        try transaction.publish(1, "second transport");
        try std.testing.expectError(error.InvalidCpuScopedPublicationOrder, transaction.publish(2, "past census"));
        transaction.commit();
        transaction.rollback();
        try std.testing.expectError(error.ClosedCpuScopedPublication, transaction.publish(2, "closed"));
        try retainedNode(directory.dir, recipe, 0, "first transport");
        try retainedNode(directory.dir, recipe, 1, "second transport");
        var buffer: [128]u8 = undefined;
        try std.testing.expectEqualStrings(if (recipe == .complete) "block-v5-cpu-scoped-node-7.proof" else "block-v5-cpu-requester-node-7.proof", try Publication.path(recipe, &buffer, 7));
    }
}

test "cpu scoped publication: reconstruct failure with zero published files preserves original inputs" {
    inline for (.{ Publication.Recipe.complete, Publication.Recipe.requesters }) |recipe| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var buffer: [128]u8 = undefined;
        try Files.publish(directory.dir, try Publication.path(recipe, &buffer, 0), "original node");
        var transaction = try Publication.ForRecipe(recipe).Tracker.init(directory.dir, 1, 1);
        transaction.rollback(); // Reconstruct performs no publication.
        try retainedNode(directory.dir, recipe, 0, "original node");
    }
}
