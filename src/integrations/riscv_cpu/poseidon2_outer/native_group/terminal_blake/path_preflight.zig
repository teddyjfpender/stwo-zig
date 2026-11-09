//! Read-only path admission for the test-only fresh guest->native->root mode.
//! Resolve existing ancestors before lexical normalization: symlink/.. follows
//! filesystem semantics, not a guessed string prefix. No directories are made.
const std = @import("std");
fn existsNoFollow(path: []const u8) !bool {
    _ = std.posix.fstatat(std.fs.cwd().fd, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}
fn canonicalCandidate(a: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0) return error.TerminalBlakeEndToEndInvalidPath;
    const absolute = if (std.fs.path.isAbsolute(path)) try a.dupe(u8, path) else blk: {
        const cwd = try std.fs.cwd().realpathAlloc(a, ".");
        defer a.free(cwd);
        break :blk try std.fs.path.join(a, &.{ cwd, path });
    };
    defer a.free(absolute);
    var current = std.mem.trimEnd(u8, absolute, "/");
    if (current.len == 0) current = "/";
    var suffix = std.ArrayList([]const u8).empty;
    defer suffix.deinit(a);
    while (true) {
        if (std.fs.cwd().realpathAlloc(a, current)) |prefix| {
            defer a.free(prefix);
            const parts = try a.alloc([]const u8, suffix.items.len + 1);
            defer a.free(parts);
            parts[0] = prefix;
            for (0..suffix.items.len) |i| parts[i + 1] = suffix.items[suffix.items.len - 1 - i];
            // Only missing suffixes remain; all existing symlinks were
            // resolved by realpath before any dot/dot-dot normalization.
            return std.fs.path.resolve(a, parts);
        } else |err| switch (err) {
            error.FileNotFound => {
                // A dangling symlink is an existing object, not a fresh
                // destination/parent that a producer may replace or follow.
                if (try existsNoFollow(current)) return error.TerminalBlakeEndToEndDanglingPath;
                const parent = std.fs.path.dirname(current) orelse return error.TerminalBlakeEndToEndInvalidPath;
                try suffix.append(a, std.fs.path.basename(current));
                current = parent;
            },
            else => return err,
        }
    }
}
fn contains(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, child)) return true;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    return parent.len == 1 or (child.len > parent.len and child[parent.len] == '/');
}
pub fn requireFreshDisjoint(a: std.mem.Allocator, native_path: []const u8, root_path: []const u8) !void {
    const native = try canonicalCandidate(a, native_path);
    defer a.free(native);
    const root = try canonicalCandidate(a, root_path);
    defer a.free(root);
    if (contains(native, root) or contains(root, native)) return error.TerminalBlakeEndToEndDirectoryOverlap;
    // Check both caller spellings and canonical targets. The second check
    // catches missing/../existing spellings before makePath creates a prefix.
    if (try existsNoFollow(native_path) or try existsNoFollow(native)) return error.TerminalBlakeEndToEndNativeExists;
    if (try existsNoFollow(root_path) or try existsNoFollow(root)) return error.TerminalBlakeEndToEndRootExists;
}
fn cases(a: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const native = try std.fs.path.join(a, &.{ base, "native" });
    defer a.free(native);
    const root = try std.fs.path.join(a, &.{ base, "root" });
    defer a.free(root);
    try requireFreshDisjoint(a, native, root);
    try std.testing.expectError(error.TerminalBlakeEndToEndDirectoryOverlap, requireFreshDisjoint(a, native, native));
    const nested = try std.fs.path.join(a, &.{ native, "child" });
    defer a.free(nested);
    try std.testing.expectError(error.TerminalBlakeEndToEndDirectoryOverlap, requireFreshDisjoint(a, native, nested));
    try std.testing.expectError(error.TerminalBlakeEndToEndDirectoryOverlap, requireFreshDisjoint(a, nested, native));
    const dots = try std.fs.path.join(a, &.{ base, "missing", "..", "native" });
    defer a.free(dots);
    try std.testing.expectError(error.TerminalBlakeEndToEndDirectoryOverlap, requireFreshDisjoint(a, native, dots));
    const sibling = try std.fs.path.join(a, &.{ base, "native-other" });
    defer a.free(sibling);
    try requireFreshDisjoint(a, native, sibling);
    // Existing parent symlink aliases and symlink/.. semantics.
    try tmp.dir.makeDir("real");
    try tmp.dir.makeDir("real/sub");
    try tmp.dir.symLink("real/sub", "alias", .{ .is_directory = true });
    const aliased = try std.fs.path.join(a, &.{ base, "alias", "..", "future" });
    defer a.free(aliased);
    const real = try std.fs.path.join(a, &.{ base, "real", "future" });
    defer a.free(real);
    try std.testing.expectError(error.TerminalBlakeEndToEndDirectoryOverlap, requireFreshDisjoint(a, aliased, real));
    // A dangling final link or parent is never treated as absent.
    try tmp.dir.symLink("not-created", "dangling", .{ .is_directory = true });
    const dangling = try std.fs.path.join(a, &.{ base, "dangling" });
    defer a.free(dangling);
    try std.testing.expectError(error.TerminalBlakeEndToEndDanglingPath, requireFreshDisjoint(a, dangling, root));
    // Rejection happens before any producer work or output mutation.
    try tmp.dir.makeDir("native");
    try std.testing.expectError(error.TerminalBlakeEndToEndNativeExists, requireFreshDisjoint(a, native, root));
    try tmp.dir.deleteDir("native");
    try tmp.dir.makeDir("root");
    try std.testing.expectError(error.TerminalBlakeEndToEndRootExists, requireFreshDisjoint(a, native, root));
    const missing_existing = try std.fs.path.join(a, &.{ base, "missing", "..", "root" });
    defer a.free(missing_existing);
    try std.testing.expectError(error.TerminalBlakeEndToEndRootExists, requireFreshDisjoint(a, native, missing_existing));
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    try tmp.dir.makeDir("real");
    try tmp.dir.symLink("real", "alias", .{ .is_directory = true });
    const native = try std.fs.path.join(a, &.{ base, "alias", "missing", "native" });
    defer a.free(native);
    const root = try std.fs.path.join(a, &.{ base, "other", "root" });
    defer a.free(root);
    try requireFreshDisjoint(a, native, root);
}
test "terminal fresh path preflight rejects overlaps aliases and existing outputs" {
    try cases(std.testing.allocator);
}
test "terminal fresh path preflight cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
