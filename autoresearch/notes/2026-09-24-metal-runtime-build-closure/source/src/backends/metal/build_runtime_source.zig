//! Bind the entire quoted-include closure into Zig's outer C compilation key.
//! Clang's dependency cache alone does not invalidate an already cached Zig test.
const std = @import("std");

pub fn digest(a: std.mem.Allocator, root: []const u8) ![64]u8 {
    var seen = std.StringHashMap(void).init(a);
    defer {
        var keys = seen.keyIterator();
        while (keys.next()) |key| a.free(key.*);
        seen.deinit();
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-metal-runtime-source-closure-v1\x00");
    try visit(a, root, &seen, &hash);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn visit(a: std.mem.Allocator, path: []const u8, seen: *std.StringHashMap(void), hash: *std.crypto.hash.sha2.Sha256) !void {
    const absolute = try std.fs.path.resolve(a, &.{path});
    if (seen.contains(absolute)) {
        a.free(absolute);
        return;
    }
    seen.put(absolute, {}) catch |err| {
        a.free(absolute);
        return err;
    };
    const bytes = try std.fs.cwd().readFileAlloc(a, absolute, 16 * 1024 * 1024);
    defer a.free(bytes);
    // Length delimiters prevent ambiguous concatenations. File contents include
    // the spelling and order of every include; absolute checkout paths are not
    // part of the digest, so identical checkouts have the same identity.
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, @intCast(bytes.len), .little);
    hash.update(&size);
    hash.update(bytes);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const child = try quotedInclude(line) orelse continue;
        const child_path = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(absolute).?, child });
        defer a.free(child_path);
        try visit(a, child_path, seen, hash);
    }
}

fn quotedInclude(line: []const u8) !?[]const u8 {
    var rest = std.mem.trimStart(u8, line, " \t\r");
    if (!std.mem.startsWith(u8, rest, "#")) return null;
    rest = std.mem.trimStart(u8, rest[1..], " \t");
    const length: usize = if (std.mem.startsWith(u8, rest, "include")) 7 else if (std.mem.startsWith(u8, rest, "import")) 6 else return null;
    rest = std.mem.trimStart(u8, rest[length..], " \t");
    // System headers belong to the SDK/toolchain identity. Refuse macro or
    // continued includes rather than silently omit an unrecognized dependency.
    if (rest.len != 0 and rest[0] == '<') return null;
    if (rest.len == 0 or rest[0] != '"') return error.UnsupportedRuntimeInclude;
    const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return error.UnsupportedRuntimeInclude;
    if (end == 1 or std.mem.indexOfScalar(u8, rest[1..end], '\\') != null)
        return error.UnsupportedRuntimeInclude;
    return rest[1..end];
}

pub fn flags(b: *std.Build, root: []const u8) []const []const u8 {
    const sha = digest(b.allocator, root) catch |err|
        std.debug.panic("cannot fingerprint Metal runtime closure {s}: {s}", .{ root, @errorName(err) });
    return b.allocator.dupe([]const u8, &.{ "-fobjc-arc", "-fblocks", b.fmt("-DSTWO_ZIG_RUNTIME_SOURCE_SHA256={s}", .{sha}) }) catch @panic("OOM");
}

test "runtime closure changes for transitive edits and handles repeated imports" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "root.m", .data = "#import \"child.h\"\n# include \"child.h\"\n" });
    try tmp.dir.writeFile(.{ .sub_path = "child.h", .data = "#include \"nested.h\"\n" });
    try tmp.dir.writeFile(.{ .sub_path = "nested.h", .data = "#import \"root.m\"\n#define VALUE 1\n" });
    const root = try tmp.dir.realpathAlloc(a, "root.m");
    defer a.free(root);
    const before = try digest(a, root);
    try std.testing.expectEqualSlices(u8, &before, &try digest(a, root));
    try tmp.dir.writeFile(.{ .sub_path = "nested.h", .data = "#import \"root.m\"\n#define VALUE 2\n" });
    try std.testing.expect(!std.mem.eql(u8, &before, &try digest(a, root)));
    try tmp.dir.deleteFile("nested.h");
    try std.testing.expectError(error.FileNotFound, digest(a, root));
}

test "runtime closure refuses unresolved include syntax" {
    try std.testing.expectEqualStrings("local.h", (try quotedInclude(" # include\t\"local.h\" // tracked")).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try quotedInclude("#import <Metal/Metal.h>"));
    try std.testing.expectEqual(@as(?[]const u8, null), try quotedInclude("// #include \"unused.h\""));
    try std.testing.expectError(error.UnsupportedRuntimeInclude, quotedInclude("#include HEADER_MACRO"));
    try std.testing.expectError(error.UnsupportedRuntimeInclude, quotedInclude("#include \\"));
    try std.testing.expectError(error.UnsupportedRuntimeInclude, quotedInclude("#include \"unfinished"));
}
