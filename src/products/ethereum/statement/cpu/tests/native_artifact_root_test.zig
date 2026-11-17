//! Private qualification path laws; no frontend/prover imports or filesystem writes.
const std = @import("std");
const owner = @import("native_artifact_root.zig");
const a = std.testing.allocator;
const expected = [_][]const u8{ "ethereum_cpu_v1", "ethereum_cpu_v2" };

test "qualification artifact: every original provider has an isolated relative and absolute directory" {
    try std.testing.expectEqual(expected.len, @typeInfo(owner.Provider).@"enum".fields.len);
    for (expected, 0..) |name, index| {
        const provider: owner.Provider = @enumFromInt(index);
        try std.testing.expectEqualStrings(name, @tagName(provider));
        for ([_][]const u8{ "qualification artifacts", "/qualification artifacts" }) |root| {
            const actual = (try owner.resolve(a, root, provider)).?;
            defer a.free(actual);
            const wanted = try std.fmt.allocPrint(a, "{s}/{s}", .{ root, name });
            defer a.free(wanted);
            try std.testing.expectEqualStrings(wanted, actual);
        }
        for (expected[0..index]) |prior| try std.testing.expect(!std.mem.eql(u8, prior, name));
    }
}

test "qualification artifact: absent and empty roots do not allocate or silently enable output" {
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const provider: owner.Provider = @enumFromInt(0);
    try std.testing.expectEqual(@as(?[]u8, null), try owner.resolve(failing.allocator(), null, provider));
    try std.testing.expectError(error.InvalidRv64ArtifactRoot, owner.resolve(failing.allocator(), "", provider));
    try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
}

fn exercisePaths(allocator: std.mem.Allocator) !void {
    for (0..expected.len) |index| {
        const path = (try owner.resolve(allocator, "qualified", @enumFromInt(index))).?;
        defer allocator.free(path);
    }
}

test "qualification artifact: every path allocation failure preserves ownership" {
    try std.testing.checkAllAllocationFailures(a, exercisePaths, .{});
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, owner.resolve(failing.allocator(), "qualified", @enumFromInt(0)));
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

fn exerciseDirectory(allocator: std.mem.Allocator) !void {
    const path = try owner.directory(allocator, @enumFromInt(0));
    defer if (path) |value| allocator.free(value);
}

test "qualification artifact: actual environment getter owns its result and propagates failures" {
    const root = std.process.getEnvVarOwned(a, "STWO_RV64_LEAN_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (root) |value| a.free(value);
    if (root) |value| {
        if (value.len == 0) {
            try std.testing.expectError(error.InvalidRv64ArtifactRoot, owner.directory(a, @enumFromInt(0)));
            return;
        }
    }
    const actual = try owner.directory(a, @enumFromInt(0));
    defer if (actual) |value| a.free(value);
    const wanted = try owner.resolve(a, root, @enumFromInt(0));
    defer if (wanted) |value| a.free(value);
    if (wanted) |value| try std.testing.expectEqualStrings(value, actual.?) else try std.testing.expect(actual == null);
    try std.testing.checkAllAllocationFailures(a, exerciseDirectory, .{});
}
