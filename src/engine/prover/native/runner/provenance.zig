//! Native benchmark source and environment provenance capture.

const std = @import("std");
const report = @import("../report.zig");

const override_names = [_][]const u8{
    "STWO_ZIG_WORKERS",
    "STWO_ZIG_POW_WORKERS",
    "STWO_ZIG_MERKLE_WORKERS",
    "STWO_ZIG_LEAF_BATCH_SIZE",
    "STWO_ZIG_MERKLE_POOL_REUSE",
    "STWO_ZIG_METAL_RADIX4_RFFT",
    "STWO_ZIG_METAL_CACHE_DIR",
};

pub const Owned = struct {
    git_commit: []u8,
    environment_overrides: []report.EnvironmentOverride,
    git_available: bool,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.git_commit);
        for (self.environment_overrides) |entry| allocator.free(entry.value);
        allocator.free(self.environment_overrides);
        self.* = undefined;
    }
};

pub const GitStatus = struct {
    output: []u8,
    available: bool,
};

pub fn collect(allocator: std.mem.Allocator) !Owned {
    var git_available = true;
    var git_commit = runCommand(allocator, &.{ "git", "rev-parse", "HEAD" }) catch blk: {
        git_available = false;
        break :blk try allocator.dupe(u8, "0000000000000000000000000000000000000000");
    };
    if (git_commit.len != 40) {
        allocator.free(git_commit);
        git_available = false;
        git_commit = try allocator.dupe(u8, "0000000000000000000000000000000000000000");
    }

    return collectWithCommit(allocator, git_commit, git_available);
}

/// Collect runtime override provenance around an already validated build-time
/// product identity. Product binaries bind commit/tree/dirty state when built;
/// copying that immutable commit avoids two child git processes on every cold
/// proof request without weakening identity-free compatibility tools.
pub fn collectEmbedded(
    allocator: std.mem.Allocator,
    implementation_commit: []const u8,
) !Owned {
    if (implementation_commit.len != 40) return error.InvalidEmbeddedCommit;
    return collectWithCommit(
        allocator,
        try allocator.dupe(u8, implementation_commit),
        true,
    );
}

fn collectWithCommit(
    allocator: std.mem.Allocator,
    git_commit: []u8,
    git_available: bool,
) !Owned {
    errdefer allocator.free(git_commit);

    var overrides = std.ArrayList(report.EnvironmentOverride).empty;
    errdefer {
        for (overrides.items) |entry| allocator.free(entry.value);
        overrides.deinit(allocator);
    }
    for (override_names) |name| {
        const value = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => continue,
            else => return err,
        };
        try overrides.append(allocator, .{ .name = name, .value = value });
    }
    return .{
        .git_commit = git_commit,
        .environment_overrides = try overrides.toOwnedSlice(allocator),
        .git_available = git_available,
    };
}

pub fn collectGitStatus(allocator: std.mem.Allocator) !GitStatus {
    const output = runCommand(
        allocator,
        &.{ "git", "status", "--porcelain", "--untracked-files=normal" },
    ) catch return .{
        .output = try allocator.alloc(u8, 0),
        .available = false,
    };
    return .{ .output = output, .available = true };
}

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.ProvenanceCommandFailed,
        else => return error.ProvenanceCommandFailed,
    }
    return allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \t\r\n"));
}

test "embedded product provenance preserves commit and runtime overrides" {
    const allocator = std.testing.allocator;
    var owned = try collectEmbedded(
        allocator,
        "0123456789012345678901234567890123456789",
    );
    defer owned.deinit(allocator);
    try std.testing.expect(owned.git_available);
    try std.testing.expectEqualStrings(
        "0123456789012345678901234567890123456789",
        owned.git_commit,
    );
    try std.testing.expectError(
        error.InvalidEmbeddedCommit,
        collectEmbedded(allocator, "short"),
    );
}
