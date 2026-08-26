//! Explicit check/update command for reviewed `compat-v1` family artifacts.

const std = @import("std");
const compat_manifest = @import("compat_manifest.zig");
const compat_manifest_diff = @import("compat_manifest_diff.zig");
const trace = @import("../../runner/trace.zig");

const max_artifact_bytes: usize = 16 * 1024 * 1024;
const Mode = enum { check, update };

pub fn main() void {
    run() catch |err| {
        std.debug.print("typed-air manifest command failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) {
        std.debug.print(
            "usage: riscv-typed-air-manifest <check|update> <artifact-directory>\n",
            .{},
        );
        return error.InvalidArguments;
    }
    const mode = std.meta.stringToEnum(Mode, args[1]) orelse
        return error.InvalidArguments;

    var artifacts: [trace.N_FAMILIES]?compat_manifest.Artifact =
        .{null} ** trace.N_FAMILIES;
    defer for (&artifacts) |*artifact| {
        if (artifact.*) |*owned| owned.deinit();
    };
    var summaries: [trace.N_FAMILIES]compat_manifest.Summary = undefined;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        artifacts[family_index] = try compat_manifest.generate(allocator, family);
        summaries[family_index] = artifacts[family_index].?.summary;
    }
    var index: std.ArrayList(u8) = .empty;
    defer index.deinit(allocator);
    try compat_manifest.writeIndex(index.writer(allocator), &summaries);

    if (mode == .update) try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(args[2], .{});
    defer directory.close();
    for (artifacts) |artifact| {
        const owned = artifact.?;
        const filename = compat_manifest.artifactFilename(owned.summary.family);
        switch (mode) {
            .check => try checkFile(allocator, directory, filename, owned.bytes),
            .update => try updateFile(allocator, directory, filename, owned.bytes),
        }
    }
    switch (mode) {
        .check => try checkFile(
            allocator,
            directory,
            compat_manifest.index_filename,
            index.items,
        ),
        .update => try updateFile(
            allocator,
            directory,
            compat_manifest.index_filename,
            index.items,
        ),
    }
    std.debug.print(
        "typed-air compat-v1 manifests: {s} passed for {d} families\n",
        .{ @tagName(mode), trace.N_FAMILIES },
    );
}

fn checkFile(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    filename: []const u8,
    expected: []const u8,
) !void {
    const actual = directory.readFileAlloc(
        allocator,
        filename,
        max_artifact_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print(
                "{s}: missing actual/on-disk artifact\n",
                .{filename},
            );
            return error.ArtifactMismatch;
        },
        else => return err,
    };
    defer allocator.free(actual);
    if (std.mem.eql(u8, expected, actual)) return;
    try reportMismatch(allocator, filename, expected, actual);
    return error.ArtifactMismatch;
}

fn updateFile(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    filename: []const u8,
    expected: []const u8,
) !void {
    const actual = directory.readFileAlloc(
        allocator,
        filename,
        max_artifact_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            const expected_digest = digest(expected);
            const expected_hex = std.fmt.bytesToHex(expected_digest, .lower);
            std.debug.print(
                "{s}: add expected/generated {d} bytes sha256={s}\n",
                .{ filename, expected.len, &expected_hex },
            );
            return writeAtomic(directory, filename, expected);
        },
        else => return err,
    };
    defer allocator.free(actual);
    if (std.mem.eql(u8, expected, actual)) return;
    try reportMismatch(allocator, filename, expected, actual);
    try writeAtomic(directory, filename, expected);
}

fn reportMismatch(
    allocator: std.mem.Allocator,
    filename: []const u8,
    expected: []const u8,
    actual: []const u8,
) !void {
    if (std.mem.endsWith(u8, filename, ".stwairc")) {
        var semantic: std.ArrayList(u8) = .empty;
        defer semantic.deinit(allocator);
        try compat_manifest_diff.writeResult(
            semantic.writer(allocator),
            compat_manifest_diff.compare(expected, actual),
        );
        std.debug.print("{s}: {s}\n", .{ filename, semantic.items });
    }
    const expected_digest = digest(expected);
    const actual_digest = digest(actual);
    const expected_hex = std.fmt.bytesToHex(expected_digest, .lower);
    const actual_hex = std.fmt.bytesToHex(actual_digest, .lower);
    std.debug.print(
        "{s}: expected {d} bytes sha256={s}, found {d} bytes sha256={s}\n",
        .{ filename, expected.len, &expected_hex, actual.len, &actual_hex },
    );
}

fn writeAtomic(directory: std.fs.Dir, filename: []const u8, bytes: []const u8) !void {
    var write_buffer: [64 * 1024]u8 = undefined;
    var file = try directory.atomicFile(filename, .{ .write_buffer = &write_buffer });
    defer file.deinit();
    try file.file_writer.interface.writeAll(bytes);
    try file.finish();
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
