//! Explicit check/update command for reviewed P-002 static-profile artifacts.

const std = @import("std");
const artifact_mod = @import("static_profile_registry_artifact.zig");

const max_artifact_bytes: usize = 4 * 1024 * 1024;
const Mode = enum { check, update };

const GeneratedFile = struct {
    filename: []const u8,
    bytes: []const u8,
};

pub fn main() void {
    run() catch |err| {
        std.debug.print(
            "typed-air static-profile command failed: {s}\n",
            .{@errorName(err)},
        );
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
            "usage: riscv-typed-air-static-profile <check|update> " ++
                "<artifact-directory>\n",
            .{},
        );
        return error.InvalidArguments;
    }
    const mode = std.meta.stringToEnum(Mode, args[1]) orelse
        return error.InvalidArguments;

    var artifact = try artifact_mod.generate(allocator);
    defer artifact.deinit();
    const files = [_]GeneratedFile{
        .{ .filename = artifact_mod.machine_filename, .bytes = artifact.machine },
        .{ .filename = artifact_mod.readable_filename, .bytes = artifact.readable },
    };

    if (mode == .update) try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(args[2], .{});
    defer directory.close();
    for (files) |file| switch (mode) {
        .check => try checkFile(allocator, directory, file.filename, file.bytes),
        .update => try updateFile(allocator, directory, file.filename, file.bytes),
    };
    std.debug.print(
        "typed-air P-002 native family profiles: {s} passed for {d} files\n",
        .{ @tagName(mode), files.len },
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
            std.debug.print("{s}: missing reviewed artifact\n", .{filename});
            return error.ArtifactMismatch;
        },
        else => return err,
    };
    defer allocator.free(actual);
    artifact_mod.checkProjection(expected, actual) catch {
        reportMismatch(filename, expected, actual);
        return error.ArtifactMismatch;
    };
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
            reportAddition(filename, expected);
            return writeAtomic(directory, filename, expected);
        },
        else => return err,
    };
    defer allocator.free(actual);
    artifact_mod.checkProjection(expected, actual) catch {
        reportMismatch(filename, expected, actual);
        return writeAtomic(directory, filename, expected);
    };
}

fn reportAddition(filename: []const u8, expected: []const u8) void {
    const expected_digest = digest(expected);
    const expected_hex = std.fmt.bytesToHex(expected_digest, .lower);
    std.debug.print(
        "{s}: add generated {d} bytes sha256={s}\n",
        .{ filename, expected.len, &expected_hex },
    );
}

fn reportMismatch(
    filename: []const u8,
    expected: []const u8,
    actual: []const u8,
) void {
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
