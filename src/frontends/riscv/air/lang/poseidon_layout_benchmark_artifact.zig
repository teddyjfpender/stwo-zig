//! Reproducible check/update workflow for committed H-010 STWAIRB vectors.

const std = @import("std");
const production = @import("../memory_commitment/poseidon2_air.zig");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");
const vector = @import("poseidon_layout_benchmark_vector.zig");

pub const Mode = enum { check, update };
pub const default_directory =
    "design/typed-air/artifacts/h010-poseidon-layout-v1";
pub const index_filename = "index-v1.tsv";

const File = struct { log_size: u8, filename: []const u8 };
const files = [_]File{
    .{ .log_size = 10, .filename = "vector-log10.stwairb" },
    .{ .log_size = 14, .filename = "vector-log14.stwairb" },
};

pub fn execute(
    allocator: std.mem.Allocator,
    mode: Mode,
    path: []const u8,
) !void {
    if (mode == .update) try std.fs.cwd().makePath(path);
    var directory = try std.fs.cwd().openDir(path, .{});
    defer directory.close();
    for (files) |spec| {
        const expected = try vector.encodeAlloc(allocator, spec.log_size);
        defer allocator.free(expected);
        switch (mode) {
            .check => try checkFile(allocator, directory, spec, expected),
            .update => try updateFile(allocator, directory, spec, expected),
        }
    }
    const index = try renderIndexAlloc(allocator);
    defer allocator.free(index);
    switch (mode) {
        .check => try checkBytes(allocator, directory, index_filename, index),
        .update => try updateBytes(allocator, directory, index_filename, index),
    }
    std.debug.print(
        "typed-air H-010 Poseidon vectors: {s} passed for {d} vectors + index\n",
        .{ @tagName(mode), files.len },
    );
}

pub fn renderIndexAlloc(allocator: std.mem.Allocator) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll("record\tkey\tvalue\n");
    try writer.writeAll(
        "meta\tprojection_format\tstwo.typed-air.poseidon-layout-vector-index-v1\n",
    );
    try writer.print("meta\tvector_format\t{s}\n", .{protocol.vector_format});
    try writer.print(
        "meta\tgenerator_id\t{s}\n",
        .{protocol.vector_generator_id},
    );
    try writer.print(
        "meta\tsemantic_digest\t{s}\n",
        .{protocol.semantic_digest_hex},
    );
    try writer.writeAll(
        "vector\tlog_size\trows\tartifact_bytes\tartifact_sha256\tvector_seal\n",
    );
    for (files) |spec| {
        var owned = try vector.Owned.generate(allocator, spec.log_size, true);
        defer owned.deinit();
        const artifact_hex = std.fmt.bytesToHex(
            owned.identity.vector_artifact_sha256,
            .lower,
        );
        const seal_hex = std.fmt.bytesToHex(
            owned.identity.vector_seal,
            .lower,
        );
        try writer.print("vector\t{d}\t{d}\t{d}\t{s}\t{s}\n", .{
            spec.log_size,
            owned.identity.rows,
            owned.identity.artifact_bytes,
            artifact_hex,
            seal_hex,
        });
    }
    try writer.writeAll("boundary\tlog_size\trow\tenabler\twide\tio");
    for (0..16) |lane| try writer.print("\tinput_{d:0>2}", .{lane});
    for (0..16) |lane| try writer.print("\texpected_{d:0>2}", .{lane});
    try writer.writeByte('\n');
    for (files) |spec| {
        var owned = try vector.Owned.generate(allocator, spec.log_size, true);
        defer owned.deinit();
        const boundary_rows = [_]usize{ 0, 1, owned.calls.len - 1 };
        for (boundary_rows) |row| {
            const call = owned.calls[row];
            const expected = production.output(production.fill(call));
            try writer.print("boundary\t{d}\t{d}\t1\t{d}\t{d}", .{
                spec.log_size,
                row,
                @intFromBool(call.wide),
                @intFromBool(call.io),
            });
            for (call.input) |value| try writer.print("\t{d}", .{value});
            for (expected) |value| try writer.print("\t{d}", .{value.toU32()});
            try writer.writeByte('\n');
        }
    }
    return output.toOwnedSlice(allocator);
}

fn checkFile(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    spec: File,
    expected: []const u8,
) !void {
    try checkBytes(allocator, directory, spec.filename, expected);
    var decoded = try vector.Owned.decodeChecked(allocator, expected, spec.log_size);
    decoded.deinit();
}

fn checkBytes(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    filename: []const u8,
    expected: []const u8,
) !void {
    const actual = directory.readFileAlloc(
        allocator,
        filename,
        expected.len + 1,
    ) catch |err| switch (err) {
        error.FileNotFound => return error.ArtifactMismatch,
        else => return err,
    };
    defer allocator.free(actual);
    if (!std.mem.eql(u8, expected, actual)) return error.ArtifactMismatch;
}

fn updateFile(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    spec: File,
    expected: []const u8,
) !void {
    try updateBytes(allocator, directory, spec.filename, expected);
}

fn updateBytes(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    filename: []const u8,
    expected: []const u8,
) !void {
    const actual = directory.readFileAlloc(
        allocator,
        filename,
        expected.len + 1,
    ) catch |err| switch (err) {
        error.FileNotFound => return writeAtomic(directory, filename, expected),
        else => return err,
    };
    defer allocator.free(actual);
    if (std.mem.eql(u8, expected, actual)) return;
    try writeAtomic(directory, filename, expected);
}

fn writeAtomic(directory: std.fs.Dir, filename: []const u8, bytes: []const u8) !void {
    var write_buffer: [64 * 1024]u8 = undefined;
    var file = try directory.atomicFile(filename, .{ .write_buffer = &write_buffer });
    defer file.deinit();
    try file.file_writer.interface.writeAll(bytes);
    try file.finish();
}

test "H-010 default artifact set excludes opt-in log 18" {
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqual(@as(u8, 10), files[0].log_size);
    try std.testing.expectEqual(@as(u8, 14), files[1].log_size);
}
