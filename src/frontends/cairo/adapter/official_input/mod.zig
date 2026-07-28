//! Bounded, strict reader for official Stwo-Cairo JSON `ProverInput`.

const std = @import("std");
const adapter = @import("../mod.zig");

pub const decode = @import("decode.zig");
pub const summary = @import("summary.zig");
pub const wire = @import("wire.zig");
pub const Limits = decode.Limits;

pub const Error = error{
    EmptyInput,
    InputNotRegularFile,
    InputTooLarge,
};

pub fn readFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) !adapter.ProverInput {
    return readFileWithLimits(allocator, path, .{});
}

pub fn readFileWithLimits(
    allocator: std.mem.Allocator,
    path: []const u8,
    limits: Limits,
) !adapter.ProverInput {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file) return Error.InputNotRegularFile;
    if (stat.size == 0) return Error.EmptyInput;
    if (stat.size > limits.max_file_bytes) return Error.InputTooLarge;

    var buffer: [256 * 1024]u8 = undefined;
    var file_reader = file.readerStreaming(&buffer);
    var json_reader = std.json.Reader.init(allocator, &file_reader.interface);
    defer json_reader.deinit();
    var parsed = try std.json.parseFromTokenSource(
        wire.ProverInput,
        allocator,
        &json_reader,
        .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = false,
            .max_value_len = 128,
        },
    );
    defer parsed.deinit();
    return decode.fromWire(allocator, parsed.value, limits);
}

pub fn parseSlice(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    limits: Limits,
) !adapter.ProverInput {
    if (encoded.len == 0) return Error.EmptyInput;
    if (encoded.len > limits.max_file_bytes) return Error.InputTooLarge;
    var parsed = try std.json.parseFromSlice(
        wire.ProverInput,
        allocator,
        encoded,
        .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = false,
            .max_value_len = 128,
        },
    );
    defer parsed.deinit();
    return decode.fromWire(allocator, parsed.value, limits);
}
