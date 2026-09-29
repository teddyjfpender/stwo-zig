//! Canonical Cairo input admission, independent of the transport encoding.

const std = @import("std");
const adapter = @import("mod.zig");
const compact = @import("adapted_input.zig");
const json = @import("official_input/mod.zig");

pub fn readFile(allocator: std.mem.Allocator, path: []const u8) !adapter.ProverInput {
    return readFileWithLimits(allocator, path, .{});
}

pub fn readFileWithLimits(allocator: std.mem.Allocator, path: []const u8, limits: json.Limits) !adapter.ProverInput {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file) return json.Error.InputNotRegularFile;
    if (stat.size == 0) return json.Error.EmptyInput;
    if (stat.size > limits.max_file_bytes) return json.Error.InputTooLarge;
    var header: [compact.MAGIC.len]u8 = undefined;
    const count = try file.readAll(&header);
    try file.seekTo(0);
    var storage: [256 * 1024]u8 = undefined;
    var reader = file.readerStreaming(&storage);
    return if (isCompact(header[0..count]))
        compact.read(allocator, &reader.interface, stat.size, limits)
    else
        json.read(allocator, &reader.interface, stat.size, limits);
}

pub fn parseSlice(allocator: std.mem.Allocator, bytes: []const u8, limits: json.Limits) !adapter.ProverInput {
    return if (isCompact(bytes))
        compact.parseSlice(allocator, bytes, limits)
    else
        json.parseSlice(allocator, bytes, limits);
}

fn isCompact(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, &compact.MAGIC);
}
