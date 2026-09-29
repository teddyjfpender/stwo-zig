//! Compact transport must preserve official semantics and fail before unsafe allocation.

const std = @import("std");
const cairo = @import("cairo_frontend");
const adapter = cairo.adapter;
const compact = adapter.adapted_input;
const fixture = "vectors/cairo/official/all_opcodes.prover_input.cpi";

test "compact Cairo input matches the official JSON semantic summary" {
    var json = try adapter.input.readFile(std.testing.allocator, "vectors/cairo/official/all_opcodes.prover_input.json");
    defer json.deinit(std.testing.allocator);
    var binary = try adapter.input.readFile(std.testing.allocator, fixture);
    defer binary.deinit(std.testing.allocator);
    const digest = [_]u8{0} ** 32;
    try std.testing.expectEqualDeep(
        adapter.official_input.summary.fromInput(&json, digest),
        adapter.official_input.summary.fromInput(&binary, digest),
    );
}

test "compact Cairo input refuses oversized counts before allocating states" {
    const bytes = try readFixture();
    defer std.testing.allocator.free(bytes);
    std.mem.writeInt(u64, bytes[64..72], 1 << 28, .little);
    try std.testing.expectError(error.Truncated, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
    std.mem.writeInt(u64, bytes[64..72], compact.MAX_ITEMS + 1, .little);
    try std.testing.expectError(error.LengthOverflow, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
}

test "compact Cairo input refuses mutually impossible memory table lengths" {
    const bytes = try readFixture();
    defer std.testing.allocator.free(bytes);
    const header = memoryHeader(bytes);
    const remaining = bytes.len - header - 48;
    std.mem.writeInt(u64, bytes[header + 32 ..][0..8], remaining / 32, .little);
    std.mem.writeInt(u64, bytes[header + 40 ..][0..8], remaining / 16, .little);
    try std.testing.expectError(error.Truncated, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
}

test "compact Cairo input shares JSON resource and address admission" {
    const bytes = try readFixture();
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.InputTooLarge, adapter.input.parseSlice(std.testing.allocator, bytes, .{ .max_states = 1497 }));
    try std.testing.expectError(error.InputTooLarge, adapter.input.parseSlice(std.testing.allocator, bytes, .{ .max_file_bytes = bytes.len - 1 }));
    const first = firstState(bytes);
    std.mem.writeInt(u32, bytes[first..][0..4], 0xffff_ffff, .little);
    try std.testing.expectError(error.StateAddressOutOfRange, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
}

test "compact Cairo input rejects reserved bits, truncation and trailing data" {
    const bytes = try readFixture();
    defer std.testing.allocator.free(bytes);
    inline for (.{ 12, 49, 50, 52, 60 }) |offset| {
        const saved = bytes[offset];
        bytes[offset] |= 0x80;
        try std.testing.expectError(error.NonCanonicalEncoding, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
        bytes[offset] = saved;
    }
    for ([_]usize{ 8, 63, 72, bytes.len - 1 }) |len| {
        try std.testing.expectError(error.Truncated, compact.parseSlice(std.testing.allocator, bytes[0..len], .{}));
    }
    const extended = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(extended);
    @memcpy(extended[0..bytes.len], bytes);
    extended[bytes.len] = 0;
    try std.testing.expectError(error.TrailingData, adapter.input.parseSlice(std.testing.allocator, extended, .{}));
}

test "compact Cairo input rejects invalid memory ids and public context" {
    const bytes = try readFixture();
    defer std.testing.allocator.free(bytes);
    const memory = memoryHeader(bytes) + 48;
    const saved = std.mem.readInt(u32, bytes[memory..][0..4], .little);
    std.mem.writeInt(u32, bytes[memory..][0..4], 0x8000_0000, .little);
    try std.testing.expectError(error.InvalidMemoryTag, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
    std.mem.writeInt(u32, bytes[memory..][0..4], saved, .little);
    bytes[48] &= 0xfe;
    try std.testing.expectError(error.InvalidPublicSegmentContext, adapter.input.parseSlice(std.testing.allocator, bytes, .{}));
}

fn readFixture() ![]u8 {
    return std.fs.cwd().readFileAlloc(std.testing.allocator, fixture, 256 * 1024);
}

fn firstState(bytes: []const u8) usize {
    var cursor: usize = 64;
    for (0..20) |_| {
        const count = std.mem.readInt(u64, bytes[cursor..][0..8], .little);
        if (count != 0) return cursor + 8;
        cursor += 8;
    }
    unreachable;
}

fn memoryHeader(bytes: []const u8) usize {
    var cursor: usize = 64;
    for (0..20) |_| {
        const count = std.mem.readInt(u64, bytes[cursor..][0..8], .little);
        cursor += 8 + @as(usize, @intCast(count)) * 12;
    }
    return cursor;
}
