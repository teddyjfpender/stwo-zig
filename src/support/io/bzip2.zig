//! Bounded libbzip2 compression behind a Zig-owned allocation interface.

const std = @import("std");

const c = @cImport({
    @cDefine("BZ_NO_STDIO", "1");
    @cInclude("bzlib.h");
});

pub const Error = error{
    CompressionFailed,
    InputTooLarge,
    OutputBoundOverflow,
};

export fn bz_internal_error(errcode: c_int) callconv(.c) noreturn {
    std.debug.panic("libbzip2 internal invariant failed: {d}", .{errcode});
}

pub fn compressAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    if (input.len == 0 or input.len > std.math.maxInt(c_uint))
        return Error.InputTooLarge;
    const one_percent = std.math.add(usize, input.len, 99) catch
        return Error.OutputBoundOverflow;
    const bound = std.math.add(
        usize,
        input.len,
        one_percent / 100 + 600,
    ) catch return Error.OutputBoundOverflow;
    if (bound > std.math.maxInt(c_uint)) return Error.OutputBoundOverflow;

    const output = try allocator.alloc(u8, bound);
    errdefer allocator.free(output);
    var output_len: c_uint = @intCast(output.len);
    const status = c.BZ2_bzBuffToBuffCompress(
        @ptrCast(output.ptr),
        &output_len,
        @ptrCast(@constCast(input.ptr)),
        @intCast(input.len),
        9,
        0,
        0,
    );
    if (status != c.BZ_OK) return Error.CompressionFailed;
    return allocator.realloc(output, output_len);
}

test "bzip2 compressor emits a standard maximum-block stream" {
    const input = "Stwo-Cairo binary proof transport\n" ** 64;
    const encoded = try compressAlloc(std.testing.allocator, input);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(encoded.len > 4);
    try std.testing.expectEqualSlices(u8, "BZh9", encoded[0..4]);
}
