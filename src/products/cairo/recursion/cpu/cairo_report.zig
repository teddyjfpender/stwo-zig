const std = @import("std");

pub fn write(path: []const u8, input_ns: u64, prove_ns: u64, publication_ns: u64) !void {
    var buffer: [4096]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    try std.json.Stringify.value(.{
        .schema = "stwo-zig-circuit-cairo-proof-report-v1",
        .timing = .{
            .input_and_assets_ns = input_ns,
            .prove_ns = prove_ns,
            .request_until_publication_ns = publication_ns,
        },
    }, .{}, &atomic.file_writer.interface);
    try atomic.file_writer.interface.writeByte('\n');
    try atomic.finish();
}
