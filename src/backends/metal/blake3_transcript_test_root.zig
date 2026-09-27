const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const Channel = core.channel.blake3.Channel;
const QM31 = core.fields.qm31.QM31;
const Op = @import("runtime/opening_operations.zig").Blake3TranscriptOperation;

test "Metal BLAKE3 transcript matches canonical framing and full width draw counters" {
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(8192 * 4);
    defer arena.deinit();
    const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..8192];
    const expected = try std.testing.allocator.alloc(u32, 8192);
    defer std.testing.allocator.free(expected);
    var channel = Channel{};
    @memset(actual, 0xa5a5a5a5);
    writeState(actual, &channel);
    @memcpy(expected, actual);
    const Case = struct { op: Op, count: u32 };
    for ([_]Case{ .{ .op = .words, .count = 0 }, .{ .op = .words, .count = 1 }, .{ .op = .words, .count = 249 }, .{ .op = .words, .count = 250 }, .{ .op = .words, .count = 1025 }, .{ .op = .felts, .count = 0 }, .{ .op = .felts, .count = 4 }, .{ .op = .felts, .count = 1028 }, .{ .op = .integer, .count = 2 }, .{ .op = .root, .count = 8 } }) |case| {
        for (actual[128..][0..case.count], 0..) |*word, i| {
            word.* = @as(u32, @intCast(i)) *% 0x9e3779b9;
            if (case.op == .felts) word.* %= 0x7fffffff;
        }
        @memcpy(expected, actual);
        switch (case.op) {
            .words => channel.mixU32s(actual[128..][0..case.count]),
            .felts => {
                const values = try std.testing.allocator.alloc(QM31, case.count / 4);
                defer std.testing.allocator.free(values);
                for (values, 0..) |*value, i| value.* = QM31.fromU32Unchecked(actual[128 + i * 4], actual[129 + i * 4], actual[130 + i * 4], actual[131 + i * 4]);
                channel.mixFelts(values);
            },
            .integer => channel.mixU64(@as(u64, actual[128]) | (@as(u64, actual[129]) << 32)),
            .root => channel.mixRoot(std.mem.toBytes(actual[128..][0..8].*)),
            .draw_secure => unreachable,
        }
        _ = try runtime.blake3Transcript(arena, 32, 128, case.count, case.op);
        writeState(expected, &channel);
        try std.testing.expectEqualSlices(u32, expected, actual);
        for ([_]u32{ 0, 1, 2, 3, 7 }) |count| {
            const values = try channel.drawSecureFelts(std.testing.allocator, count);
            defer std.testing.allocator.free(values);
            for (values, 0..) |value, i| for (value.toM31Array(), 0..) |coordinate, j| {
                expected[4096 + i * 4 + j] = coordinate.v;
            };
            _ = try runtime.blake3Transcript(arena, 32, 4096, count, .draw_secure);
            writeState(expected, &channel);
            try std.testing.expectEqualSlices(u32, expected, actual);
        }
    }
    for ([_]u64{ 0xffffffff, 0x100000009, std.math.maxInt(u64) - 2 }) |counter| {
        channel.n_draws = counter;
        writeState(actual, &channel);
        @memcpy(expected, actual);
        const values = try channel.drawSecureFelts(std.testing.allocator, 3);
        defer std.testing.allocator.free(values);
        for (values, 0..) |value, i| for (value.toM31Array(), 0..) |coordinate, j| {
            expected[4096 + i * 4 + j] = coordinate.v;
        };
        _ = try runtime.blake3Transcript(arena, 32, 4096, 3, .draw_secure);
        writeState(expected, &channel);
        try std.testing.expectEqualSlices(u32, expected, actual);
    }
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 4096, 1, .draw_secure));
    try std.testing.expectEqual(@as(u32, 1), actual[42]);
    expected[42] = 1;
    try std.testing.expectEqualSlices(u32, expected, actual);
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 128, 8, .root));
    actual[42] = 0;
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 32, 8, .root));
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 8191, 2, .draw_secure));
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 128, 3, .felts));
    actual[128] = 0xffffffff;
    try std.testing.expectError(error.CommitmentFailed, runtime.blake3Transcript(arena, 32, 128, 4, .felts));
}
fn writeState(words: []u32, channel: *const Channel) void {
    for (0..8) |i| words[32 + i] = std.mem.readInt(u32, channel.digest[i * 4 ..][0..4], .little);
    words[40] = @truncate(channel.n_draws);
    words[41] = @truncate(channel.n_draws >> 32);
    words[42] = 0;
}
