const std = @import("std");
const core = @import("stwo_core");
const protocol = core.channel.blake3;
const Frame = protocol.Frame;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
test "BLAKE3 canonical frames match native operations and full hash witnesses" {
    const a = std.testing.allocator;
    const state = (protocol.Channel{}).digestBytes();
    const words = [_]u32{ 0, 0x80000000, 0xffffffff };
    const felts = [_]QM31{ QM31.fromU32Unchecked(0, 1, 2147483646, 17), QM31.fromU32Unchecked(19, 23, 29, 31) };
    const leaf = [_]M31{ M31.zero(), M31.one(), M31.fromCanonical(2147483646) };
    const right: [32]u8 = @splat(0xff);
    const frames = [_]Frame{
        .{ .init = {} },
        .{ .words = .{ .state = state, .values = &words } },
        .{ .felts = .{ .state = state, .values = &felts } },
        .{ .integer = .{ .state = state, .value = 0xfedcba9876543210 } },
        .{ .root = .{ .state = state, .value = right } },
        .{ .draw = .{ .state = state, .index = 3 } },
        .{ .pow = .{ .state = state, .bits = 8, .nonce = 19 } },
        .{ .leaf = &leaf },
        .{ .node = .{ .left = state, .right = right } },
    };
    for (frames) |frame| {
        const bytes = try frame.encode(a);
        defer a.free(bytes);
        try std.testing.expectEqual(try frame.encodedSize(), bytes.len);
        try std.testing.expectEqualSlices(u8, protocol.PROTOCOL_ID, bytes[0..protocol.PROTOCOL_ID.len]);
        try std.testing.expectEqual(@intFromEnum(std.meta.activeTag(frame)), bytes[protocol.PROTOCOL_ID.len]);
        var expected: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &expected, .{});
        try std.testing.expectEqualSlices(u8, &expected, &frame.hash());
        var prepared = try @import("../blake3_hash_witness.zig").prepare(a, 991, bytes, expected);
        defer prepared.rows.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &prepared.digest);
    }
    var channel = protocol.Channel{};
    channel.mixU32s(&words);
    try std.testing.expectEqualSlices(u8, &frames[1].hash(), &channel.digestBytes());
    channel = .{};
    channel.mixFelts(&felts);
    try std.testing.expectEqualSlices(u8, &frames[2].hash(), &channel.digestBytes());
    channel = .{};
    channel.mixU64(0xfedcba9876543210);
    try std.testing.expectEqualSlices(u8, &frames[3].hash(), &channel.digestBytes());
    channel = .{};
    channel.mixRoot(right);
    try std.testing.expectEqualSlices(u8, &frames[4].hash(), &channel.digestBytes());
    channel = .{ .n_draws = 3 };
    const draw = channel.drawU32s();
    var draw_bytes: [32]u8 = undefined;
    for (draw, 0..) |word, i| std.mem.writeInt(u32, draw_bytes[i * 4 ..][0..4], word, .little);
    try std.testing.expectEqualSlices(u8, &frames[5].hash(), &draw_bytes);
    const pow = frames[6].hash();
    try std.testing.expectEqual(@ctz(std.mem.readInt(u32, pow[0..4], .little)) >= 8, (protocol.Channel{}).verifyPowNonce(8, 19));
    const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;
    var h = Hasher.defaultWithInitialState();
    h.updateLeaf(leaf[0..1]);
    h.updateLeaf(leaf[1..]);
    try std.testing.expectEqualSlices(u8, &frames[7].hash(), &h.finalize());
    try std.testing.expectEqualSlices(u8, &frames[8].hash(), &Hasher.hashChildren(.{ .left = state, .right = right }));
}
