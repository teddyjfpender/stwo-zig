//! Fixed CAS05 byte-transcript replay against the independent hashlib model
//! in scripts/check_cas05_bcs_join.py. This is a deterministic test vector,
//! not a random-oracle or BCS soundness proof.

const std = @import("std");
const core = @import("stwo_core");
const Channel = core.channel.blake2s.Blake2sChannel;
const QM31 = core.fields.qm31.QM31;
const cascade = core.pcs.paired_sparse_cascade_experimental;
const merkle = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;

test "CAS05 raw Blake2s transcript matches independent byte fixture" {
    const allocator = std.testing.allocator;
    var channel = Channel{};
    const profile = cascade.Profile{ .source = .{
        .largest_log_size = 7,
        .height_count = 3,
        .columns = .{ 2, 2, 2, 0, 0, 0, 0, 0 },
        .query_count = 13,
    }, .log_blowup = 2 };
    const source_root = [_]u8{1} ** 32;
    cascade.bindVersion(&channel);
    _ = try cascade.drawOodPoint(&channel, profile, source_root);

    var claims: [3][2]QM31 = undefined;
    for (0..3) |height| {
        for (0..2) |column| {
            const first: u32 = @intCast(1 + 8 * height + 4 * column);
            claims[height][column] = QM31.fromU32Unchecked(
                first,
                first + 1,
                first + 2,
                first + 3,
            );
        }
    }
    const claim_slices = [3][]const QM31{ &claims[0], &claims[1], &claims[2] };
    const batch = cascade.drawBatchAfterOod(&channel, &claim_slices);
    try std.testing.expect(batch.eql(QM31.fromU32Unchecked(
        509825195,
        245298048,
        1594495169,
        1420883916,
    )));

    const expected_alphas = [3]QM31{
        QM31.fromU32Unchecked(1947997308, 20437450, 856818144, 497347522),
        QM31.fromU32Unchecked(345394895, 176559447, 906012219, 1249083167),
        QM31.fromU32Unchecked(469933430, 317179828, 1411933177, 1490171744),
    };
    for (expected_alphas, 0..) |expected, height| {
        try std.testing.expect(channel.drawSecureFelt().eql(expected));
        if (height < 2) cascade.mixLineRoot(&channel, height, [_]u8{@intCast(height + 2)} ** 32);
    }
    var terminal: [4]QM31 = undefined;
    for (&terminal, 0..) |*coefficient, i| {
        const first: u32 = @intCast(25 + 4 * i);
        coefficient.* = QM31.fromU32Unchecked(first, first + 1, first + 2, first + 3);
    }
    cascade.mixTerminal(&channel, &terminal);
    const raw = try core.queries.drawQueries(&channel, allocator, 7, 13);
    defer allocator.free(raw);
    const expected_raw = [_]usize{ 54, 105, 48, 49, 119, 101, 18, 37, 9, 12, 5, 10, 53 };
    try std.testing.expectEqualSlices(usize, &expected_raw, raw);
    try std.testing.expectEqual(@as(u32, 2), channel.n_draws);
    var expected_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_digest, "d8b8d28b38d740c724937975a4a66113a4fc3d3a10ad201b3e750a35a88c8066");
    try std.testing.expectEqualSlices(u8, &expected_digest, &channel.digest);
}

test "CAS05 typed absorption separates root and two-QM31 byte roles" {
    const root = [_]u8{0} ** 32;
    const two_felts = [_]QM31{ QM31.zero(), QM31.zero() };
    var old_root = Channel{};
    var old_felts = Channel{};
    merkle.mixRoot(&old_root, root);
    old_felts.mixFelts(&two_felts);
    // This is an exact preimage ambiguity, not a hash collision.
    try std.testing.expectEqualSlices(u8, &old_root.digest, &old_felts.digest);

    var new_root = Channel{};
    var new_felts = Channel{};
    cascade.mixLineRoot(&new_root, 0, root);
    cascade.mixTerminal(&new_felts, &two_felts);
    try std.testing.expect(!std.mem.eql(u8, &new_root.digest, &new_felts.digest));
}
