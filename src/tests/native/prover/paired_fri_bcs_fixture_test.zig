//! Fixed CAS05 byte-transcript replay against the independent hashlib model
//! in scripts/check_cas05_bcs_join.py. This is a deterministic test vector,
//! not a random-oracle or BCS soundness proof.

const std = @import("std");
const core = @import("stwo_core");
const Channel = core.channel.blake2s.Blake2sChannel;
const QM31 = core.fields.qm31.QM31;
const cascade = core.pcs.paired_sparse_cascade_experimental;
const old = core.pcs.paired_cascade_experimental;
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
    _ = try old.drawOodPoint(&channel, profile, source_root);

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
    const batch = old.drawBatchAfterOod(&channel, &claim_slices);
    try std.testing.expect(batch.eql(QM31.fromU32Unchecked(
        195907403,
        991404599,
        1032918988,
        1721050455,
    )));

    const expected_alphas = [3]QM31{
        QM31.fromU32Unchecked(207818986, 379074701, 1473678298, 439680753),
        QM31.fromU32Unchecked(1691656688, 1427965515, 1822009979, 2097874896),
        QM31.fromU32Unchecked(956968829, 273474105, 1920676061, 506046241),
    };
    for (expected_alphas, 0..) |expected, height| {
        try std.testing.expect(channel.drawSecureFelt().eql(expected));
        if (height < 2) merkle.mixRoot(&channel, [_]u8{@intCast(height + 2)} ** 32);
    }
    var terminal: [4]QM31 = undefined;
    for (&terminal, 0..) |*coefficient, i| {
        const first: u32 = @intCast(25 + 4 * i);
        coefficient.* = QM31.fromU32Unchecked(first, first + 1, first + 2, first + 3);
    }
    channel.mixFelts(&terminal);
    const raw = try core.queries.drawQueries(&channel, allocator, 7, 13);
    defer allocator.free(raw);
    const expected_raw = [_]usize{ 71, 72, 53, 46, 104, 55, 88, 37, 74, 79, 23, 2, 77 };
    try std.testing.expectEqualSlices(usize, &expected_raw, raw);
    try std.testing.expectEqual(@as(u32, 2), channel.n_draws);
    var expected_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_digest, "fa648bb0f4a5df143d275a916a309fb0a8f88d53157baeb64cbbd7e88678eebe");
    try std.testing.expectEqualSlices(u8, &expected_digest, &channel.digest);
}
