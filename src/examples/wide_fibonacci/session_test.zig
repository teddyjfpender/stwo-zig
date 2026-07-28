//! Transaction-level tests for reusable wide Fibonacci prover sessions.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("../../interop/proof_wire/mod.zig");
const subject = @import("../wide_fibonacci.zig");

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

test "wide Fibonacci session: sequential proofs match compatibility path exactly" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const statement = subject.Statement{ .log_n_rows = 5, .sequence_len = 8 };
    const required_log = try subject.requiredTwiddleCircleLog(statement, config);

    var session = try subject.CpuProverEngine.initSession(
        allocator,
        config,
        required_log,
        1 << 20,
    );
    defer session.deinit(allocator);

    var compatibility = try subject.prove(allocator, config, statement);
    defer compatibility.proof.deinit(allocator);

    const first_input = try subject.prepareInput(allocator, statement);
    var first = try subject.provePreparedWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        first_input,
        null,
    );
    defer first.proof.deinit(allocator);

    const second_input = try subject.prepareInput(allocator, statement);
    var second = try subject.provePreparedWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        second_input,
        null,
    );
    defer second.proof.deinit(allocator);

    const expected = try proof_wire.encodeProofBytes(allocator, compatibility.proof);
    defer allocator.free(expected);
    const first_bytes = try proof_wire.encodeProofBytes(allocator, first.proof);
    defer allocator.free(first_bytes);
    const second_bytes = try proof_wire.encodeProofBytes(allocator, second.proof);
    defer allocator.free(second_bytes);

    try std.testing.expectEqualSlices(u8, expected, first_bytes);
    try std.testing.expectEqualSlices(u8, expected, second_bytes);
    try std.testing.expectEqual(@as(usize, 8912), expected.len);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected, &digest, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x2c, 0x90, 0x68, 0x4b, 0x49, 0x38, 0x78, 0x04,
        0xfd, 0x51, 0xbe, 0xf3, 0xe2, 0x86, 0x20, 0x1e,
        0x4b, 0x0b, 0x43, 0xa9, 0x6b, 0x42, 0x20, 0x0a,
        0x7b, 0x68, 0x12, 0xa5, 0xa1, 0x1e, 0x31, 0x7d,
    }, &digest);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "wide Fibonacci commitments match pinned raw Stwo oracle order" {
    const allocator = std.testing.allocator;
    var output = try subject.prove(
        allocator,
        try testConfig(),
        .{ .log_n_rows = 5, .sequence_len = 16 },
    );
    defer output.proof.deinit(allocator);

    const commitments = output.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 3), commitments.len);
    const expected_hex = [_][]const u8{
        "2a133e150238721921d1ea772882979c810f85f2849099b9d3415a8619d85fad",
        "dfc402b1c9be2a0b32d61bc810f24190b5e549d5d86c41ac2b1b8d01063aeaeb",
        "ee5df2e32512551d63a489914903324afccee9670125e3f8783ce19f495854a2",
    };
    for (commitments, expected_hex) |commitment, encoded| {
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, encoded);
        try std.testing.expectEqualSlices(u8, &expected, &commitment);
    }
}

test "wide Fibonacci session: request geometry is rejected before proving" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const statement = subject.Statement{ .log_n_rows = 5, .sequence_len = 8 };
    const required_log = try subject.requiredTwiddleCircleLog(statement, config);

    var session = try subject.CpuProverEngine.initSession(
        allocator,
        config,
        required_log - 1,
        1 << 20,
    );
    defer session.deinit(allocator);

    const prepared = try subject.prepareInput(allocator, statement);
    try std.testing.expectError(
        error.InvalidCircleLog,
        subject.provePreparedWithSessionAndEngine(
            subject.CpuProverEngine,
            &session,
            allocator,
            config,
            prepared,
            null,
        ),
    );
}
