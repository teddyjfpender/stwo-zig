//! Prepared-input and reusable-session tests for the XOR prover.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const subject = @import("../xor.zig");

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn testStatement() subject.Statement {
    return .{ .log_size = 5, .log_step = 2, .offset = 3 };
}

test "XOR session: compatibility, prepared, and sequential proofs match exactly" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const statement = testStatement();
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

    const prepared_engine_input = try subject.prepareInput(allocator, statement);
    var prepared_engine = try subject.provePreparedWithEngine(
        subject.CpuProverEngine,
        allocator,
        config,
        prepared_engine_input,
        null,
    );
    defer prepared_engine.proof.deinit(allocator);

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
    const prepared_bytes = try proof_wire.encodeProofBytes(allocator, prepared_engine.proof);
    defer allocator.free(prepared_bytes);
    const first_bytes = try proof_wire.encodeProofBytes(allocator, first.proof);
    defer allocator.free(first_bytes);
    const second_bytes = try proof_wire.encodeProofBytes(allocator, second.proof);
    defer allocator.free(second_bytes);

    try std.testing.expectEqualSlices(u8, expected, prepared_bytes);
    try std.testing.expectEqualSlices(u8, expected, first_bytes);
    try std.testing.expectEqualSlices(u8, expected, second_bytes);
    try std.testing.expectEqual(@as(usize, 11_132), expected.len);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected, &digest, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x71, 0xe1, 0x97, 0xa4, 0x58, 0xf1, 0x29, 0x84,
        0x2e, 0xb3, 0x20, 0x6b, 0xc1, 0x39, 0x04, 0xbe,
        0x0a, 0x10, 0xe4, 0xf3, 0xc0, 0x16, 0xf9, 0x50,
        0x7e, 0x7f, 0x69, 0x59, 0x92, 0xd5, 0xfd, 0x6e,
    }, &digest);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "XOR session: undersized geometry fails before ownership transfer" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const statement = testStatement();
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

test "XOR input: invalid prepared geometry still consumes owned columns" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var prepared = try subject.prepareInput(allocator, testStatement());
    prepared.trace.committed_cells += 1;

    try std.testing.expectError(
        error.InvalidPreparedGeometry,
        subject.provePreparedWithEngine(
            subject.CpuProverEngine,
            allocator,
            config,
            prepared,
            null,
        ),
    );
}

fn prepareAndDeinit(allocator: std.mem.Allocator) !void {
    var prepared = try subject.prepareInput(allocator, testStatement());
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 5), prepared.trace.max_column_log);
    try std.testing.expectEqual(@as(u64, 11), prepared.trace.committed_columns);
    try std.testing.expectEqual(@as(u64, 352), prepared.trace.committed_cells);
}

test "XOR input: preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndDeinit,
        .{},
    );
}
