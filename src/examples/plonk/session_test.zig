//! Prepared-input and reusable-session tests for the Plonk prover.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const subject = @import("../plonk.zig");

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn testStatement() subject.Statement {
    return .{ .log_n_rows = 5 };
}

test "Plonk session: compatibility, prepared, and sequential proofs match exactly" {
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

    const extended_engine_input = try subject.prepareInput(allocator, statement);
    var extended_engine = try subject.provePreparedExWithEngine(
        subject.CpuProverEngine,
        allocator,
        config,
        extended_engine_input,
        false,
        null,
    );
    defer extended_engine.proof.deinit(allocator);

    const extended_session_input = try subject.prepareInput(allocator, statement);
    var extended_session = try subject.provePreparedExWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        extended_session_input,
        true,
        null,
    );
    defer extended_session.proof.deinit(allocator);

    const expected = try proof_wire.encodeProofBytes(allocator, compatibility.proof);
    defer allocator.free(expected);
    const prepared_bytes = try proof_wire.encodeProofBytes(allocator, prepared_engine.proof);
    defer allocator.free(prepared_bytes);
    const first_bytes = try proof_wire.encodeProofBytes(allocator, first.proof);
    defer allocator.free(first_bytes);
    const second_bytes = try proof_wire.encodeProofBytes(allocator, second.proof);
    defer allocator.free(second_bytes);
    const extended_engine_bytes = try proof_wire.encodeProofBytes(
        allocator,
        extended_engine.proof.proof,
    );
    defer allocator.free(extended_engine_bytes);
    const extended_session_bytes = try proof_wire.encodeProofBytes(
        allocator,
        extended_session.proof.proof,
    );
    defer allocator.free(extended_session_bytes);

    try std.testing.expectEqualSlices(u8, expected, prepared_bytes);
    try std.testing.expectEqualSlices(u8, expected, first_bytes);
    try std.testing.expectEqualSlices(u8, expected, second_bytes);
    try std.testing.expectEqualSlices(u8, expected, extended_engine_bytes);
    try std.testing.expectEqualSlices(u8, expected, extended_session_bytes);
    try std.testing.expectEqual(@as(usize, 9399), expected.len);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected, &digest, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x36, 0x3e, 0xf5, 0x44, 0xe6, 0xff, 0xd6, 0xe1,
        0x50, 0x75, 0x70, 0x49, 0x7a, 0xd3, 0xf3, 0x71,
        0x7c, 0xf7, 0xc7, 0x81, 0x80, 0x76, 0xc2, 0xd7,
        0x49, 0xf1, 0xfa, 0xd5, 0x80, 0x8b, 0x56, 0x9c,
    }, &digest);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "Plonk session: undersized geometry fails before ownership transfer" {
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

test "Plonk input: invalid prepared geometry still consumes owned columns" {
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
    try std.testing.expectEqual(@as(u64, 8), prepared.trace.committed_columns);
    try std.testing.expectEqual(@as(u64, 256), prepared.trace.committed_cells);
}

test "Plonk input: preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndDeinit,
        .{},
    );
}
