//! Prepared-input and reusable-session tests for the Poseidon prover.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const subject = @import("../poseidon.zig");

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn testStatement() subject.Statement {
    return .{ .log_n_instances = 8 };
}

test "Poseidon session: compatibility, prepared, and sequential proofs match exactly" {
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

    const extended_input = try subject.prepareInput(allocator, statement);
    var extended = try subject.provePreparedExWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        extended_input,
        false,
        null,
    );
    defer extended.proof.deinit(allocator);

    const expected = try proof_wire.encodeProofBytes(allocator, compatibility.proof);
    defer allocator.free(expected);
    const prepared_bytes = try proof_wire.encodeProofBytes(allocator, prepared_engine.proof);
    defer allocator.free(prepared_bytes);
    const first_bytes = try proof_wire.encodeProofBytes(allocator, first.proof);
    defer allocator.free(first_bytes);
    const second_bytes = try proof_wire.encodeProofBytes(allocator, second.proof);
    defer allocator.free(second_bytes);
    const extended_bytes = try proof_wire.encodeProofBytes(allocator, extended.proof.proof);
    defer allocator.free(extended_bytes);

    try std.testing.expectEqualSlices(u8, expected, prepared_bytes);
    try std.testing.expectEqualSlices(u8, expected, first_bytes);
    try std.testing.expectEqualSlices(u8, expected, second_bytes);
    try std.testing.expectEqualSlices(u8, expected, extended_bytes);
    try std.testing.expectEqual(@as(usize, 112_247), expected.len);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected, &digest, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x21, 0xa2, 0x28, 0x31, 0x01, 0x0d, 0xa1, 0x4e,
        0x3a, 0x8d, 0x3b, 0x09, 0x71, 0x84, 0xe2, 0xde,
        0xf2, 0x75, 0x1d, 0x4f, 0x66, 0x57, 0x56, 0xcc,
        0x2a, 0x3d, 0x25, 0xf7, 0x28, 0x7f, 0xf1, 0x15,
    }, &digest);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "Poseidon session: undersized geometry consumes the prepared trace" {
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

test "Poseidon input: invalid prepared geometry still consumes owned columns" {
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

test "Poseidon input: request and column geometry must match exactly" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var prepared = try subject.prepareInput(allocator, testStatement());
    prepared.request.log_n_instances += 1;

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
    try std.testing.expectEqual(@as(usize, 0), prepared.trace.preprocessed.columns.?.len);
    try std.testing.expectEqual(@as(usize, subject.N_COLUMNS), prepared.trace.main.columns.?.len);
    try std.testing.expectEqual(@as(u32, 5), prepared.trace.max_column_log);
    try std.testing.expectEqual(@as(u64, 1_264), prepared.trace.committed_columns);
    try std.testing.expectEqual(@as(u64, 40_448), prepared.trace.committed_cells);
    for (prepared.trace.main.columns.?) |column| {
        try std.testing.expectEqual(@as(u32, 5), column.log_size);
        try std.testing.expectEqual(@as(usize, 32), column.values.len);
    }
}

test "Poseidon input: preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndDeinit,
        .{},
    );
}
