//! Prepared-input and reusable-session tests for the State Machine prover.

const std = @import("std");
const fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("../../interop/proof_wire/mod.zig");
const subject = @import("../state_machine.zig");

const M31 = m31.M31;

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn testRequest() subject.Request {
    return .{
        .log_n_rows = 5,
        .initial_state = .{ M31.fromCanonical(14), M31.fromCanonical(6) },
    };
}

test "State Machine session: compatibility, prepared, and sequential proofs match exactly" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const request = testRequest();
    const required_log = try subject.requiredTwiddleCircleLog(request, config);

    var session = try subject.CpuProverEngine.initSession(
        allocator,
        config,
        required_log,
        1 << 20,
    );
    defer session.deinit(allocator);

    var compatibility = try subject.prove(
        allocator,
        config,
        request.log_n_rows,
        request.initial_state,
    );
    defer compatibility.proof.deinit(allocator);

    const prepared_engine_input = try subject.prepareInput(allocator, request);
    var prepared_engine = try subject.provePreparedWithEngine(
        subject.CpuProverEngine,
        allocator,
        config,
        prepared_engine_input,
        null,
    );
    defer prepared_engine.proof.deinit(allocator);

    const first_input = try subject.prepareInput(allocator, request);
    var first = try subject.provePreparedWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        first_input,
        null,
    );
    defer first.proof.deinit(allocator);

    const second_input = try subject.prepareInput(allocator, request);
    var second = try subject.provePreparedWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        second_input,
        null,
    );
    defer second.proof.deinit(allocator);

    const extended_input = try subject.prepareInput(allocator, request);
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
    try std.testing.expectEqual(@as(usize, 8880), expected.len);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected, &digest, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe4, 0x42, 0x95, 0xb0, 0x8b, 0xe6, 0x0f, 0xcb,
        0x27, 0xdd, 0x33, 0x1d, 0x84, 0xf2, 0x1d, 0xe8,
        0x0d, 0x9a, 0x83, 0x36, 0x77, 0xe0, 0xae, 0x23,
        0x51, 0xaa, 0x5a, 0x53, 0x9f, 0x16, 0x9f, 0x56,
    }, &digest);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "State Machine session: undersized geometry consumes the prepared trace" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const request = testRequest();
    const required_log = try subject.requiredTwiddleCircleLog(request, config);

    var session = try subject.CpuProverEngine.initSession(
        allocator,
        config,
        required_log - 1,
        1 << 20,
    );
    defer session.deinit(allocator);

    const prepared = try subject.prepareInput(allocator, request);
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

test "State Machine input: invalid prepared geometry still consumes owned columns" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var prepared = try subject.prepareInput(allocator, testRequest());
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
    var prepared = try subject.prepareInput(allocator, testRequest());
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 5), prepared.trace.max_column_log);
    try std.testing.expectEqual(@as(u64, 4), prepared.trace.committed_columns);
    try std.testing.expectEqual(@as(u64, 96), prepared.trace.committed_cells);
}

test "State Machine input: preparation cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndDeinit,
        .{},
    );
}
