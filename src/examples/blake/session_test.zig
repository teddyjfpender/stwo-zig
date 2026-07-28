//! Session and admission tests for the exact Blake prover.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const subject = @import("../blake.zig");

fn testConfig() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn testRequest() subject.Request {
    return .{ .log_n_rows = 4, .n_rounds = 10 };
}

test "Blake session: exact minimum geometry admits one reusable tower" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    const required_log = try subject.requiredTwiddleCircleLog(
        testRequest(),
        config,
    );
    try std.testing.expectEqual(@as(u32, 17), required_log);

    var session = try subject.CpuProverEngine.initSession(
        allocator,
        config,
        required_log,
        1 << 20,
    );
    defer session.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 1),
        session.constructionTelemetry().tower_build_count,
    );
}

test "Blake session: invalid and oversized requests fail before allocation" {
    try std.testing.expectError(
        error.InvalidNRounds,
        subject.exact_input.validate(.{ .log_n_rows = 4, .n_rounds = 9 }),
    );
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        subject.exact_input.validate(.{ .log_n_rows = 20 }),
    );
}

test "Blake session: opt-in exact proof and reused session are byte-identical" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(
        allocator,
        "STWO_RUN_SLOW_BLAKE",
    ) catch return error.SkipZigTest;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;

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

    var direct = try subject.prove(allocator, config, request);
    defer direct.proof.deinit(allocator);
    const prepared = try subject.prepareInput(allocator, request);
    var reused = try subject.provePreparedWithSessionAndEngine(
        subject.CpuProverEngine,
        &session,
        allocator,
        config,
        prepared,
        null,
    );
    defer reused.proof.deinit(allocator);

    try std.testing.expect(std.meta.eql(direct.statement, reused.statement));
    const direct_bytes = try proof_wire.encodeProofBytes(allocator, direct.proof);
    defer allocator.free(direct_bytes);
    const reused_bytes = try proof_wire.encodeProofBytes(allocator, reused.proof);
    defer allocator.free(reused_bytes);
    try std.testing.expectEqualSlices(u8, direct_bytes, reused_bytes);

    const verification_proof = try proof_wire.decodeProofBytes(
        allocator,
        direct_bytes,
    );
    try subject.verify(
        allocator,
        config,
        direct.statement,
        verification_proof,
    );
}
