//! Challenge-order, tuple, and LogUp cancellation tests for Keccak relations.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_challenges = @import("../relation_challenges.zig");
const authority = @import("keccakf_authority.zig");
const relations = @import("keccakf_relations.zig");

fn state(seed: u64) authority.State {
    var result: authority.State = undefined;
    for (&result, 0..) |*lane, index|
        lane.* = seed ^ (@as(u64, index) *% 0x9e3779b97f4a7c15);
    return result;
}

test "keccakf relations: schema IDs arities and types are profile-local" {
    try std.testing.expectEqual(@as(u16, 12), relations.io_schema_numeric_id);
    try std.testing.expectEqual(@as(u16, 13), relations.chi_schema_numeric_id);
    try std.testing.expectEqual(@as(u16, 14), relations.xor5_schema_numeric_id);
    try std.testing.expectEqual(@as(usize, 109), relations.io_schema.fields.len);
    try std.testing.expectEqual(@as(usize, 6), relations.chi_schema.fields.len);
    try std.testing.expect(relations.io_schema.request_is_unit);
    try std.testing.expect(relations.chi_schema.supply_is_weighted);
    try std.testing.expect(relations.xor5_schema.supply_is_weighted);
    for (relations.io_schema.fields) |field| switch (field) {
        .exact => |field_type| try field_type.validate(),
        .field_scalar => return error.TestUnexpectedResult,
    };
}

test "keccakf relations: extension challenges append after exact base schedule" {
    var actual_channel = Blake2sChannel{};
    var oracle_channel = Blake2sChannel{};
    const actual = try relations.Relations.draw(std.testing.allocator, &actual_channel);
    _ = try base_challenges.Relations.draw(std.testing.allocator, &oracle_channel);
    const extension = try oracle_channel.drawSecureFelts(std.testing.allocator, 6);
    defer std.testing.allocator.free(extension);
    try std.testing.expect(actual.io.z.eql(extension[0]));
    try std.testing.expect(actual.io.alpha.eql(extension[1]));
    try std.testing.expect(actual.chi.z.eql(extension[2]));
    try std.testing.expect(actual.xor5.alpha.eql(extension[5]));
    try std.testing.expect(actual_channel.drawSecureFelt().eql(oracle_channel.drawSecureFelt()));
}

test "keccakf relations: packed states bind call order and every input output bit" {
    const input = state(17);
    var output = input;
    authority.permute(&output);
    const tuple = try relations.ioTuple(9, input, output);
    try std.testing.expectEqual(@as(u32, 9), tuple[0].toU32());
    const reconstructed_lane0 = @as(u64, tuple[1].toU32()) |
        (@as(u64, tuple[2].toU32()) << 30) |
        (@as(u64, tuple[3].toU32() & 0xf) << 60);
    try std.testing.expectEqual(input[0], reconstructed_lane0);
    try std.testing.expect(tuple[relations.state_chunk_count].toU32() < 1 << 10);
    try std.testing.expect(tuple[relations.io_arity - 1].toU32() < 1 << 10);
    var changed_input = input;
    changed_input[24] ^= @as(u64, 1) << 63;
    try std.testing.expect(!std.meta.eql(
        tuple,
        try relations.ioTuple(9, changed_input, output),
    ));
    var changed_output = output;
    changed_output[0] ^= 1;
    try std.testing.expect(!std.meta.eql(
        tuple,
        try relations.ioTuple(9, input, changed_output),
    ));
    try std.testing.expectError(
        error.CallIndexOutOfRange,
        relations.ioTuple(authority.candidate.maximum_calls, input, output),
    );
}

test "keccakf relations: request and emit cancel only on the same typed bus" {
    const challenge = relations.Relations.dummy();
    const input = state(5);
    var output = input;
    authority.permute(&output);
    const tuple = try relations.ioTuple(3, input, output);
    const request = relations.IoEvent.unitRequest(tuple);
    const emit = relations.IoEvent.unitEmit(tuple);
    const sum = (try request.term(challenge.io)).add(try emit.term(challenge.io));
    try std.testing.expect(sum.isZero());

    var changed = tuple;
    changed[1] = changed[1].add(M31.one());
    const mismatch = (try request.term(challenge.io)).add(
        try relations.IoEvent.unitEmit(changed).term(challenge.io),
    );
    try std.testing.expect(!mismatch.isZero());

    var invalid_request = request;
    invalid_request.coefficient = M31.fromCanonical(2);
    try std.testing.expectError(error.InvalidRequestMultiplicity, invalid_request.validate());
    var invalid_padding = relations.IoEvent.padding();
    invalid_padding.tuple[4] = M31.one();
    try std.testing.expectError(error.InvalidPadding, invalid_padding.validate());
}

test "keccakf relations: table tuples are injective at sampled boundaries" {
    const chi_rows = [_]u32{ 0, 1, 15, 16, 4095, 4096, 8191 };
    for (chi_rows) |row| {
        const tuple = try relations.chiTuple(row);
        for (chi_rows) |other| {
            if (row == other) continue;
            try std.testing.expect(!std.meta.eql(tuple, try relations.chiTuple(other)));
        }
    }
    const xor_rows = [_]u32{ 0, 1, 3, 4, 255, 256, 1023 };
    for (xor_rows) |row| {
        const tuple = try relations.xor5Tuple(row);
        for (xor_rows) |other| {
            if (row == other) continue;
            try std.testing.expect(!std.meta.eql(tuple, try relations.xor5Tuple(other)));
        }
    }

    const challenge = relations.Relations.dummy();
    const chi_tuple = try relations.chiTuple(17);
    const chi_balance = (try relations.ChiEvent.unitRequest(chi_tuple).term(challenge.chi)).add(
        try relations.ChiEvent.weightedEmit(chi_tuple, M31.one()).term(challenge.chi),
    );
    try std.testing.expect(chi_balance.eql(QM31.zero()));
}
