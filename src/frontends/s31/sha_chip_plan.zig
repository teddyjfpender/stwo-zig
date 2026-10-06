//! Fixed three-call boundary for an 80-byte Bitcoin header SHA256d chip.
//!
//! This prepares the witness and checks the public/circuit-to-chip boundary.
//! It does not verify compression: the SHA AIR must prove each Call's
//! (state, block) -> output relation in the same bound proof.
const std = @import("std");
const provider = @import("s31_sha_provider");
const sha = provider.compression;
const modulus = @import("stwo_core").fields.m31.Modulus;

pub const Call = struct {
    state: sha.State,
    block: [64]u8,
    output: sha.State,
};

pub const Plan = struct {
    calls: [3]Call,
    digest: [32]u8,
};

pub fn prepare(header: [80]u8) Plan {
    var first_block: [64]u8 = undefined;
    @memcpy(&first_block, header[0..64]);
    const first_state = sha.compress(sha.initial_state, first_block);

    var second_block: [64]u8 = @splat(0);
    @memcpy(second_block[0..16], header[64..80]);
    second_block[16] = 0x80;
    std.mem.writeInt(u64, second_block[56..64], 640, .big);
    const first_digest_state = sha.compress(first_state, second_block);

    var third_block: [64]u8 = @splat(0);
    @memcpy(third_block[0..32], &sha.stateBytes(first_digest_state));
    third_block[32] = 0x80;
    std.mem.writeInt(u64, third_block[56..64], 256, .big);
    const final_state = sha.compress(sha.initial_state, third_block);
    const plan = Plan{
        .calls = .{
            .{ .state = sha.initial_state, .block = first_block, .output = first_state },
            .{ .state = first_state, .block = second_block, .output = first_digest_state },
            .{ .state = sha.initial_state, .block = third_block, .output = final_state },
        },
        .digest = sha.stateBytes(final_state),
    };
    return plan;
}

/// Checks every byte crossing between the three SHA calls and the enclosing
/// statement. A prover cannot choose padding, block order, chaining states,
/// or a digest independently of the chip outputs. This check is useful for
/// native testing; the eventual verifier must impose equivalent *proof-bound*
/// constraints and also verify each compression call's AIR.
pub fn validateBoundary(header: [80]u8, plan: Plan) !void {
    const calls = plan.calls;
    if (!std.meta.eql(calls[0].state, sha.initial_state) or
        !std.mem.eql(u8, &calls[0].block, header[0..64])) return error.InvalidShaBoundary;
    if (!std.meta.eql(calls[1].state, calls[0].output) or
        !std.mem.eql(u8, calls[1].block[0..16], header[64..80]) or
        calls[1].block[16] != 0x80 or
        !allZero(calls[1].block[17..56]) or
        std.mem.readInt(u64, calls[1].block[56..64], .big) != 640) return error.InvalidShaBoundary;
    const first_digest = sha.stateBytes(calls[1].output);
    if (!std.meta.eql(calls[2].state, sha.initial_state) or
        !std.mem.eql(u8, calls[2].block[0..32], &first_digest) or
        calls[2].block[32] != 0x80 or
        !allZero(calls[2].block[33..56]) or
        std.mem.readInt(u64, calls[2].block[56..64], .big) != 256 or
        !std.mem.eql(u8, &plan.digest, &sha.stateBytes(calls[2].output))) return error.InvalidShaBoundary;
}

/// Adapter to the existing packed SHA AIR row provider. Call IDs are explicit
/// and must be unique across a proof; a two-header batch can use 1..3, 4..6.
/// This prepares rows only. The S31 proof still needs an authenticated lookup
/// bridge and a verifier roster before these rows may replace circuit gates.
pub fn providerCalls(header: [80]u8, plan: Plan, first_call_id: u32) ![3]provider.Call {
    try validateBoundary(header, plan);
    if (first_call_id == 0 or first_call_id > modulus - 3) return error.InvalidShaCallId;
    var records: [3]provider.Call = undefined;
    for (plan.calls, &records, 0..) |call, *record, i| {
        if (!std.meta.eql(call.output, sha.compress(call.state, call.block)))
            return error.InvalidShaCompressionWitness;
        record.* = .{
            .execution_clock = first_call_id + @as(u32, @intCast(i)),
            .state = call.state,
            .block = call.block,
        };
    }
    return records;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

test "three calls match independent SHA256d and reject every bridge substitution" {
    var random = std.Random.DefaultPrng.init(0x5348_4132_3536);
    for (0..16) |_| {
        var header: [80]u8 = undefined;
        random.random().bytes(&header);
        const plan = prepare(header);
        try validateBoundary(header, plan);
        var first_digest: [32]u8 = undefined;
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&header, &first_digest, .{});
        std.crypto.hash.sha2.Sha256.hash(&first_digest, &expected, .{});
        try std.testing.expectEqualDeep(expected, plan.digest);

        var changed = plan;
        changed.calls[0].block[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[1].state[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[1].block[16] = 0;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[2].block[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.digest[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
    }
}

test "two header plans feed six exact packed SHA provider calls" {
    var parent: [80]u8 = undefined;
    var child: [80]u8 = undefined;
    for (&parent, &child, 0..) |*a, *b, i| {
        a.* = @truncate(i * 37 + 11);
        b.* = @truncate(i * 71 + 9);
    }
    const a = prepare(parent);
    const b = prepare(child);
    const a_records = try providerCalls(parent, a, 1);
    const b_records = try providerCalls(child, b, 4);
    const records = a_records ++ b_records;
    var rows = try provider.prepare(std.testing.allocator, &records);
    defer rows.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 10, 9, 9, 6 }, &rows.geometry.logs);
    try std.testing.expectEqual(@as(u32, 1), rows.sources[0][4].toU32());
    try std.testing.expectEqual(@as(u32, 6), rows.sources[5 * 88][4].toU32());
    try std.testing.expectError(error.InvalidShaCallId, providerCalls(parent, a, 0));
    var corrupt = a;
    corrupt.calls[0].output[0] ^= 1;
    corrupt.calls[1].state = corrupt.calls[0].output;
    try std.testing.expectError(error.InvalidShaCompressionWitness, providerCalls(parent, corrupt, 1));
}
