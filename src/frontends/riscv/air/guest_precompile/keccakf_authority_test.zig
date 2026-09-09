//! Independent semantic and mutation tests for the Keccak-f typed-AIR authority.

const std = @import("std");
const authority = @import("keccakf_authority.zig");

fn patternedState(seed: u64) authority.State {
    var state: authority.State = undefined;
    for (&state, 0..) |*lane, index| {
        lane.* = seed ^ (@as(u64, index) *% 0x9e3779b97f4a7c15) ^
            std.math.rotl(u64, seed, @as(u6, @intCast(index % 64)));
    }
    return state;
}

fn standardPermutation(input: authority.State) authority.State {
    const KeccakF = std.crypto.core.keccak.KeccakF(1600);
    var bytes: [KeccakF.block_bytes]u8 = undefined;
    for (input, 0..) |lane, index|
        std.mem.writeInt(u64, bytes[index * 8 ..][0..8], lane, .little);
    var state = KeccakF.init(bytes);
    state.permute();
    var output: authority.State = undefined;
    for (&output, 0..) |*lane, index|
        lane.* = std.mem.readInt(u64, state.asBytes()[index * 8 ..][0..8], .little);
    return output;
}

test "keccakf authority: wide and compact paired geometries remain internally exact" {
    try std.testing.expectEqual(@as(usize, 1600), authority.width_bits);
    try std.testing.expectEqual(@as(usize, 24), authority.round_count);
    try std.testing.expectEqual(@as(usize, 29), authority.geometry.rows_per_slot);
    try std.testing.expectEqual(@as(usize, 2), authority.geometry.operations_per_slot);
    try std.testing.expectEqual(@as(usize, 2_097_152), authority.geometry.chi_table_rows);
    try std.testing.expectEqual(@as(usize, 46_656), authority.geometry.xor5_table_rows);
    try std.testing.expectEqual(@as(usize, 320), authority.geometry.chi_lookups_per_round);
    try std.testing.expectEqual(@as(usize, 107), authority.geometry.xor5_lookups_per_round);
    try std.testing.expectEqual(@as(usize, 7_680), authority.geometry.chi_lookups_per_slot);
    try std.testing.expectEqual(@as(usize, 2_568), authority.geometry.xor5_lookups_per_slot);
    try std.testing.expectEqual(@as(usize, 8_192), authority.geometry.compact.chi_table_rows);
    try std.testing.expectEqual(@as(usize, 1_024), authority.geometry.compact.xor5_table_rows);
    try std.testing.expectEqual(@as(usize, 1_600), authority.geometry.compact.chi_lookups_per_round);
    try std.testing.expectEqual(@as(usize, 320), authority.geometry.compact.xor5_lookups_per_round);
    try std.testing.expectEqual(@as(usize, 111_848), authority.geometry.maximum_calls);
    try std.testing.expect(
        authority.geometry.maximum_slots * authority.geometry.compact.chi_lookups_per_slot <
            0x7fff_ffff,
    );
}

test "keccakf authority: zero and patterned states match independent standard implementation" {
    const corpus = [_]authority.State{
        @splat(0),
        @splat(std.math.maxInt(u64)),
        patternedState(0x0123456789abcdef),
        patternedState(0xfedcba9876543210),
    };
    for (corpus) |input| {
        const trace = authority.buildTrace(input);
        try authority.validateTrace(input, &trace);
        try std.testing.expectEqual(standardPermutation(input), trace[authority.round_count]);
    }
}

test "keccakf authority: paired sliced tables reconstruct every round and odd padding" {
    const trace_a = authority.buildTrace(patternedState(0x0123456789abcdef));
    const trace_b = authority.buildTrace(patternedState(0xa5a5a5a55a5a5a5a));
    try authority.validatePairedTraces(&trace_a, &trace_b);

    const zero_b = authority.buildTrace(@splat(0));
    try authority.validatePairedTraces(&trace_a, &zero_b);
}

test "keccakf authority: trace and table mutations reject fail closed" {
    const trace_a = authority.buildTrace(patternedState(7));
    const trace_b = authority.buildTrace(patternedState(11));

    var bad_input = trace_a;
    bad_input[0][3] ^= 1;
    try std.testing.expectError(
        error.TraceRoundMismatch,
        authority.validatePairedTraces(&bad_input, &trace_b),
    );

    var bad_round = trace_a;
    bad_round[13][17] ^= @as(u64, 1) << 41;
    try std.testing.expectError(
        error.TraceRoundMismatch,
        authority.validatePairedTraces(&bad_round, &trace_b),
    );

    try std.testing.expectError(
        error.InvalidChiDigit,
        authority.chiTableRow(.{ 0, 1, 2, 3, 4 }, @splat(0), false),
    );
    try std.testing.expectError(
        error.InvalidChiRow,
        authority.chiTableEntry(authority.geometry.chi_table_rows),
    );
    try std.testing.expectError(
        error.InvalidXor5Digit,
        authority.xor5TableRow(.{ .{ 0, 0 }, .{ 5, 5 }, .{ 6, 0 } }),
    );
    try std.testing.expectError(
        error.InvalidXor5Row,
        authority.xor5TableEntry(authority.geometry.xor5_table_rows),
    );
}
