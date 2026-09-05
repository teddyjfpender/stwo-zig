//! Mutation and committed-order tests for shared Keccak lookup counters.

const std = @import("std");
const authority = @import("keccakf_authority.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const infra = @import("../../infra_trace.zig");
const witness = @import("keccakf_witness.zig");

fn state(seed: u64) authority.State {
    var result: authority.State = undefined;
    for (&result, 0..) |*lane, index|
        lane.* = seed +% @as(u64, @intCast(index * 0x10203));
    return result;
}

test "keccakf counters: paired and odd slots share one exact authority" {
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    const paired = try witness.buildSlot(state(1), state(2));
    const odd = try witness.buildSlot(state(3), null);
    try counters.recordSlot(&paired);
    try counters.recordSlot(&odd);
    try counters.validateTotals();
    try std.testing.expectEqual(@as(usize, 2), counters.slots);

    const first_row = try witness.compactChiLookupRow(&paired, 0, 0, 0, 0);
    try std.testing.expect(counters.chi[first_row].toU32() != 0);
    const committed = try counters.committedColumn(std.testing.allocator, .chi);
    defer std.testing.allocator.free(committed);
    const reversal = try infra.BitReversalTable.init(std.testing.allocator, 13);
    defer reversal.deinit(std.testing.allocator);
    try std.testing.expect(committed[reversal.map(first_row)].eql(
        counters.chi[first_row],
    ));
}

test "keccakf counters: empty and malformed slots fail before publication" {
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    const empty = try witness.buildSlot(null, null);
    try std.testing.expectError(error.EmptySlot, counters.recordSlot(&empty));
    try std.testing.expectEqual(@as(usize, 0), counters.slots);

    var malformed = try witness.buildSlot(state(7), null);
    malformed.rows[8].state[9] ^= 1;
    try std.testing.expectError(
        error.InvalidChiTransition,
        counters.recordSlot(&malformed),
    );
    try std.testing.expectEqual(@as(usize, 0), counters.slots);
}
