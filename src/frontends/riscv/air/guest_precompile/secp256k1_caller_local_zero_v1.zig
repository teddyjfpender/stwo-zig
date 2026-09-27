//! Explicit signer pointer recipe sharing the original arithmetic events.
//! This module grants no caller admission or global register closure.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const original = @import("secp256k1_recovery_caller.zig");
const envelope = @import("x0_caller_envelope_v1.zig");
const logup = @import("../logup.zig");
pub const Layout = struct {
    pub const hints: usize = original.Layout.main_columns;
    pub const main_columns: usize = original.Layout.main_columns + 2;
};
pub const constraint_count = original.constraint_count + envelope.directCount(.signer);
pub const event_count = original.event_count;
pub const batch_count = original.batch_count;
pub const maximum_constraint_degree: u8 = 3;
pub const range_pair_count = original.range_pair_count;
pub fn rangePairs(comptime S: type, main: *const [Layout.main_columns]S) [0][2]S {
    _ = main;
    return .{};
}
pub fn abiId() [32]u8 {
    return envelope.abiId(.signer);
}

pub fn rowFromRecord(record: @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record) ![Layout.main_columns]M {
    var row: [Layout.main_columns]M = @splat(M.zero());
    const source = original.rowFromRecord(record);
    @memcpy(row[0..source.len], &source);
    try envelope.fillHintsAndNormalize(.signer, &row, row[original.Layout.is_active]);
    return row;
}
pub fn evaluateDirect(comptime S: type, main: *const [Layout.main_columns]S, sink: anytype) !void {
    original.evaluateDirect(S, main[0..original.Layout.main_columns], sink);
    try envelope.evaluateDirect(S, .signer, main, main[original.Layout.is_active], sink);
}
pub fn rowEvents(comptime S: type, main: *const [Layout.main_columns]S, relations: anytype) ![event_count]logup.RowPairFor(envelope.InteractionScalar(S)) {
    var events = original.rowEvents(S, main[0..original.Layout.main_columns], relations);
    const keep = envelope.lift(S, try envelope.weight(S, .signer, main, main[original.Layout.is_active], 0));
    for (events[3..6]) |*event| event.n1 = event.n1.mul(keep);
    return events;
}
pub fn rowPairs(comptime S: type, main: *const [Layout.main_columns]S, relations: anytype) ![batch_count]logup.RowPairFor(envelope.InteractionScalar(S)) {
    const events = try rowEvents(S, main, relations);
    var pairs: [batch_count]logup.RowPairFor(envelope.InteractionScalar(S)) = undefined;
    for (&pairs, 0..) |*pair, i| pair.* = .{ .n1 = events[2 * i].n1, .d1 = events[2 * i].d1, .n2 = events[2 * i + 1].n1, .d2 = events[2 * i + 1].d1 };
    return pairs;
}
