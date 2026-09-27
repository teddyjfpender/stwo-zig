//! Explicit local-zero Keccak caller arithmetic recipe. Legacy caller helpers
//! remain unchanged; the containing profile must independently select this
//! physical width and identity before these equations reach a proof.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const original = @import("keccakf_caller.zig");
const envelope = @import("x0_caller_envelope_v1.zig");
const logup = @import("../logup.zig");
pub const Layout = struct {
    pub const hints: usize = original.Layout.main_columns;
    pub const main_columns: usize = original.Layout.main_columns + 2;
};
pub const direct_constraint_count = original.direct_constraint_count + envelope.directCount(.keccak);
pub const event_count = original.event_count;
pub const batch_count = original.batch_count;
pub const maximum_constraint_degree: u32 = 3;
pub const abiId = struct {
    pub fn call() [32]u8 {
        return envelope.abiId(.keccak);
    }
}.call;

pub fn fill(record: @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record) ![Layout.main_columns]M {
    var row: [Layout.main_columns]M = @splat(M.zero());
    const source = original.fill(record);
    @memcpy(row[0..source.len], &source);
    try envelope.fillHintsAndNormalize(.keccak, &row, row[original.Layout.enabler]);
    return row;
}
pub fn evaluateDirect(comptime S: type, caller: []const S, active: S, sink: anytype) !void {
    if (caller.len != Layout.main_columns) return error.InvalidX0CallerGeometry;
    try original.evaluateDirect(S, caller[0..original.Layout.main_columns], active, sink);
    try envelope.evaluateDirect(S, .keccak, caller, caller[original.Layout.enabler], sink);
}
pub fn coreEvents(comptime S: type, caller: []const S, input_state: []const S, output_state: []const S, relations: anytype) ![event_count]logup.RowPairFor(envelope.InteractionScalar(S)) {
    if (caller.len != Layout.main_columns) return error.InvalidX0CallerGeometry;
    var events = original.coreEvents(S, caller[0..original.Layout.main_columns], input_state, output_state, relations);
    const keep = envelope.lift(S, try envelope.weight(S, .keccak, caller, caller[original.Layout.enabler], 0));
    for (events[3..6]) |*event| event.n1 = event.n1.mul(keep);
    return events;
}
pub fn rowPairs(comptime S: type, caller: []const S, input_state: []const S, output_state: []const S, io_a: []const S, io_b: []const S, selector_a: S, selector_b: S, in_use_b: S, relations: anytype) ![batch_count]logup.RowPairFor(envelope.InteractionScalar(S)) {
    if (caller.len != Layout.main_columns) return error.InvalidX0CallerGeometry;
    var pairs = try original.rowPairs(S, caller[0..original.Layout.main_columns], input_state, output_state, io_a, io_b, selector_a, selector_b, in_use_b, relations);
    const keep = envelope.lift(S, try envelope.weight(S, .keccak, caller, caller[original.Layout.enabler], 0));
    pairs[1].n2 = pairs[1].n2.mul(keep);
    pairs[2].n1 = pairs[2].n1.mul(keep);
    pairs[2].n2 = pairs[2].n2.mul(keep);
    return pairs;
}
