//! Pure batch accounting after original STARK authentication. This returns no
//! Verified object and cannot replace admission, physical claims or a proof.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Caller = @import("block_v7_caller_joint_source_v1.zig");
const Accumulator = @import("block_v7_execution_claim_closure_v1.zig").Accumulator;
pub const Open = struct {
    /// Original selected program/state/register physical sums, one per owner.
    controls: []const [3]Q,
    arithmetic_sum: Q,
    table_requests: [6]Q,
    universal_opposite: Q,
    transition_sum: Q,
    byte_requests: Q,
    event_count: u64,
};
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
}
pub fn requireClosed(pin: Source.Pin, source: Open) !void {
    if (pin.windows.len == 0 or source.controls.len != pin.windows.len) return error.InvalidKeccakBatchControlCount;
    inline for (.{ source.arithmetic_sum, source.universal_opposite, source.transition_sum, source.byte_requests }) |value| try canonical(value);
    var residual = source.arithmetic_sum.add(source.universal_opposite);
    var calls: u64 = 0;
    for (pin.windows, source.controls) |window, controls| {
        calls = try std.math.add(u64, calls, window.calls);
        for (controls) |value| {
            try canonical(value);
            residual = residual.sub(value);
        }
    }
    for (source.table_requests) |value| {
        try canonical(value);
        residual = residual.sub(value);
    }
    const words = @import("block_execution_external_access_bridge_v2.zig").KECCAK_ACCESS_COUNT - 1;
    if (calls != pin.geometry.call_count or source.event_count != try std.math.mul(u64, calls, words)) return error.UntrustedKeccakBatchCensus;
    if (!residual.isZero()) return error.UnclosedKeccakBatchRelations;
}
/// Split only the accounting of an already verified batch: controls remain
/// separate by native window; global tables/RAM totals are added exactly once.
/// These temporary Exports are not separately verified caller receipts.
pub fn addToExecution(acc: *Accumulator, pin: Source.Pin, source: Open) !void {
    try requireClosed(pin, source);
    if (source.controls.len > acc.expected_callers -| acc.callers) return error.InvalidV7CallerRoster;
    for (pin.windows, 0..) |window, i| {
        if (window.execution_index >= acc.states.len or acc.caller_seen[window.execution_index] or (i != 0 and window.execution_index <= pin.windows[i - 1].execution_index)) return error.InvalidV7CallerRoster;
    }
    for (pin.windows, source.controls, 0..) |window, controls, i| {
        var out = std.mem.zeroes(Caller.Exports);
        out.program_sum = controls[0];
        out.state_sum = controls[1];
        out.register_sum = controls[2];
        out.fetch_count = window.calls;
        out.arithmetic_sum = controls[0].add(controls[1]).add(controls[2]);
        if (i == 0) {
            out.table_requests = source.table_requests;
            out.universal_opposite = source.universal_opposite;
            out.transition_sum = source.transition_sum;
            out.byte_requests = source.byte_requests;
            out.event_count = source.event_count;
            out.arithmetic_sum = out.arithmetic_sum.sub(source.universal_opposite);
            for (source.table_requests) |value| out.arithmetic_sum = out.arithmetic_sum.add(value);
        }
        try acc.addCaller(window.execution_index, out);
    }
}
