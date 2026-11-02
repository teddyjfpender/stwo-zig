//! Sixteen adjacent domain rows stay in base-field lanes until a secure
//! relation or random-coefficient accumulation requires extension arithmetic.
//! No transpose, wide copy, per-row allocation or scalar QM31 promotion.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const frame = @import("frame.zig");
const C = @import("component.zig");
const Evaluation = @import("coset_evaluation.zig").Evaluation;
const Column = @import("stwo_prover_engine").air.accumulation.ColumnAccumulator;
const M = core.fields.m31.M31;
const F = E.PackedBase;
pub const LANES = E.LANES;
pub const PreviousSource = struct { destination: usize, values: []const M };
pub const Scratch = struct {
    logical: E.MainFor(F),
    main: [E.L.MAIN + frame.WIDTH]F,
    prior_main: [E.L.MAIN + frame.WIDTH]F,
    current: [C.MAX_INTERACTION]F,
    prior: [C.MAX_INTERACTION]F,
    pub fn initialize(self: *Scratch) void {
        @memset(&self.logical, F.zero());
        @memset(&self.prior_main, F.zero());
        @memset(&self.prior, F.zero());
    }
};
pub fn evaluate(component: *const C.Component, evaluation: *const Evaluation, scratch: *Scratch, part: usize, start: usize, end: usize, previous_main: []const PreviousSource, previous_interaction: []const PreviousSource, output: *Column, inverse: M) void {
    const main = scratch.main[0..component.mainCount()];
    const prior_main = scratch.prior_main[0..component.mainCount()];
    const current = scratch.current[0..component.interactionCount()];
    const prior = scratch.prior[0..component.interactionCount()];
    const sources = evaluation.current_values;
    const inter_start = frame.FIXED + main.len;
    var row = start;
    while (row < end) : (row += LANES) {
        const count = @min(LANES, end - row);
        var fixed: [frame.FIXED]F = undefined;
        for (&fixed, sources[0..frame.FIXED]) |*value, source| value.* = load(source, row, count);
        for (main, sources[frame.FIXED..inter_start]) |*value, source| value.* = load(source, row, count);
        for (current, sources[inter_start..]) |*value, source| value.* = load(source, row, count);
        var indices: [LANES]usize = undefined;
        for (indices[0..count], 0..) |*value, i| value.* = evaluation.previousRow(part, row + i);
        for (previous_main) |source| prior_main[source.destination] = gather(source.values, indices[0..count]);
        for (previous_interaction) |source| prior[source.destination] = gather(source.values, indices[0..count]);
        const prepared = component.inflation.applyPreparedGeneric(F, main[0..component.plan.main_count], &scratch.logical);
        var accumulator = E.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.PackedSink{ .weighted_accumulator = &accumulator };
        component.emitInflatedGeneric(F, fixed, main, prior_main, current, prior, prepared, &sink);
        std.debug.assert(sink.count == component.constraint_count);
        const value = accumulator.accumulation.mulBase(F.splat(inverse));
        accumulate(output, evaluation.globalRow(part, row), count, value);
    }
}
fn load(source: []const M, start: usize, count: usize) F {
    if (count == LANES) return F.load(source.ptr + start);
    var values: [LANES]M = @splat(M.zero());
    @memcpy(values[0..count], source[start..][0..count]);
    return F.fromLanes(values);
}
fn gather(source: []const M, indices: []const usize) F {
    var values: [LANES]M = @splat(M.zero());
    for (indices, 0..) |index, i| values[i] = source[index];
    return F.fromLanes(values);
}
fn accumulate(output: *Column, start: usize, count: usize, value: E.PackedSecure) void {
    const coordinates = value.coordinates();
    if (output.next_fresh_index) |next| {
        if (next == start) {
            for (output.col.columns, coordinates) |column, coordinate| {
                if (count == LANES) {
                    coordinate.store(column.ptr + start);
                } else for (0..count) |i| {
                    column[start + i] = coordinate.lane(i);
                }
            }
            output.next_fresh_index = start + count;
            return;
        }
        output.next_fresh_index = null;
    }
    for (output.col.columns, coordinates) |column, coordinate| {
        if (count == LANES) {
            F.load(column.ptr + start).add(coordinate).store(column.ptr + start);
        } else for (0..count) |i| {
            column[start + i] = column[start + i].add(coordinate.lane(i));
        }
    }
}
