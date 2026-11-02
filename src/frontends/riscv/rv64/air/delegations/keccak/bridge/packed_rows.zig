//! Sixteen M31 input rows with secure challenged prefix equations.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../../evaluation.zig");
const C = @import("component.zig");
const E = @import("equations.zig");
const L = @import("layout.zig");
const Eval = @import("../../../full/coset_evaluation.zig").Evaluation;
const Column = @import("stwo_prover_engine").air.accumulation.ColumnAccumulator;
const M = core.fields.m31.M31;
const F = V.PackedBase;
const S = V.PackedSecure;
const LANES = V.LANES;
pub fn evaluate(component: *const C.Component, evaluation: *const Eval, part: usize, start: usize, end: usize, output: *Column, inverse: M, scratch: *C.ScratchFor(F)) void {
    const values = evaluation.current_values;
    const fm = L.FIXED + L.MAIN;
    var begin = start;
    while (begin < end) : (begin += LANES) {
        const count = @min(LANES, end - begin);
        var previous: [LANES]usize = undefined;
        for (0..count) |i| previous[i] = evaluation.previousRow(part, begin + i);
        for (&scratch.fixed, values[0..L.FIXED]) |*v, column| v.* = load(column, begin, count);
        for (&scratch.main, values[L.FIXED..fm]) |*v, column| v.* = load(column, begin, count);
        for (&scratch.previous, evaluation.previous_values[L.FIXED..][0..L.PREVIOUS_MAIN]) |*v, column| v.* = gather(column, previous[0..count]);
        for (&scratch.previous_header, evaluation.previous_values[L.FIXED + L.ACTIVE ..][0..2]) |*v, column| v.* = gather(column, previous[0..count]);
        for (&scratch.interaction, 0..) |*v, batch| v.* = loadSecure(values[fm + 4 * batch ..][0..4], begin, count);
        const prior = gatherSecure(evaluation.previous_values[fm + L.INTERACTION - 4 ..][0..4], previous[0..count]);
        var weighted = V.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = V.PackedSink{ .weighted_accumulator = &weighted };
        E.emitFor(F, scratch.row(), &scratch.interaction, prior, component.claim, component.challenges, .{ .calls = component.calls, .first_id = component.first_call_id }, &sink);
        std.debug.assert(sink.count == L.CONSTRAINTS);
        accumulate(output, evaluation.globalRow(part, begin), count, weighted.accumulation.mulBase(F.splat(inverse)));
    }
}
fn load(column: []const M, start: usize, count: usize) F {
    if (count == LANES) return F.load(column.ptr + start);
    var values: [LANES]M = @splat(M.zero());
    @memcpy(values[0..count], column[start..][0..count]);
    return F.fromLanes(values);
}
fn gather(column: []const M, indices: []const usize) F {
    var values: [LANES]M = @splat(M.zero());
    for (indices, 0..) |index, i| values[i] = column[index];
    return F.fromLanes(values);
}
fn loadSecure(columns: []const []const M, start: usize, count: usize) S {
    return S.fromCoordinates(.{ load(columns[0], start, count), load(columns[1], start, count), load(columns[2], start, count), load(columns[3], start, count) });
}
fn gatherSecure(columns: []const []const M, indices: []const usize) S {
    return S.fromCoordinates(.{ gather(columns[0], indices), gather(columns[1], indices), gather(columns[2], indices), gather(columns[3], indices) });
}
fn accumulate(output: *Column, start: usize, count: usize, value: S) void {
    const coordinates = value.coordinates();
    if (output.next_fresh_index) |next| {
        if (next == start) {
            for (output.col.columns, coordinates) |column, coordinate| {
                if (count == LANES) {
                    coordinate.store(column.ptr + start);
                } else {
                    for (0..count) |i| column[start + i] = coordinate.lane(i);
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
        } else {
            for (0..count) |i| column[start + i] = column[start + i].add(coordinate.lane(i));
        }
    }
}
