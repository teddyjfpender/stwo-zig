//! Native sixteen-row Keccak evaluation. Phase polynomials remain full inputs.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../evaluation.zig");
const C = @import("component.zig");
const E = @import("equations.zig");
const L = @import("layout.zig");
const Eval = @import("../../full/coset_evaluation.zig").Evaluation;
const Column = @import("stwo_prover_engine").air.accumulation.ColumnAccumulator;
const M = core.fields.m31.M31;
const F = V.PackedBase;
const S = V.PackedSecure;
const LANES = V.LANES;
pub const Scratch = struct {
    fixed: [L.FIXED]F,
    main: [L.MAIN]F,
    shifted: [4][L.STATE]F,
    previous_header: [3]F,
    interaction: [L.BATCHES]S,
    fn row(self: *const Scratch) E.RowFor(F) {
        return .{ .fixed = &self.fixed, .main = &self.main, .previous_header = &self.previous_header, .state_minus_two = &self.shifted[0], .state_minus_one = &self.shifted[1], .state_plus_one = &self.shifted[2], .state_plus_two = &self.shifted[3] };
    }
};
const Halo = struct { row: usize, partner: bool };
pub fn evaluate(component: *const C.Parameters, evaluation: *const Eval, part: usize, start: usize, end: usize, output: *Column, inverse: M, scratch: ?*Scratch) void {
    const values = evaluation.current_values;
    var begin = start;
    while (begin < end) : (begin += LANES) {
        const count = @min(LANES, end - begin);
        var previous: [LANES]usize = undefined;
        for (0..count) |i| previous[i] = evaluation.previousRow(part, begin + i);
        var accumulator = V.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = V.PackedSink{ .weighted_accumulator = &accumulator };
        if (component.kind == .permutation) {
            const row = scratch.?;
            const fm = L.FIXED + L.MAIN;
            for (&row.fixed, values[0..L.FIXED]) |*v, column| v.* = load(column, begin, count);
            for (&row.main, values[L.FIXED..fm]) |*v, column| v.* = load(column, begin, count);
            var halos: [4][LANES]Halo = undefined;
            for (L.MASK_OFFSETS[1..], 0..) |offset, j| {
                for (0..count) |i| {
                    const shifted = core.utils.offsetBitReversedCircleDomainIndex(evaluation.globalRow(part, begin + i), evaluation.trace_log, evaluation.trace_log + 2, offset);
                    const target = shifted / evaluation.size;
                    std.debug.assert(target == part or target == part ^ 1);
                    halos[j][i] = .{ .row = shifted % evaluation.size, .partner = target != part };
                }
                for (&row.shifted[j], 0..) |*v, c| {
                    var lanes: [LANES]M = @splat(M.zero());
                    const own = values[L.FIXED + c];
                    const partner = evaluation.previous_values[L.FIXED + c];
                    for (halos[j][0..count], 0..) |halo, i| lanes[i] = (if (halo.partner) partner else own)[halo.row];
                    v.* = F.fromLanes(lanes);
                }
            }
            for (&row.previous_header, evaluation.previous_values[L.FIXED + L.ACTIVE_A ..][0..3]) |*v, column| v.* = gather(column, previous[0..count]);
            for (row.interaction[0..component.batches], 0..) |*v, batch| v.* = loadSecure(values[fm + 4 * batch ..][0..4], begin, count);
            const prior = gatherSecure(evaluation.previous_values[fm + component.interactionCount() - 4 ..][0..4], previous[0..count]);
            component.emit_packed.?(row.row(), row.interaction[0..component.batches], prior, component.claim, component.challenges, .{ .calls = component.calls, .first_id = component.first_call_id }, &sink);
        } else {
            var tuple: [6]F = undefined;
            for (&tuple, values[0..6]) |*v, column| v.* = load(column, begin, count);
            sink.emit(C.tableResidualFor(F, component, &tuple, load(values[6], begin, count), load(values[7], begin, count), loadSecure(values[8..12], begin, count), gatherSecure(evaluation.previous_values[8..12], previous[0..count])));
        }
        std.debug.assert(sink.count == component.nConstraints());
        accumulate(output, evaluation.globalRow(part, begin), count, accumulator.accumulation.mulBase(F.splat(inverse)));
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
