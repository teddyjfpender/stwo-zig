//! Bounded sixteen-row base-field gather; only FS algebra becomes secure.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const C = @import("component.zig");
const L = @import("layout.zig");
const Column = @import("stwo_prover_engine").air.accumulation.ColumnAccumulator;
const M = core.fields.m31.M31;
const F = E.PackedBase;
const S = E.PackedSecure;
const LANES = E.LANES;

pub fn evaluate(component: *const C.Component, columns: []const []const M, start: usize, end: usize, inverses: []const M, output: *Column) !void {
    if (component.log_size < 5 or component.log_size > L.MAX_LOG) return error.InvalidExecutionGeometry;
    const n = @as(usize, 1) << @intCast(component.log_size + 1);
    const widths = [_]usize{ 3, L.main.COUNT, L.inter.COUNT };
    const total = widths[0] + widths[1] + widths[2];
    if (columns.len != total or start > end or end > n or inverses.len != 2 or output.random_coeff_powers.len != component.nConstraints()) return error.InvalidExecutionDomain;
    for (columns) |column| if (column.len != n) return error.InvalidExecutionDomain;
    for (output.col.columns) |column| if (column.len < n) return error.InvalidExecutionDomain;
    const inter_start = widths[0] + widths[1];
    var begin = start;
    while (begin < end) : (begin += LANES) {
        const count = @min(LANES, end - begin);
        var values: [C.COLUMNS]F = undefined;
        var pm: [L.main.COUNT]F = @splat(F.zero());
        var pi: [L.inter.COUNT]F = @splat(F.zero());
        for (columns, 0..) |column, i| values[i] = load(column, begin, count);
        var indices: [LANES]usize = undefined;
        for (indices[0..count], 0..) |*index, i| index.* = core.utils.previousBitReversedCircleDomainIndex(begin + i, component.log_size, component.log_size + 1);
        for (1..3) |tree| {
            const offset = if (tree == 1) widths[0] else inter_start;
            for (0..widths[tree]) |c| if (if (tree == 1) L.previousMain(c) else L.previousInter(c)) {
                var lanes: [LANES]M = @splat(M.zero());
                for (indices[0..count], 0..) |index, lane| lanes[lane] = columns[offset + c][index];
                if (tree == 1) pm[c] = F.fromLanes(lanes) else pi[c] = F.fromLanes(lanes);
            };
        }
        var accumulator = E.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.PackedSink{ .weighted_accumulator = &accumulator };
        component.emitFor(F, values[0..widths[0]], values[widths[0]..][0..widths[1]], pm[0..widths[1]], values[inter_start..][0..widths[2]], pi[0..widths[2]], &sink);
        std.debug.assert(sink.count == component.nConstraints());
        var denominators: [LANES]M = @splat(M.zero());
        for (denominators[0..count], 0..) |*value, lane| value.* = inverses[(begin + lane) >> @intCast(component.log_size)];
        accumulate(output, begin, count, accumulator.accumulation.mulBase(F.fromLanes(denominators)));
    }
}
fn load(column: []const M, start: usize, count: usize) F {
    if (count == LANES) return F.load(column.ptr + start);
    var values: [LANES]M = @splat(M.zero());
    @memcpy(values[0..count], column[start..][0..count]);
    return F.fromLanes(values);
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
