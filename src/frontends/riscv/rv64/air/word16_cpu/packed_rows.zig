//! Sixteen logical rows, packed M31 local values and packed secure LogUp.
//! Scalar oracle and SIMD call the SAME Component.emitFor polynomial authority.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const C = @import("component.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const F = E.PackedBase;
const S = E.PackedSecure;
const Column = @import("stwo_prover_engine").air.accumulation.ColumnAccumulator;
const LANES = E.LANES;
pub fn evaluate(component: *const C.Component, columns: []const []const M, inverses: []const M, output: *Column) !void {
    const n = @as(usize, 1) << @intCast(component.log_size + 1);
    const widths = component.widths();
    const inter_start = widths[0] + widths[1];
    if (columns.len != inter_start + widths[2] or inverses.len != 2 or output.random_coeff_powers.len != component.nConstraints()) return error.InvalidWord16CpuDomain;
    for (columns) |column| if (column.len != n) return error.InvalidWord16CpuDomain;
    for (output.col.columns) |column| if (column.len < n) return error.InvalidWord16CpuDomain;
    if (component.scalar_reference) return scalar(component, columns, inverses, output);
    var begin: usize = 0;
    while (begin < n) : (begin += LANES) {
        const count = @min(LANES, n - begin);
        var values: [C.MAX_COLUMNS]F = undefined;
        var previous_main: [44]F = @splat(F.zero());
        var previous: [56]F = @splat(F.zero());
        for (columns, 0..) |column, i| values[i] = load(column, begin, count);
        var indices: [LANES]usize = undefined;
        for (indices[0..count], 0..) |*index, i| index.* = core.utils.previousBitReversedCircleDomainIndex(begin + i, component.log_size, component.log_size + 1);
        for ([_]usize{ 1, 2 }) |tree| {
            const at = if (tree == 1) widths[0] else inter_start;
            for (0..widths[tree]) |column| if (component.needsPrevious(tree, column)) {
                var lanes: [LANES]M = @splat(M.zero());
                for (indices[0..count], 0..) |index, lane| lanes[lane] = columns[at + column][index];
                if (tree == 1) previous_main[column] = F.fromLanes(lanes) else previous[column] = F.fromLanes(lanes);
            };
        }
        var accumulator = E.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.PackedSink{ .weighted_accumulator = &accumulator };
        component.emitFor(F, values[0..widths[0]], values[widths[0]..][0..widths[1]], values[inter_start..][0..widths[2]], &previous_main, &previous, &sink);
        std.debug.assert(sink.count == component.nConstraints());
        var denominators: [LANES]M = @splat(M.zero());
        for (denominators[0..count], 0..) |*value, lane| value.* = inverses[(begin + lane) >> @intCast(component.log_size)];
        accumulate(output, begin, count, accumulator.accumulation.mulBase(F.fromLanes(denominators)));
    }
}
fn scalar(component: *const C.Component, columns: []const []const M, inverses: []const M, output: *Column) !void {
    const widths = component.widths();
    const inter_start = widths[0] + widths[1];
    for (0..columns[0].len) |row| {
        var values: [C.MAX_COLUMNS]Q = undefined;
        var previous_main: [44]Q = @splat(Q.zero());
        var previous: [56]Q = @splat(Q.zero());
        for (columns, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, component.log_size, component.log_size + 1);
        for ([_]usize{ 1, 2 }) |tree| {
            const at = if (tree == 1) widths[0] else inter_start;
            for (0..widths[tree]) |column| if (component.needsPrevious(tree, column)) {
                if (tree == 1) previous_main[column] = Q.fromBase(columns[at + column][prior]) else previous[column] = Q.fromBase(columns[at + column][prior]);
            };
        }
        var accumulator = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
        component.emitFor(Q, values[0..widths[0]], values[widths[0]..][0..widths[1]], values[inter_start..][0..widths[2]], &previous_main, &previous, &sink);
        std.debug.assert(sink.count == component.nConstraints());
        const result = accumulator.accumulation.mulM31(inverses[row >> @intCast(component.log_size)]);
        if (output.next_fresh_index) |next| {
            if (next == row) {
                for (output.col.columns, result.toM31Array()) |column, coordinate| column[row] = coordinate;
                output.next_fresh_index = row + 1;
                continue;
            }
            output.next_fresh_index = null;
        }
        for (output.col.columns, result.toM31Array()) |column, coordinate| column[row] = column[row].add(coordinate);
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
                    for (0..count) |lane| column[start + lane] = coordinate.lane(lane);
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
            for (0..count) |lane| column[start + lane] = column[start + lane].add(coordinate.lane(lane));
        }
    }
}
