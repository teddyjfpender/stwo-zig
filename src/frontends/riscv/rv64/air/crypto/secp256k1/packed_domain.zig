//! Bounded sixteen-row loads and disjoint quotient stores shared by the two
//! concrete secp providers. No field equations or transcript state live here.
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const M = core.fields.m31.M31;
pub const F = E.PackedBase;
pub const S = E.PackedSecure;
pub const LANES = E.LANES;
pub fn load(source: []const M, start: usize, count: usize) F {
    if (count == LANES) return F.load(source.ptr + start);
    var values: [LANES]M = @splat(M.zero());
    @memcpy(values[0..count], source[start..][0..count]);
    return F.fromLanes(values);
}
pub fn gather(source: []const M, indices: []const usize) F {
    var values: [LANES]M = @splat(M.zero());
    for (indices, 0..) |index, i| values[i] = source[index];
    return F.fromLanes(values);
}
pub fn secure(source: []const []const M, start: usize, count: usize) S {
    var values: [4]F = undefined;
    for (&values, source[0..4]) |*value, column| value.* = load(column, start, count);
    return S.fromCoordinates(values);
}
pub fn previousSecure(source: []const []const M, indices: []const usize) S {
    var values: [4]F = undefined;
    for (&values, source[0..4]) |*value, column| value.* = gather(column, indices);
    return S.fromCoordinates(values);
}
pub fn accumulate(output: *@import("stwo_prover_engine").air.accumulation.ColumnAccumulator, start: usize, count: usize, value: S) void {
    const coordinates = value.coordinates();
    if (output.next_fresh_index) |next| {
        if (next == start) {
            for (output.col.columns, coordinates) |column, coordinate| {
                if (count == LANES) coordinate.store(column.ptr + start) else for (0..count) |i| {
                    column[start + i] = coordinate.lane(i);
                }
            }
            output.next_fresh_index = start + count;
            return;
        }
        output.next_fresh_index = null;
    }
    for (output.col.columns, coordinates) |column, coordinate| {
        if (count == LANES) F.load(column.ptr + start).add(coordinate).store(column.ptr + start) else for (0..count) |i| {
            column[start + i] = column[start + i].add(coordinate.lane(i));
        }
    }
}
