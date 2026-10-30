//! Disabled arbitrary-alignment byte-transfer kernel for the SAME-ROM five-op
//! loop. This kernel proves only one destination word's byte merge. A future
//! macro source must additionally prove caller/word boundaries, exact source
//! word queries, clocks, range/byte supply, halt policy and complete VM joins.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const production_active = false;
pub const whole_source_qualified = false;
pub const COLUMN_COUNT = 33;
pub const CONSTRAINT_COUNT = 45;
pub const MAX_DEGREE = 3;
pub const Layout = struct {
    pub const active = 0;
    pub const source_low = 1;
    pub const source_high = 5;
    pub const destination_before = 9;
    pub const destination_after = 13;
    pub const mask = 17;
    pub const start = 21;
    pub const end = 25;
    pub const shift = 29;
};
fn sum(comptime S: type, row: [COLUMN_COUNT]S, start: usize) S {
    var result = S.zero();
    for (0..4) |i| result = result.add(row[start + i]);
    return result;
}
fn sourceByte(comptime S: type, row: [COLUMN_COUNT]S, destination_lane: usize) S {
    var result = S.zero();
    for (0..4) |shift| result = result.add(row[Layout.shift + shift].mul(row[Layout.source_low + destination_lane + shift]));
    return result;
}
/// The local source-word value provider uses these weights, never duplicate
/// external RAM transitions. Unused boundary words are not read or queried.
pub fn sourceQueryWeights(comptime S: type, row: [COLUMN_COUNT]S) [2]S {
    var low = S.zero();
    var high = S.zero();
    for (0..4) |shift| {
        for (0..4) |start| if (start + shift < 4) {
            low = low.add(row[Layout.start + start].mul(row[Layout.shift + shift]));
        };
        for (1..5) |end| if (end + shift > 4) {
            high = high.add(row[Layout.end + end - 1].mul(row[Layout.shift + shift]));
        };
    }
    return .{ low, high };
}
pub fn constraints(comptime S: type, row: [COLUMN_COUNT]S) [CONSTRAINT_COUNT]S {
    const active = row[Layout.active];
    var out: [CONSTRAINT_COUNT]S = undefined;
    var n: usize = 0;
    out[n] = active.mul(active.sub(S.one()));
    n += 1;
    for (row[Layout.mask..]) |value| {
        out[n] = value.mul(value.sub(S.one()));
        n += 1;
    }
    for ([_]usize{ Layout.start, Layout.end, Layout.shift }) |start| {
        out[n] = sum(S, row, start).sub(active);
        n += 1;
    }
    var invalid_span = S.zero();
    for (0..4) |start| for (1..start + 1) |end| {
        invalid_span = invalid_span.add(row[Layout.start + start].mul(row[Layout.end + end - 1]));
    };
    out[n] = invalid_span;
    n += 1;
    for (0..4) |lane| {
        var starts = S.zero();
        var ends = S.zero();
        for (0..lane + 1) |i| starts = starts.add(row[Layout.start + i]);
        for (lane..4) |i| ends = ends.add(row[Layout.end + i]);
        out[n] = row[Layout.mask + lane].sub(starts.mul(ends));
        n += 1;
        out[n] = row[Layout.destination_after + lane].sub(row[Layout.destination_before + lane]).sub(row[Layout.mask + lane].mul(sourceByte(S, row, lane).sub(row[Layout.destination_before + lane])));
        n += 1;
    }
    for (row[Layout.source_low..Layout.mask]) |value| {
        out[n] = S.one().sub(active).mul(value);
        n += 1;
    }
    std.debug.assert(n == CONSTRAINT_COUNT);
    return out;
}
/// Proved last destination row can link this degree-three expression into a
/// separate call/end relation to authenticate x14's final loaded byte.
pub fn lastCopiedByte(comptime S: type, row: [COLUMN_COUNT]S) S {
    var result = S.zero();
    for (0..4) |lane| result = result.add(row[Layout.end + lane].mul(sourceByte(S, row, lane)));
    return result;
}
pub fn witness(source_low: u32, source_high: u32, destination_before: u32, start: u2, end: u3, shift: u2) ![COLUMN_COUNT]M {
    if (end == 0 or end > 4 or start >= end) return error.InvalidByteLoopSpan;
    var row: [COLUMN_COUNT]M = @splat(M.zero());
    row[Layout.active] = M.one();
    row[Layout.start + @as(usize, start)] = M.one();
    row[Layout.end + @as(usize, end) - 1] = M.one();
    row[Layout.shift + @as(usize, shift)] = M.one();
    for (0..4) |byte| {
        row[Layout.source_low + byte] = M.fromCanonical((source_low >> @as(u5, @intCast(8 * byte))) & 255);
        row[Layout.source_high + byte] = M.fromCanonical((source_high >> @as(u5, @intCast(8 * byte))) & 255);
        row[Layout.destination_before + byte] = M.fromCanonical((destination_before >> @as(u5, @intCast(8 * byte))) & 255);
    }
    for (0..4) |byte| {
        const selected = byte >= start and byte < end;
        row[Layout.mask + byte] = M.fromCanonical(@intFromBool(selected));
        row[Layout.destination_after + byte] = if (selected) row[Layout.source_low + byte + shift] else row[Layout.destination_before + byte];
    }
    return row;
}
