//! Test/prototype witness only. No Context hook, PCS roster or production gate.
const std = @import("std");
const Core = @import("stwo_core");
const Row = @import("row.zig");
const Source = @import("authority.zig").Source;
const M = Core.fields.m31.M31;
const Q = Core.fields.qm31.QM31;
const O = Core.fields.om31.OM31;
pub fn main(a: std.mem.Allocator, source: *const Source, values: []const Q) ![][Row.MAIN]M {
    if (values.len == 0 or !values[0].isZero()) return error.NativeDotZeroAuthority;
    const rows = try a.alloc([Row.MAIN]M, source.fixed.len);
    errdefer a.free(rows);
    @memset(rows, @splat(M.zero()));
    var prior = O.zero();
    for (source.fixed[0..source.raw_rows], rows[0..source.raw_rows]) |fixed, *row| {
        const ids = [3]u32{ fixed[0].v, fixed[1].v, fixed[2].v };
        for (ids) |id| if (id >= values.len) return error.NativeDotWitnessShape;
        const scalar = values[ids[2]].toM31Array();
        for (scalar[1..]) |v| if (!v.isZero()) return error.NativeDotScalarNotBase;
        const weight = O{ .c0 = values[ids[0]], .c1 = values[ids[1]] };
        row.* = Row.fill(weight, scalar[0], prior, !fixed[Row.FIRST].isZero());
        prior = O.fromM31Array(row[Row.ACC..][0..8].*);
        if (!fixed[Row.LAST].isZero()) for (0..2) |i| {
            const id = fixed[Row.OUTPUT_IDS + i].v;
            if (id >= values.len or !values[id].eql(if (i == 0) prior.c0 else prior.c1)) return error.NativeDotOutputMismatch;
        };
    }
    return rows;
}
