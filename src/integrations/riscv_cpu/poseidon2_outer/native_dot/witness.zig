//! Shared bounded row iterator. Physical MAIN writes directly into its final
//! column allocations; the dense logical wrapper is only a small test helper.
const std = @import("std");
const Core = @import("stwo_core");
const Row = @import("row.zig");
const Source = @import("authority.zig").Source;
const M = Core.fields.m31.M31;
const Q = Core.fields.qm31.QM31;
const O = Core.fields.om31.OM31;
pub const Iterator = struct {
    source: *const Source,
    variables: []const Q,
    index: usize = 0,
    prior: O = O.zero(),
    pub fn init(source: *const Source, variables: []const Q) !Iterator {
        if (variables.len == 0 or !variables[0].isZero()) return error.NativeDotZeroAuthority;
        return .{ .source = source, .variables = variables };
    }
    pub fn next(self: *Iterator) !?[Row.MAIN]M {
        if (self.index == self.source.raw_rows) return null;
        const fixed = self.source.fixed[self.index];
        const ids = [3]u32{ fixed[0].v, fixed[1].v, fixed[2].v };
        for (ids) |id| if (id >= self.variables.len) return error.NativeDotWitnessShape;
        const scalar = self.variables[ids[2]].toM31Array();
        for (scalar[1..]) |v| if (!v.isZero()) return error.NativeDotScalarNotBase;
        const weight = O{ .c0 = self.variables[ids[0]], .c1 = self.variables[ids[1]] };
        const row = Row.fill(weight, scalar[0], self.prior, !fixed[Row.FIRST].isZero());
        const result = O.fromM31Array(row[Row.ACC..][0..8].*);
        if (!fixed[Row.LAST].isZero()) for (0..2) |i| {
            const id = fixed[Row.OUTPUT_IDS + i].v;
            if (id >= self.variables.len or !self.variables[id].eql(if (i == 0) result.c0 else result.c1)) return error.NativeDotOutputMismatch;
        };
        self.prior = result;
        self.index += 1;
        return row;
    }
};
pub fn main(a: std.mem.Allocator, source: *const Source, values: []const Q) ![][Row.MAIN]M {
    var iterator = try Iterator.init(source, values);
    const rows = try a.alloc([Row.MAIN]M, source.fixed.len);
    errdefer a.free(rows);
    @memset(rows, @splat(M.zero()));
    var i: usize = 0;
    while (try iterator.next()) |row| : (i += 1) rows[i] = row;
    return rows;
}
