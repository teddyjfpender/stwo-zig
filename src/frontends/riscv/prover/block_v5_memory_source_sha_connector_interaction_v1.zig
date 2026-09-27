//! Dedicated post-main SHA/core wire prefixes. Source semantic challenges
//! cannot be used as this challenge. All original/capture/core main roots
//! must already be sealed by the caller's independently checked roster.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Air = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const Placement = @import("../air/block/memory_component_trace.zig");
pub const Claim = struct { sums: [Air.PAIRS]Q, wire_requests: u64 };
pub fn normalize(claim: Claim, rows: usize, expected_requests: u64) ![Air.PAIRS]Q {
    if (rows == 0 or rows >= core.fields.m31.Modulus or claim.wire_requests != expected_requests or expected_requests >= core.fields.m31.Modulus) return error.InvalidSourceShaConnectorClaim;
    const inverse = try M.fromCanonical(@intCast(rows)).inv();
    var out: [Air.PAIRS]Q = undefined;
    for (&out, claim.sums) |*value, sum| value.* = sum.mulM31(inverse);
    return out;
}
pub const Columns = struct {
    fixed: []const []const M,
    original: []const []const M,
    captures: []const []const M,
    row_log: u32,
    logical_rows: u32,
    pub fn rows(self: Columns) !usize {
        if (self.row_log == 0 or self.row_log >= 31) return error.InvalidSourceShaConnectorGeometry;
        const count = @as(usize, 1) << @intCast(self.row_log);
        if (self.logical_rows > count or self.fixed.len != Air.EXPANDED_FIXED_COUNT or self.original.len != Air.SOURCE_MAIN_COUNT or self.captures.len != Air.CAPTURE_MAIN_COUNT) return error.InvalidSourceShaConnectorGeometry;
        for (self.fixed) |column| if (column.len != count) return error.InvalidSourceShaConnectorGeometry;
        for (self.original) |column| if (column.len != count) return error.InvalidSourceShaConnectorGeometry;
        for (self.captures) |column| if (column.len != count) return error.InvalidSourceShaConnectorGeometry;
        return count;
    }
    fn terms(self: Columns, physical: usize, challenge: Air.Algebra(Q).Challenge) [Air.WIRE_COUNT]Air.Algebra(Q).Term {
        var fixed: [Air.EXPANDED_FIXED_COUNT]Q = undefined;
        var main: [Air.MAIN_COUNT]Q = undefined;
        for (&fixed, self.fixed) |*value, column| value.* = Q.fromBase(column[physical]);
        for (main[0..Air.SOURCE_MAIN_COUNT], self.original) |*value, column| value.* = Q.fromBase(column[physical]);
        for (main[Air.SOURCE_MAIN_COUNT..], self.captures) |*value, column| value.* = Q.fromBase(column[physical]);
        return Air.Algebra(Q).terms(fixed, main, challenge);
    }
};
pub const Generated = struct {
    allocator: std.mem.Allocator,
    cells: []M,
    claim: Claim,
    pub fn deinit(self: *Generated) void {
        self.allocator.free(self.cells);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, columns: Columns, challenge: Air.Algebra(Q).Challenge, expected_requests: u64, max_cells: usize) !Generated {
    const rows = try columns.rows();
    const count = try std.math.mul(usize, rows, Air.INTERACTION_COUNT);
    if (count > max_cells) return error.SourceShaConnectorResourceLimit;
    var observed_requests: u64 = 0;
    for (0..columns.logical_rows) |logical| {
        const physical = Placement.committedRow(logical, columns.row_log);
        const active = columns.fixed[0][physical].toU32();
        const second = columns.fixed[3][physical].toU32();
        if (active > 1 or second > active) return error.InvalidSourceShaConnectorFixedRecipe;
        observed_requests = try std.math.add(u64, observed_requests, 32 * @as(u64, active + second));
    }
    if (observed_requests != expected_requests or expected_requests >= core.fields.m31.Modulus) return error.InvalidSourceShaConnectorClaim;
    const cells = try a.alloc(M, count);
    errdefer a.free(cells);
    var claim = Claim{ .sums = @splat(Q.zero()), .wire_requests = observed_requests };
    for (0..columns.logical_rows) |logical| {
        const terms = columns.terms(Placement.committedRow(logical, columns.row_log), challenge);
        for (0..Air.PAIRS) |pair| claim.sums[pair] = claim.sums[pair].add(try contribution(terms[2 * pair], terms[2 * pair + 1]));
    }
    const normalized = try normalize(claim, rows, expected_requests);
    var running: [Air.PAIRS]Q = @splat(Q.zero());
    for (0..rows) |logical| {
        const physical = Placement.committedRow(logical, columns.row_log);
        const terms = if (logical < columns.logical_rows) columns.terms(physical, challenge) else null;
        for (0..Air.PAIRS) |pair| {
            const change = if (terms) |values| try contribution(values[2 * pair], values[2 * pair + 1]) else Q.zero();
            running[pair] = running[pair].add(change).sub(normalized[pair]);
            for (running[pair].toM31Array(), 0..) |value, coordinate| cells[(4 * pair + coordinate) * rows + physical] = value;
        }
    }
    return .{ .allocator = a, .cells = cells, .claim = claim };
}
fn contribution(left: Air.Algebra(Q).Term, right: Air.Algebra(Q).Term) !Q {
    var out = Q.zero();
    if (!left.numerator.isZero()) out = out.add(left.numerator.mul(try left.denominator.inv()));
    if (!right.numerator.isZero()) out = out.add(right.numerator.mul(try right.denominator.inv()));
    return out;
}
