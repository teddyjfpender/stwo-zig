//! PAGE-local dedicated post-main wire interaction. Every byte in this view
//! belongs to the same precommitted capture tree used by semantic arithmetic.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Air = @import("block_v5_memory_source_blake_capture_air_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
pub const Claim = struct { sums: [Air.PAIRS]Q, wire_requests: u64 };
pub fn normalize(claim: Claim, rows: usize, expected_requests: u64) ![Air.PAIRS]Q {
    if (rows == 0 or rows >= core.fields.m31.Modulus or expected_requests >= core.fields.m31.Modulus or claim.wire_requests != expected_requests)
        return error.InvalidSourceBlakeCaptureClaim;
    const inv = try M.fromCanonical(@intCast(rows)).inv();
    var out: [Air.PAIRS]Q = undefined;
    for (&out, claim.sums) |*value, sum| value.* = sum.mulM31(inv);
    return out;
}
pub const Columns = struct {
    fixed: []const []const M,
    main: []const []const M,
    row_log: u32,
    compressions: u32,
    first_circuit: u32,
    pub fn rows(self: Columns) !usize {
        if (self.row_log < 1 or self.row_log >= core.circle.M31_CIRCLE_LOG_ORDER or self.row_log >= @bitSizeOf(usize) or self.first_circuit == 0)
            return error.InvalidSourceBlakeCaptureGeometry;
        const count = @as(usize, 1) << @intCast(self.row_log);
        if (self.compressions > count or @as(u64, self.first_circuit) + self.compressions >= core.fields.m31.Modulus or
            self.fixed.len != Air.FIXED_COUNT or self.main.len != Air.MAIN_COUNT) return error.InvalidSourceBlakeCaptureGeometry;
        for (self.fixed) |column| if (column.len != count) return error.InvalidSourceBlakeCaptureGeometry;
        for (self.main) |column| if (column.len != count) return error.InvalidSourceBlakeCaptureGeometry;
        // All physical padding and independently enumerated circuit ordinals
        // are checked before interaction allocation. Other mapping fields are
        // rebuilt and pinned by the enclosing PAGE receiver.
        for (0..count) |logical| {
            const physical = Place.committedRow(logical, self.row_log);
            if (logical < self.compressions) {
                if (self.fixed[0][physical].toU32() != 1 or self.fixed[1][physical].toU32() != self.first_circuit + logical)
                    return error.InvalidSourceBlakeCaptureFixed;
            } else {
                for (self.fixed) |column| if (!column[physical].isZero()) return error.InvalidSourceBlakeCaptureTail;
                for (self.main) |column| if (!column[physical].isZero()) return error.InvalidSourceBlakeCaptureTail;
            }
        }
        return count;
    }
    fn terms(self: Columns, physical: usize, c: Air.Algebra(Q).Challenge) [Air.WIRE_COUNT]Air.Algebra(Q).Term {
        var fixed: [Air.FIXED_COUNT]Q = undefined;
        var main: [Air.MAIN_COUNT]Q = undefined;
        for (&fixed, self.fixed) |*value, column| value.* = Q.fromBase(column[physical]);
        for (&main, self.main) |*value, column| value.* = Q.fromBase(column[physical]);
        return Air.Algebra(Q).terms(fixed, main, c);
    }
};
pub const Generated = struct {
    a: std.mem.Allocator,
    cells: []M,
    claim: Claim,
    pub fn deinit(self: *Generated) void {
        self.a.free(self.cells);
        self.* = undefined;
    }
};
fn contribution(left: Air.Algebra(Q).Term, right: Air.Algebra(Q).Term) !Q {
    var result = Q.zero();
    if (!left.numerator.isZero()) result = result.add(left.numerator.mul(try left.denominator.inv()));
    if (!right.numerator.isZero()) result = result.add(right.numerator.mul(try right.denominator.inv()));
    return result;
}
pub fn generate(a: std.mem.Allocator, columns: Columns, challenge: Air.Algebra(Q).Challenge, expected_requests: u64, max_cells: usize) !Generated {
    const rows = try columns.rows();
    const requests = try std.math.mul(u64, columns.compressions, Air.requestMass());
    if (expected_requests != requests or requests >= core.fields.m31.Modulus) return error.InvalidSourceBlakeCaptureClaim;
    const count = try std.math.mul(usize, rows, Air.INTERACTION_COUNT);
    if (count > max_cells) return error.SourceBlakeCaptureResourceLimit;
    const cells = try a.alloc(M, count);
    errdefer a.free(cells);
    var claim = Claim{ .sums = @splat(Q.zero()), .wire_requests = requests };
    for (0..columns.compressions) |logical| {
        const terms = columns.terms(Place.committedRow(logical, columns.row_log), challenge);
        for (0..Air.PAIRS) |i| claim.sums[i] = claim.sums[i].add(try contribution(terms[2 * i], terms[2 * i + 1]));
    }
    const normalized = try normalize(claim, rows, requests);
    var running: [Air.PAIRS]Q = @splat(Q.zero());
    for (0..rows) |logical| {
        const physical = Place.committedRow(logical, columns.row_log);
        const terms = if (logical < columns.compressions) columns.terms(physical, challenge) else null;
        for (0..Air.PAIRS) |i| {
            const delta = if (terms) |values| try contribution(values[2 * i], values[2 * i + 1]) else Q.zero();
            running[i] = running[i].add(delta).sub(normalized[i]);
            for (running[i].toM31Array(), 0..) |value, part| cells[(4 * i + part) * rows + physical] = value;
        }
    }
    return .{ .a = a, .cells = cells, .claim = claim };
}
