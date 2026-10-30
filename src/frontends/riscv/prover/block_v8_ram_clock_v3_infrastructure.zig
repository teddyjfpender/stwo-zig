//! Explicit V3 clock infrastructure: canonical clock equations plus active*space=0.
//! This forbids RAM filler rows inside the proof, including malicious witnesses.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const C = core.air.components;
const P = engine.air.component_prover;
const A = engine.air.accumulation;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const Clock = @import("../air/clock_update_component.zig");
pub fn constraints(comptime S: type, main: []const S, active: S) ![4]S {
    if (main.len != 10) return error.InvalidPartitionedDirectMask;
    return (try Clock.directConstraintsGeneric(S, main, active)) ++ [1]S{active.mul(main[1])};
}
pub const Component = struct {
    log_size: u32,
    active_column: usize,
    main_offset: usize,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, P.ComponentProver, P.Trace, A.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Self) P.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) C.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 4;
    }
    pub fn width(_: *const Self) usize {
        return @import("../air/clock_update_interaction.zig").N_MAIN_COLUMNS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 1;
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return a.dupe(usize, &.{self.active_column});
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, &.{self.log_size});
        errdefer a.free(fixed);
        const main = try a.alloc(u32, self.width());
        errdefer a.free(main);
        @memset(main, self.log_size);
        const interaction = try a.alloc(u32, 0);
        errdefer a.free(interaction);
        return .initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        if (max_log < self.log_size) return error.InvalidPartitionedDirectMask;
        const fixed = try pointColumns(a, 1, point);
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, self.width(), point);
        errdefer freePoints(a, main);
        const interaction = try pointColumns(a, 0, point);
        errdefer freePoints(a, interaction);
        return .initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn evaluate(self: *const Self, comptime S: type, main: []const S, active: S, out: *[4]S) ![]const S {
        if (main.len != self.width()) return error.InvalidPartitionedDirectMask;
        out.* = try constraints(S, main, active);
        return out[0..self.nConstraints()];
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < self.log_size or mask.items.len < 3 or mask.items[0].len <= self.active_column or mask.items[1].len < self.main_offset + self.width()) return error.InvalidPartitionedDirectMask;
        var row: [10]Q = undefined;
        for (row[0..self.width()], mask.items[1][self.main_offset..][0..self.width()]) |*value, column| value.* = try pointAt(column);
        var checks: [4]Q = undefined;
        const values = try self.evaluate(Q, row[0..self.width()], try pointAt(mask.items[0][self.active_column]), &checks);
        const inverse = try core.constraints.cosetVanishing(Q, Canonic.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
        for (values) |value| accumulator.accumulate(value.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const P.Trace, accumulator: *A.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len <= self.active_column or trace.polys.items[1].len < self.main_offset + self.width()) return error.InvalidPartitionedDirectMask;
        const a = accumulator.allocator;
        const eval_log = self.log_size + 1;
        const domain = Canonic.new(eval_log).circleDomain();
        var polys: [11]P.Poly = undefined;
        polys[0] = trace.polys.items[0][self.active_column];
        @memcpy(polys[1..][0..self.width()], trace.polys.items[1][self.main_offset..][0..self.width()]);
        var owned_count: usize = 0;
        for (polys[0 .. 1 + self.width()]) |poly| {
            try poly.validate();
            owned_count += @intFromBool(poly.log_size != eval_log);
        }
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var values: [11][]const M = undefined;
        for (polys[0 .. 1 + self.width()], values[0 .. 1 + self.width()]) |poly, *out| out.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, self.log_size, eval_log, domain.size(), owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        var inverses: [2]M = undefined;
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, Canonic.new(self.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 1))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(output);
        var result = output[0];
        for (0..domain.size()) |physical| {
            var row: [10]Q = undefined;
            for (row[0..self.width()], values[1..][0..self.width()]) |*value, column| value.* = Q.fromBase(column[physical]);
            var checks: [4]Q = undefined;
            const evaluated = try self.evaluate(Q, row[0..self.width()], Q.fromBase(values[0][physical]), &checks);
            var folded = Q.zero();
            for (evaluated, 0..) |check, i| folded = folded.add(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i].mul(check));
            result.accumulate(physical, folded.mulM31(inverses[physical >> @intCast(self.log_size)]));
        }
    }
};
fn pointAt(values: []const Q) !Q {
    if (values.len != 1) return error.InvalidPartitionedDirectMask;
    return values[0];
}
fn pointColumns(a: std.mem.Allocator, count: usize, point: Point) ![][]Point {
    const columns = try a.alloc([]Point, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| a.free(column);
        a.free(columns);
    }
    for (columns) |*column| {
        column.* = try a.dupe(Point, &.{point});
        initialized += 1;
    }
    return columns;
}
fn freePoints(a: std.mem.Allocator, columns: [][]Point) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
