//! PCS adapter for the versioned caller-only geometry frame, with no LogUp.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frame = @import("block_v5_native_frame_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const components = core.air.components;
const prover = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const canonic = core.poly.circle.canonic;
pub const Component = struct {
    expected: frame.Expected,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover.ComponentProver, prover.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Self) prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return frame.N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(_: *const Self) u32 {
        return frame.LOG_SIZE + 1;
    }
    pub fn traceLogDegreeBounds(_: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, &.{frame.LOG_SIZE});
        errdefer a.free(fixed);
        const main = try a.dupe(u32, &([_]u32{frame.LOG_SIZE} ** frame.MAIN_COLUMNS));
        errdefer a.free(main);
        const interaction = try a.dupe(u32, &.{frame.LOG_SIZE});
        errdefer a.free(interaction);
        return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(_: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !components.MaskPoints {
        if (max_log < frame.LOG_SIZE) return error.InvalidV5NativeFrameMask;
        const fixed = try pointColumns(a, frame.FIXED_COLUMNS, point);
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, frame.MAIN_COLUMNS, point);
        errdefer freePoints(a, main);
        const interaction = try pointColumns(a, frame.INTERACTION_COLUMNS, point);
        errdefer freePoints(a, interaction);
        return components.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
        return a.dupe(usize, &.{0});
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < frame.LOG_SIZE or mask.items.len < 3 or
            mask.items[0].len != frame.FIXED_COLUMNS or mask.items[1].len != frame.MAIN_COLUMNS or
            mask.items[2].len != frame.INTERACTION_COLUMNS) return error.InvalidV5NativeFrameMask;
        const selector = try pointAt(mask.items[0][0]);
        var row: [frame.MAIN_COLUMNS]Q = undefined;
        for (&row, mask.items[1]) |*value, column| value.* = try pointAt(column);
        const checks = frame.evaluateGeneric(Q, selector, row, try pointAt(mask.items[2][0]), frame.symbols(Q, self.expected));
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(frame.LOG_SIZE).coset(), point.repeatedDouble(max_log - frame.LOG_SIZE)).inv();
        for (checks) |check| accumulator.accumulate(check.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len != frame.FIXED_COLUMNS or
            trace.polys.items[1].len != frame.MAIN_COLUMNS or trace.polys.items[2].len != frame.INTERACTION_COLUMNS)
            return error.InvalidV5NativeFrameTrees;
        const a = accumulator.allocator;
        const eval_log = frame.LOG_SIZE + 1;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        var polys: [frame.FIXED_COLUMNS + frame.MAIN_COLUMNS + frame.INTERACTION_COLUMNS]prover.Poly = undefined;
        polys[0] = trace.polys.items[0][0];
        @memcpy(polys[1 .. 1 + frame.MAIN_COLUMNS], trace.polys.items[1]);
        polys[polys.len - 1] = trace.polys.items[2][0];
        var owned_count: usize = 0;
        for (polys) |poly| {
            try poly.validate();
            owned_count += @intFromBool(poly.log_size != eval_log);
        }
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var values: [polys.len][]const M = undefined;
        for (polys, &values) |poly, *out| out.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, frame.LOG_SIZE, eval_log, eval_size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        var inverses: [2]M = undefined;
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, canonic.CanonicCoset.new(frame.LOG_SIZE).coset(), domain.at(core.utils.bitReverseIndex(i, 1))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = frame.N_CONSTRAINTS }});
        defer a.free(output);
        var result = output[0];
        const pinned = frame.symbols(Q, self.expected);
        for (0..eval_size) |physical| {
            var row: [frame.MAIN_COLUMNS]Q = undefined;
            for (&row, values[1 .. 1 + frame.MAIN_COLUMNS]) |*value, column| value.* = Q.fromBase(column[physical]);
            const checks = frame.evaluateGeneric(Q, Q.fromBase(values[0][physical]), row, Q.fromBase(values[values.len - 1][physical]), pinned);
            var folded = Q.zero();
            for (checks, 0..) |check, i| folded = folded.add(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i].mul(check));
            result.accumulate(physical, folded.mulM31(inverses[physical >> frame.LOG_SIZE]));
        }
    }
};

fn pointAt(values: []const Q) !Q {
    if (values.len != 1) return error.InvalidV5NativeFrameMask;
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
