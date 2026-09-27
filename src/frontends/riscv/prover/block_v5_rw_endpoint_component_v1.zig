//! Endpoint quotient over the same fixed/main PCS roots as sorted memory.
//! Ordering, predecessor links and byte validity are supplied by a separately
//! fresh-verified sorted-memory proof; this adapter constrains the projection.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const prover = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const support = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const trace = @import("../air/block/memory_component_trace.zig");
const endpoint = @import("block_v5_rw_endpoint_interaction_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const F = trace.fixed_column_count;
const I = endpoint.COLUMN_COUNT;
pub const Component = ComponentFor(false);
pub const CompactComponent = ComponentFor(true);
fn ComponentFor(comptime compact: bool) type {
    return struct {
        const W = if (compact) @import("../air/block/memory_component.zig").Layout.linked_previous else trace.main_column_count;
        const N = F + W + I;
        log_size: u32,
        claim: endpoint.Claim,
        elements: *const universal.Elements,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, prover.ComponentProver, prover.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return 4;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 2;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 2;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= 4) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
            const fixed = try logs(a, F, self.log_size);
            errdefer a.free(fixed);
            const main = try logs(a, W, self.log_size);
            errdefer a.free(main);
            const interaction = try logs(a, I, self.log_size);
            errdefer a.free(interaction);
            return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
            if (max_log < self.log_size) return error.InvalidV5EndpointMask;
            const fixed = try pointColumns(a, F, &.{point});
            errdefer freePoints(a, fixed);
            const main = try pointColumns(a, W, &.{point});
            errdefer freePoints(a, main);
            const interaction = try pointColumns(a, I, &.{ point, @import("../air/logup.zig").prevRowPoint(max_log, point) });
            errdefer freePoints(a, interaction);
            return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed, main, interaction }));
        }
        pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
            const indices = try a.alloc(usize, F);
            for (indices, 0..) |*index, i| index.* = i;
            return indices;
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len < 3 or mask.items[0].len != F or mask.items[1].len != W or mask.items[2].len != I or max_log < self.log_size) return error.InvalidV5EndpointMask;
            var fixed: [F]Q = undefined;
            var main: [W]Q = undefined;
            var current: [I]Q = undefined;
            var previous: [I]Q = undefined;
            for (&fixed, 0..) |*out, i| out.* = try pointAt(mask.items[0][i], 0);
            for (&main, 0..) |*out, i| out.* = try pointAt(mask.items[1][i], 0);
            for (&current, &previous, 0..) |*out, *before, i| {
                out.* = try pointAt(mask.items[2][i], 0);
                before.* = try pointAt(mask.items[2][i], 1);
            }
            const equations = try endpoint.constraints(self.elements, try endpoint.point(&fixed, &@import("../air/block/memory_component_stark.zig").expandedMain(main)), current, previous, self.claim, @as(u32, 1) << @intCast(self.log_size));
            const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
            for (equations) |equation| accumulator.accumulate(equation.mul(inverse));
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            if (source.polys.items.len != 3 or source.polys.items[0].len != F or source.polys.items[1].len != W or source.polys.items[2].len != I) return error.InvalidV5EndpointTrees;
            const a = accumulator.allocator;
            const eval_log = self.log_size + 2;
            const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
            const size = domain.size();
            var polys: [N]prover.Poly = undefined;
            for (0..F) |i| polys[i] = source.polys.items[0][i];
            for (0..W) |i| polys[F + i] = source.polys.items[1][i];
            for (0..I) |i| polys[F + W + i] = source.polys.items[2][i];
            var needed: usize = 0;
            for (polys) |poly| needed += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
            const owned = try a.alloc([]M, needed);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |column| a.free(column);
                a.free(owned);
            }
            var values: [N][]const M = undefined;
            for (polys, &values) |poly, *out| out.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
            if (owned.len != 0) {
                var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &twiddles);
                try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
            }
            var inverses: [4]M = undefined;
            const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
            for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, 2))).inv();
            const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 4 }});
            defer a.free(output);
            var result = output[0];
            const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
            for (0..size) |row| {
                const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
                var fixed: [F]Q = undefined;
                var main: [W]Q = undefined;
                var current: [I]Q = undefined;
                var previous: [I]Q = undefined;
                for (&fixed, 0..) |*value, i| value.* = Q.fromBase(values[i][row]);
                for (&main, 0..) |*value, i| value.* = Q.fromBase(values[F + i][row]);
                for (&current, &previous, 0..) |*value, *before, i| {
                    value.* = Q.fromBase(values[F + W + i][row]);
                    before.* = Q.fromBase(values[F + W + i][prior]);
                }
                const equations = try endpoint.constraints(self.elements, try endpoint.point(&fixed, &@import("../air/block/memory_component_stark.zig").expandedMain(main)), current, previous, self.claim, @as(u32, 1) << @intCast(self.log_size));
                var folded = Q.zero();
                const powers = result.random_coeff_powers;
                for (equations, 0..) |equation, i| folded = folded.add(powers[powers.len - 1 - i].mul(equation));
                result.accumulate(row, folded.mulM31(inverses[row >> shift]));
            }
        }
    };
}

fn logs(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    const result = try a.alloc(u32, count);
    @memset(result, log);
    return result;
}
fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingV5EndpointPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const result = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column);
        a.free(result);
    }
    for (result) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}
fn freePoints(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
