//! Static quotient adapter shared by independently planned packed memory
//! and its range16 provider. Source widths/degree are selected by trusted ABI.
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
pub fn For(comptime Spec: type) type {
    const F = Spec.FIXED_COUNT;
    const W = Spec.MAIN_COUNT;
    const I = Spec.INTERACTION_COUNT;
    return struct {
        const N = F + W + I;
        log_size: u32,
        spec: Spec,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, prover.ComponentProver, prover.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) prover.ComponentProver {
            var result = Adapter.asProverComponent(self);
            if (@hasDecl(Spec, "exportSecurePolynomial")) result.secure_polynomial_capability_v1 = .{ .context = self, .kind = Spec.SECURE_POLYNOMIAL_KIND, .trace_log = self.log_size, .export_program = exportSecurePolynomial };
            result.domain_parallel_evaluator = evaluateParallel;
            result.pool_exclusive_domain = true;
            return result;
        }
        fn exportSecurePolynomial(raw: *const anyopaque, a: std.mem.Allocator) !engine.air.secure_polynomial_program_v1.Program {
            const self: *const Self = @ptrCast(@alignCast(raw));
            if (comptime @hasDecl(Spec, "exportSecurePolynomial")) return self.spec.exportSecurePolynomial(a, @as(u32, 1) << @intCast(self.log_size));
            return error.SecurePolynomialExportUnavailable;
        }
        fn evaluateParallel(raw: *const anyopaque, source: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) !void {
            const self: *const Self = @ptrCast(@alignCast(raw));
            try self.evaluateDomain(source, accumulator, pool);
        }
        pub fn asVerifierComponent(self: *const Self) components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return Spec.CONSTRAINT_COUNT;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + Spec.EXPANSION_BITS;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return Spec.EXPANSION_BITS;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= Spec.CONSTRAINT_COUNT) return error.InvalidConstraintIndex;
            return Spec.DEGREE;
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
            return staticMaskPoints(self.log_size, a, point, max_log);
        }
        /// Exact original Spec masks without constructing a Spec value.
        pub fn staticMaskPoints(log_size: u32, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
            if (max_log < log_size) return error.InvalidV5WordMask;
            const fixed = try pointColumns(a, F, &.{point});
            errdefer freePoints(a, fixed);
            const main = try mainPoints(a, point, @import("../air/logup.zig").prevRowPoint(max_log, point));
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
            if (mask.items.len < 3 or mask.items[0].len != F or mask.items[1].len != W or mask.items[2].len != I or max_log < self.log_size) return error.InvalidV5WordMask;
            var fixed: [F]Q = undefined;
            var main: [W]Q = undefined;
            var prior_main: [W]Q = @splat(Q.zero());
            var current: [I]Q = undefined;
            var previous: [I]Q = undefined;
            for (&fixed, 0..) |*out, i| {
                if (mask.items[0][i].len != 1) return error.InvalidV5WordMask;
                out.* = try pointAt(mask.items[0][i], 0);
            }
            for (0..W) |i| {
                const wanted: usize = if (Spec.PREVIOUS_MAIN_MASK[i]) 2 else 1;
                if (mask.items[1][i].len != wanted) return error.InvalidV5WordMask;
                main[i] = try pointAt(mask.items[1][i], 0);
                if (Spec.PREVIOUS_MAIN_MASK[i]) prior_main[i] = try pointAt(mask.items[1][i], 1);
            }
            for (&current, &previous, 0..) |*out, *before, i| {
                if (mask.items[2][i].len != 2) return error.InvalidV5WordMask;
                out.* = try pointAt(mask.items[2][i], 0);
                before.* = try pointAt(mask.items[2][i], 1);
            }
            const equations = try self.spec.evaluate(fixed, main, prior_main, current, previous, @as(u32, 1) << @intCast(self.log_size));
            const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
            for (equations) |equation| accumulator.accumulate(equation.mul(inverse));
        }
        fn mainPoints(a: std.mem.Allocator, current: circle.CirclePointQM31, previous: circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
            const result = try a.alloc([]circle.CirclePointQM31, W);
            var initialized: usize = 0;
            errdefer {
                for (result[0..initialized]) |column| a.free(column);
                a.free(result);
            }
            for (0..W) |i| {
                result[i] = try a.dupe(circle.CirclePointQM31, if (Spec.PREVIOUS_MAIN_MASK[i]) &.{ current, previous } else &.{current});
                initialized += 1;
            }
            return result;
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(source, accumulator, engine.work_pool.getGlobalPool());
        }
        fn evaluateDomain(self: *const Self, source: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            if (source.polys.items.len != 3 or source.polys.items[0].len != F or source.polys.items[1].len != W or source.polys.items[2].len != I) return error.InvalidV5WordTrees;
            const a = accumulator.allocator;
            const eval_log = self.log_size + Spec.EXPANSION_BITS;
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
            var inverses: [1 << Spec.EXPANSION_BITS]M = undefined;
            const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
            for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, Spec.EXPANSION_BITS))).inv();
            const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = Spec.CONSTRAINT_COUNT }});
            defer a.free(output);
            var result = output[0];
            const prepared = try self.spec.prepareDomain(@as(u32, 1) << @intCast(self.log_size));
            try @import("block_v5_word_domain_rows_v1.zig").For(Spec).evaluateWithPool(prepared, &values, &inverses, self.log_size, eval_log, &result, pool);
        }
    };
}

fn logs(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    const result = try a.alloc(u32, count);
    @memset(result, log);
    return result;
}
fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingV5WordPoint;
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
