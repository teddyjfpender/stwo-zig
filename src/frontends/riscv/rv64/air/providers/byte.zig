//! Independently sized byte provider in the execution proof's three shared trees.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const canonic = core.poly.circle.canonic;
const geometry = @import("../geometry.zig");
const provider = @import("../range/provider.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const points = @import("../../../air/component_point_support.zig");

const lane = @import("../lane.zig");
const E = @import("../evaluation.zig");
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        // The canonical byte table uses log 8. Independently sized lookup consumers
        // share this rational/prefix authority and select their own trace height.
        log_size: u32 = provider.LOG_SIZE,
        fixed_offset: usize,
        main_offset: usize,
        interaction_offset: usize,
        alpha: Lane,
        claim: Lane,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return provider.N_CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 2;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 2;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= provider.N_CONSTRAINTS) return error.InvalidConstraintIndex;
            return if (index == 2) 3 else 2;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            const fixed = try points.emptyOrFilledLogs(a, provider.N_FIXED, self.log_size);
            errdefer a.free(fixed);
            const main = try points.emptyOrFilledLogs(a, provider.N_MAIN, self.log_size);
            errdefer a.free(main);
            const interaction = try points.emptyOrFilledLogs(a, provider.N_INTERACTION, self.log_size);
            errdefer a.free(interaction);
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const indices = try a.alloc(usize, provider.N_FIXED);
            for (indices, 0..) |*index, i| index.* = self.fixed_offset + i;
            return indices;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            const fixed = try points.currentPointColumns(a, provider.N_FIXED, point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, provider.N_MAIN, point);
            errdefer points.freePointColumns(a, main);
            const interaction = try points.currentPointColumns(a, provider.N_INTERACTION, point);
            errdefer points.freePointColumns(a, interaction);
            for (interaction[4..]) |*column| {
                const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(column.*);
                column.* = replacement;
            }
            return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = accumulator };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidByteProviderShape else err;
        }
        /// Lane-generic point evaluation. Mask map: fixed[fixed_offset + {0,1,2}]
        /// (value, first, last) sample 0; main[main_offset] sample 0;
        /// interaction[interaction_offset + i] sample 0 (i < 4) or samples 0/1 (i >= 4).
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("byte provider lane mismatch");
            const value = try lane.sample(F, masks, 0, self.fixed_offset, 0, 1);
            const first = try lane.sample(F, masks, 0, self.fixed_offset + 1, 0, 1);
            const last = try lane.sample(F, masks, 0, self.fixed_offset + 2, 0, 1);
            const multiplicity = try lane.sample(F, masks, 1, self.main_offset, 0, 1);
            const inverse = try lane.secureSample(F, masks, 2, self.interaction_offset, 0, 1);
            const sum = try lane.secureSample(F, masks, 2, self.interaction_offset + 4, 0, 2);
            const previous = try lane.secureSample(F, masks, 2, self.interaction_offset + 4, 1, 2);
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            for (provider.evaluateFor(F, value, first, last, multiplicity, inverse, sum, previous, self.claim, self.alpha)) |residual| sink.emit(residual);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.fixed_offset + 3 or trace.polys.items[1].len <= self.main_offset or trace.polys.items[2].len < self.interaction_offset + 8) return error.InvalidByteProviderShape;
            const a = accumulator.allocator;
            const eval_log = self.log_size + 2;
            const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
            const size = domain.size();
            var polys: [12]cp.Poly = undefined;
            @memcpy(polys[0..3], trace.polys.items[0][self.fixed_offset..][0..3]);
            polys[3] = trace.polys.items[1][self.main_offset];
            @memcpy(polys[4..], trace.polys.items[2][self.interaction_offset..][0..8]);
            var owned_count: usize = 0;
            for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
            const owned = try a.alloc([]M, owned_count);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |column| a.free(column);
                a.free(owned);
            }
            var evaluations: [12][]const M = undefined;
            for (polys, &evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
            if (owned.len != 0) {
                var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &twiddles);
                try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
            }
            const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
            defer a.free(inverses);
            const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = provider.N_CONSTRAINTS }});
            defer a.free(columns);
            var output = columns[0];
            for (0..size) |row| {
                const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
                const residuals = provider.evaluate(Q.fromBase(evaluations[0][row]), Q.fromBase(evaluations[1][row]), Q.fromBase(evaluations[2][row]), Q.fromBase(evaluations[3][row]), points.secureAt(evaluations[4..8], row), points.secureAt(evaluations[8..12], row), points.secureAt(evaluations[8..12], prior), self.claim, self.alpha);
                var folded = Q.zero();
                for (residuals, 0..) |value, i| folded = folded.add(output.random_coeff_powers[provider.N_CONSTRAINTS - 1 - i].mul(value));
                output.accumulate(row, folded.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.log_size))]));
            }
        }
    };
}
pub const Component = ComponentFor(Q);
