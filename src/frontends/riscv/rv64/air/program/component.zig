//! Concrete program provider in the same three trees/FRI as execution and range.
//! Offsets identify slices in shared trees; preprocessing remains receiver-owned.
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
const provider = @import("provider.zig");
const rom = @import("setup.zig");
const compact = @import("compact.zig");
const packed_control = @import("packed_control.zig");
const E = @import("../evaluation.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const points = @import("../../../air/component_point_support.zig");
pub const FIXED = rom.field.COUNT + 2;
const TOTAL = FIXED + 1 + provider.INTERACTION;

const lane = @import("../lane.zig");
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        log_size: u32,
        encoding: enum { full155, compact41, packed26 } = .full155,
        fixed_offset: usize,
        main_offset: usize,
        interaction_offset: usize,
        challenges: provider.ChallengesFor(Lane),
        claim: Lane,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return provider.CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 2;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 2;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= provider.CONSTRAINTS) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            const fixed = try points.emptyOrFilledLogs(a, self.fixedCount(), self.log_size);
            errdefer a.free(fixed);
            const main = try points.emptyOrFilledLogs(a, 1, self.log_size);
            errdefer a.free(main);
            const interaction = try points.emptyOrFilledLogs(a, provider.INTERACTION, self.log_size);
            errdefer a.free(interaction);
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const result = try a.alloc(usize, self.fixedCount());
            for (result, 0..) |*value, i| value.* = self.fixed_offset + i;
            return result;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            const fixed = try points.currentPointColumns(a, self.fixedCount(), point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, 1, point);
            errdefer points.freePointColumns(a, main);
            const interaction = try points.currentPointColumns(a, provider.INTERACTION, point);
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
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidRv64RomShape else err;
        }
        /// Lane-generic point evaluation (lane.zig accessor contract). Mask map:
        /// fixed[fixed_offset + i], i < fixedCount(), sample 0; main[main_offset]
        /// sample 0; interaction[interaction_offset + i] sample 0 (i < 4) or
        /// samples 0/1 (i >= 4, previous row). The sink's scale is set here.
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("ROM provider lane mismatch");
            if (self.log_size < 5 or self.log_size > 22) return error.InvalidRv64MaskShape;
            const count = self.tupleCount();
            const denominator = switch (self.encoding) {
                .packed26 => blk: {
                    var entry: [packed_control.COUNT]F = undefined;
                    for (&entry, 0..) |*value, i| value.* = try lane.sample(F, masks, 0, self.fixed_offset + i, 0, 1);
                    break :blk packed_control.denominatorFor(F, self.challenges, &entry);
                },
                .compact41 => blk: {
                    var entry: [compact.COUNT]F = undefined;
                    for (&entry, 0..) |*value, i| value.* = try lane.sample(F, masks, 0, self.fixed_offset + i, 0, 1);
                    break :blk compact.denominatorFor(F, self.challenges, &entry);
                },
                .full155 => blk: {
                    var entry: [rom.field.COUNT]F = undefined;
                    for (&entry, 0..) |*value, i| value.* = try lane.sample(F, masks, 0, self.fixed_offset + i, 0, 1);
                    break :blk E.denominatorFor(F, self.challenges.offset, &self.challenges.coefficients, &entry, false);
                },
            };
            var current: [provider.INTERACTION]F = undefined;
            var previous: [provider.INTERACTION]F = @splat(F.zero());
            for (&current, 0..) |*value, i| {
                value.* = try lane.sample(F, masks, 2, self.interaction_offset + i, 0, if (i < 4) 1 else 2);
                if (i >= 4) previous[i] = try lane.sample(F, masks, 2, self.interaction_offset + i, 1, 2);
            }
            const first = try lane.sample(F, masks, 0, self.fixed_offset + count, 0, 1);
            const last = try lane.sample(F, masks, 0, self.fixed_offset + count + 1, 0, 1);
            const multiplicity = try lane.sample(F, masks, 1, self.main_offset, 0, 1);
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            provider.evaluateDenominatorFor(F, first, last, denominator, multiplicity, &current, &previous, self.claim, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            if (trace.polys.items.len != 3) return error.InvalidRv64RomShape;
            try self.checkShape(trace.polys.items[0].len, trace.polys.items[1].len, trace.polys.items[2].len);
            const a = accumulator.allocator;
            const eval_log = self.log_size + 2;
            const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
            const size = domain.size();
            const n_fixed = self.fixedCount();
            const total = n_fixed + 1 + provider.INTERACTION;
            var polynomial_storage: [TOTAL]cp.Poly = undefined;
            const polys = polynomial_storage[0..total];
            @memcpy(polys[0..n_fixed], trace.polys.items[0][self.fixed_offset..][0..n_fixed]);
            polys[n_fixed] = trace.polys.items[1][self.main_offset];
            @memcpy(polys[n_fixed + 1 ..], trace.polys.items[2][self.interaction_offset..][0..provider.INTERACTION]);
            var owned_count: usize = 0;
            for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
            const owned = try a.alloc([]M, owned_count);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |column| a.free(column);
                a.free(owned);
            }
            var evaluation_storage: [TOTAL][]const M = undefined;
            const evaluations = evaluation_storage[0..total];
            for (polys, evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
            if (owned.len != 0) {
                var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &twiddles);
                try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
            }
            const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
            defer a.free(inverses);
            const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = provider.CONSTRAINTS }});
            defer a.free(columns);
            var output = columns[0];
            for (0..size) |row| {
                const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
                const denominator = if (self.encoding == .packed26) blk: {
                    var entry: packed_control.Tuple = undefined;
                    for (&entry, 0..) |*value, i| value.* = Q.fromBase(evaluations[i][row]);
                    break :blk packed_control.denominator(self.challenges, &entry);
                } else blk: {
                    var entry: rom.Tuple = @splat(Q.zero());
                    for (0..self.tupleCount()) |i| entry[self.sourceIndex(i)] = Q.fromBase(evaluations[i][row]);
                    break :blk self.challenges.denominator(&entry);
                };
                var current: [provider.INTERACTION]Q = undefined;
                var previous: [provider.INTERACTION]Q = @splat(Q.zero());
                for (&current, evaluations[n_fixed + 1 ..], 0..) |*value, column, i| {
                    value.* = Q.fromBase(column[row]);
                    if (i >= 4) previous[i] = Q.fromBase(column[prior]);
                }
                var residuals: [provider.CONSTRAINTS]Q = undefined;
                var sink = E.Sink{ .values = &residuals };
                provider.evaluateDenominator(Q.fromBase(evaluations[self.tupleCount()][row]), Q.fromBase(evaluations[self.tupleCount() + 1][row]), denominator, Q.fromBase(evaluations[n_fixed][row]), &current, &previous, self.claim, &sink);
                var folded = Q.zero();
                for (residuals, 0..) |value, i| folded = folded.add(output.random_coeff_powers[provider.CONSTRAINTS - 1 - i].mul(value));
                output.accumulate(row, folded.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.log_size))]));
            }
        }
        pub fn tupleCount(self: *const Self) usize {
            return switch (self.encoding) {
                .full155 => rom.field.COUNT,
                .compact41 => compact.COUNT,
                .packed26 => packed_control.COUNT,
            };
        }
        fn sourceIndex(self: *const Self, i: usize) usize {
            return switch (self.encoding) {
                .full155 => i,
                .compact41 => compact.fields[i],
                .packed26 => packed_control.sources[i].start,
            };
        }
        pub fn fixedCount(self: *const Self) usize {
            return self.tupleCount() + 2;
        }
        fn checkShape(self: *const Self, fixed: usize, main: usize, interaction: usize) !void {
            if (self.log_size < 5 or self.log_size > 22 or fixed < try points.checkedEnd(self.fixed_offset, self.fixedCount()) or main < try points.checkedEnd(self.main_offset, 1) or interaction < try points.checkedEnd(self.interaction_offset, provider.INTERACTION)) return error.InvalidRv64RomShape;
        }
    };
}
pub const Component = ComponentFor(Q);
