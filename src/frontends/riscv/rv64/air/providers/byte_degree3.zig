//! Separate native2n BYTE table. The legacy4n component remains unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const Old = @import("byte.zig");
const P = @import("../range/provider.zig");
const geometry = @import("../geometry.zig");
const Partition = @import("../full/coset_evaluation.zig").Evaluation;
const cp = engine.air.component_prover;
const acc = engine.air.accumulation;
const air = core.air.components;
const Point = core.circle.CirclePointQM31;
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        base: Old.ComponentFor(Lane),
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, acc.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return P.N_CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.base.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(_: *const Self, i: usize) !u8 {
            if (i >= P.N_CONSTRAINTS) return error.InvalidConstraintIndex;
            return if (i == 2) 3 else 2;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            return self.base.traceLogDegreeBounds(a);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.base.preprocessedColumnIndices(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            return self.base.maskPoints(a, point, global_log);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            return self.base.evaluateConstraintQuotientsAtPoint(point, masks, accumulator, global_log);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            return self.base.evaluateQuotientsAtPointFor(F, point, global_log, masks, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) !void {
            if (self.base.log_size != P.LOG_SIZE or trace.polys.items.len != 3 or trace.polys.items[0].len < self.base.fixed_offset + 3 or trace.polys.items[1].len <= self.base.main_offset or trace.polys.items[2].len < self.base.interaction_offset + 8) return error.InvalidByteDegree3Shape;
            const a = accumulator.allocator;
            var polys: [12]cp.Poly = undefined;
            @memcpy(polys[0..3], trace.polys.items[0][self.base.fixed_offset..][0..3]);
            polys[3] = trace.polys.items[1][self.base.main_offset];
            @memcpy(polys[4..], trace.polys.items[2][self.base.interaction_offset..][0..8]);
            var previous: [12]bool = @splat(false);
            @memset(previous[8..], true);
            var evaluation = try Partition.initDegreeThree(a, &polys, P.LOG_SIZE, &previous);
            defer evaluation.deinit();
            const columns = try accumulator.columns(a, &.{.{ .log_size = P.LOG_SIZE + 1, .n_cols = P.N_CONSTRAINTS }});
            defer a.free(columns);
            var output = columns[0];
            const F = E.PackedBase;
            for (0..2) |part| {
                try evaluation.evaluatePart(part);
                const inverse = try evaluation.denominatorInverse(part);
                var row: usize = 0;
                while (row < evaluation.size) : (row += E.LANES) {
                    var values: [12]F = undefined;
                    for (&values, 0..) |*v, c| v.* = F.load(evaluation.current_values[c].ptr + row);
                    var prior: [4]F = undefined;
                    for (&prior, 0..) |*v, c| {
                        var lanes: [E.LANES]core.fields.m31.M31 = undefined;
                        for (&lanes, 0..) |*x, j| x.* = evaluation.previous_values[8 + c][evaluation.previousRow(part, row + j)];
                        v.* = F.fromLanes(lanes);
                    }
                    var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
                    var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
                    for (P.evaluateFor(F, values[0], values[1], values[2], values[3], E.secureFor(F, &values, 4), E.secureFor(F, &values, 8), E.secureFromCoordinatesFor(F, prior), self.base.claim, self.base.alpha)) |v| sink.emit(v);
                    const coordinates = weighted.accumulation.mulBase(F.fromBase(inverse)).coordinates();
                    const start = evaluation.globalRow(part, row);
                    const fresh = if (output.next_fresh_index) |next| next == start else false;
                    output.next_fresh_index = if (fresh) start + E.LANES else null;
                    for (output.col.columns, coordinates) |column, v| {
                        if (fresh) v.store(column.ptr + start) else F.load(column.ptr + start).add(v).store(column.ptr + start);
                    }
                }
            }
        }
    };
}
pub const Component = ComponentFor(E.Q);
