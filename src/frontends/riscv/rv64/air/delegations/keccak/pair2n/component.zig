//! Concrete native2n adapter; mixed polynomial authority lives in equations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const V = @import("../../../evaluation.zig");
const lane = @import("../../../lane.zig");
const geometry = @import("../../../geometry.zig");
const points = @import("../../../../../air/component_point_support.zig");
const K = @import("../layout.zig");
const Base = @import("../component.zig");
const E = @import("../equations.zig");
const L = @import("layout.zig");
const Pair = @import("equations.zig");
const Eval = @import("../../../full/coset_evaluation.zig").Evaluation;
pub const Component = struct {
    kind: Base.Kind,
    log_size: u32,
    calls: u32 = 0,
    first_call_id: u32 = 1,
    offsets: Base.Offsets = .{},
    challenges: E.Challenges,
    claim: Q,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn validate(self: *const Component) !void {
        switch (self.kind) {
            .permutation => try K.validateGeometry(self.calls, self.first_call_id, self.log_size),
            .chi => if (self.log_size != 13 or self.calls != 0) return error.InvalidKeccakComponentGeometry,
            .xor5 => if (self.log_size != 10 or self.calls != 0) return error.InvalidKeccakComponentGeometry,
        }
    }
    pub fn fixedCount(self: *const Component) usize {
        return if (self.kind == .permutation) L.FIXED else 7;
    }
    pub fn mainCount(self: *const Component) usize {
        return if (self.kind == .permutation) L.MAIN else 1;
    }
    pub fn interactionCount(self: *const Component) usize {
        return if (self.kind == .permutation) L.INTERACTION else 4;
    }
    pub fn nConstraints(self: *const Component) usize {
        return if (self.kind == .permutation) L.CONSTRAINTS else 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return if (self.kind == .permutation) 3 else 2;
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var out = Adapter.asProverComponent(self);
        out.domain_parallel_evaluator = evaluateParallel;
        out.pool_exclusive_domain = self.kind == .permutation;
        return out;
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.domain(trace, acc, pool);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        try self.validate();
        const f = try points.emptyOrFilledLogs(a, self.fixedCount(), self.log_size);
        errdefer a.free(f);
        const m = try points.emptyOrFilledLogs(a, self.mainCount(), self.log_size);
        errdefer a.free(m);
        const i = try points.emptyOrFilledLogs(a, self.interactionCount(), self.log_size);
        errdefer a.free(i);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ f, m, i }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.fixedCount());
        for (out, 0..) |*v, c| v.* = self.offsets.fixed + c;
        return out;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        try self.validate();
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const f = try points.currentPointColumns(a, self.fixedCount(), point);
        errdefer points.freePointColumns(a, f);
        const m = try points.currentPointColumns(a, self.mainCount(), point);
        errdefer points.freePointColumns(a, m);
        const i = try points.currentPointColumns(a, self.interactionCount(), point);
        errdefer points.freePointColumns(a, i);
        const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
        const lifted = Point{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) };
        if (self.kind == .permutation) {
            for (m[0..K.STATE]) |*column| {
                var samples: [5]Point = undefined;
                for (&samples, K.MASK_OFFSETS) |*p, offset| p.* = point.add(lifted.mulSigned(offset));
                const replacement = try a.dupe(Point, &samples);
                a.free(column.*);
                column.* = replacement;
            }
            for (m[K.ACTIVE_A..K.MAIN]) |*column| {
                const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(column.*);
                column.* = replacement;
            }
        }
        for (i[i.len - 4 ..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ f, m, i }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, masks: *const air.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        var sink = V.Sink{ .values = null, .accumulator = acc };
        try self.evaluatePointFor(Q, point, global_log, lane.NativeMasks{ .values = masks }, self.challenges, .{ .calls = self.calls, .first_id = self.first_call_id }, self.claim, &sink);
    }
    /// Circuit callers supply challenge/public wires explicitly; no native Q
    /// constants are captured by the lane-generic polynomial authority.
    pub fn evaluatePointFor(self: *const Component, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, ch: E.ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), claim: V.ConstFor(F), sink: *V.SinkFor(F)) !void {
        if (comptime !V.isExternalLane(F)) try self.validate();
        sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
        const f = self.offsets.fixed;
        const m = self.offsets.main;
        const i = self.offsets.interaction;
        const previous = try lane.secureSample(F, masks, 2, i + self.interactionCount() - 4, 1, 2);
        if (self.kind != .permutation) {
            var tuple: [6]F = undefined;
            for (&tuple, 0..) |*v, c| v.* = try lane.sample(F, masks, 0, f + c, 0, 1);
            sink.emit(Base.tableResidualFor(F, .{ .kind = self.kind, .challenges = ch, .claim = claim }, &tuple, try lane.sample(F, masks, 0, f + 6, 0, 1), try lane.sample(F, masks, 1, m, 0, 1), try lane.secureSample(F, masks, 2, i, 0, 2), previous));
            return;
        }
        var scratch: ScratchFor(F) = undefined;
        for (&scratch.fixed, 0..) |*v, c| v.* = try lane.sample(F, masks, 0, f + c, 0, 1);
        for (&scratch.main, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + c, 0, if (c < K.STATE) 5 else if (c >= K.ACTIVE_A and c < K.MAIN) 2 else 1);
        for (&scratch.shifted, 1..) |*state, sample| for (state, 0..) |*v, c| {
            v.* = try lane.sample(F, masks, 1, m + c, sample, 5);
        };
        for (&scratch.previous_header, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + K.ACTIVE_A + c, 1, 2);
        for (&scratch.interaction, 0..) |*v, c| v.* = try lane.secureSample(F, masks, 2, i + 4 * c, 0, if (c == L.PAIRS) 2 else 1);
        Pair.emitFor(F, scratch.row(), &scratch.interaction, previous, claim, ch, public, sink);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        return self.domain(trace, acc, null);
    }
    fn domain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        const a = acc.allocator;
        const counts = [_]usize{ self.fixedCount(), self.mainCount(), self.interactionCount() };
        const offsets = [_]usize{ self.offsets.fixed, self.offsets.main, self.offsets.interaction };
        if (trace.polys.items.len != 3) return error.InvalidKeccakTraceShape;
        const total = counts[0] + counts[1] + counts[2];
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        var at: usize = 0;
        for (counts, offsets, trace.polys.items) |count, offset, columns| {
            if (offset > columns.len or count > columns.len - offset) return error.InvalidKeccakTraceShape;
            @memcpy(polys[at..][0..count], columns[offset..][0..count]);
            at += count;
        }
        const previous = try a.alloc(bool, total);
        defer a.free(previous);
        @memset(previous, false);
        if (self.kind == .permutation) {
            @memset(previous[L.FIXED..][0..K.STATE], true);
            @memset(previous[L.FIXED + K.ACTIVE_A ..][0..3], true);
        }
        @memset(previous[total - 4 ..], true);
        var evaluation = try Eval.initDegreeThree(a, polys, self.log_size, previous);
        defer evaluation.deinit();
        const outputs = try acc.columns(a, &.{.{ .log_size = self.log_size + 1, .n_cols = self.nConstraints() }});
        defer a.free(outputs);
        var output = outputs[0];
        for (0..2) |part| {
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_pair2n_fft", "Keccak pair2n quotient coset FFT");
                defer stage.end();
                try evaluation.evaluatePartWithPool(part, pool);
            }
            const inverse = try evaluation.denominatorInverse(part);
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_pair2n_rows", "Keccak pair2n quotient rows");
                defer stage.end();
                try @import("parallel.zig").evaluate(self, &evaluation, part, &output, inverse, pool);
            }
        }
    }
};
pub fn ScratchFor(comptime F: type) type {
    return struct {
        fixed: [L.FIXED]F,
        main: [L.MAIN]F,
        shifted: [4][K.STATE]F,
        previous_header: [3]F,
        interaction: [L.PAIRS + 1]V.SecureFor(F),
        pub fn row(self: *const @This()) Pair.RowFor(F) {
            return .{ .base = .{ .fixed = &self.fixed, .main = self.main[0..K.MAIN], .previous_header = &self.previous_header, .state_minus_two = &self.shifted[0], .state_minus_one = &self.shifted[1], .state_plus_one = &self.shifted[2], .state_plus_two = &self.shifted[3] }, .round_enable = self.main[L.ROUND_ENABLE], .io_enable = self.main[L.IO_ENABLE] };
        }
    };
}
