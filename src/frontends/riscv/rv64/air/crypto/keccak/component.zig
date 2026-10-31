//! Concrete permutation/table adapter sharing one three-tree PCS transaction.
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
const L = @import("layout.zig");
const E = @import("equations.zig");
const V = @import("../../evaluation.zig");
const Sink = V.Sink;
const lane = @import("../../lane.zig");
const geometry = @import("../../geometry.zig");
const cosets = @import("../../full/coset_evaluation.zig");
const points = @import("../../../../air/component_point_support.zig");
pub const Kind = enum { permutation, chi, xor5 };
pub const Offsets = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        kind: Kind,
        log_size: u32,
        calls: V.CountFor(Lane) = V.countDefault(Lane, 0),
        first_call_id: V.CountFor(Lane) = V.countDefault(Lane, 1),
        /// External lanes supply the derived `calls != 0` wire here.
        calls_nonzero: V.FlagFor(Lane) = V.flagDefault(Lane),
        offsets: Offsets = .{},
        challenges: E.ChallengesFor(Lane),
        claim: Lane,
        stage_recorder: ?*engine.stage_profile.Recorder = null,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn parameters(self: *const Self) Parameters {
            return .{ .kind = self.kind, .log_size = self.log_size, .calls = self.calls, .first_call_id = self.first_call_id, .offsets = self.offsets, .challenges = self.challenges, .claim = self.claim, .stage_recorder = self.stage_recorder, .batches = L.BATCHES, .lookup_degree = 4, .emit_q = emitTripleQ };
        }
        pub fn proverParameters(self: *const Self) Parameters {
            var result = self.parameters();
            result.emit_packed = emitTriplePacked;
            result.legacy_gather = true;
            return result;
        }
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallelErased;
            result.pool_exclusive_domain = self.kind == .permutation;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            const parameters_value = self.proverParameters();
            return parameters_value.evaluateDomain(trace, accumulator, pool);
        }
        pub fn validate(self: *const Self) !void {
            const p = self.parameters();
            return p.validate();
        }
        pub fn fixedCount(self: *const Self) usize {
            return if (self.kind == .permutation) L.FIXED else 7;
        }
        pub fn mainCount(self: *const Self) usize {
            return if (self.kind == .permutation) L.MAIN else 1;
        }
        pub fn interactionCount(self: *const Self) usize {
            return if (self.kind == .permutation) 4 * L.BATCHES else 4;
        }
        pub fn nConstraints(self: *const Self) usize {
            return if (self.kind == .permutation) L.DIRECT + L.BATCHES else 1;
        }
        fn callSpan(self: *const Self) !V.CallSpanFor(Lane) {
            if (comptime V.isExternalLane(Lane)) return .{ .calls = self.calls, .first_id = self.first_call_id, .nonempty = self.calls_nonzero orelse return error.MissingRv64LaneFlag };
            return .{ .calls = self.calls, .first_id = self.first_call_id };
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            const p = self.parameters();
            return p.maxConstraintLogDegreeBound();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            const p = self.parameters();
            return p.compositionLogSplit();
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            const p = self.parameters();
            return p.constraintDegreeBound(index);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            const p = self.parameters();
            return p.traceLogDegreeBounds(a);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const p = self.parameters();
            return p.preprocessedColumnIndices(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            const p = self.parameters();
            return p.maskPoints(a, point, global_log);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = Sink{ .values = null, .accumulator = accumulator };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidKeccakMaskShape else err;
            std.debug.assert(sink.count == self.nConstraints());
        }
        /// Lane-generic triple-batched point evaluation. Mask map: fixed[fixed + c]
        /// sample 0; permutation main[main + c] samples [0,-2,-1,+1,+2] for
        /// c < L.STATE (sample k = offset MASK_OFFSETS[k]), samples 0/1 for the
        /// header columns c >= L.ACTIVE_A, sample 0 otherwise; tables main[main]
        /// sample 0; interaction[interaction + i] sample 0, plus sample 1 for the
        /// last four columns.
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *V.SinkFor(F)) !void {
            comptime if (V.ConstFor(F) != Lane) @compileError("Keccak component lane mismatch");
            if (comptime !V.isExternalLane(F)) try self.validate();
            const f = self.offsets.fixed;
            const m = self.offsets.main;
            const i = self.offsets.interaction;
            const inter_count = self.interactionCount();
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            const previous = try lane.secureSample(F, masks, 2, i + inter_count - 4, 1, 2);
            if (self.kind != .permutation) {
                var tuple: [6]F = undefined;
                for (&tuple, 0..) |*v, c| v.* = try lane.sample(F, masks, 0, f + c, 0, 1);
                const first = try lane.sample(F, masks, 0, f + 6, 0, 1);
                const count = try lane.sample(F, masks, 1, m, 0, 1);
                const current = try lane.secureSample(F, masks, 2, i, 0, 2);
                sink.emit(tableResidualFor(F, self, &tuple, first, count, current, previous));
                return;
            }
            var scratch: ScratchFor(F) = undefined;
            for (&scratch.fixed, 0..) |*v, c| v.* = try lane.sample(F, masks, 0, f + c, 0, 1);
            for (&scratch.main, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + c, 0, if (c < L.STATE) 5 else if (c >= L.ACTIVE_A) 2 else 1);
            for (&scratch.shifted, 1..) |*state, sample_index| for (state, 0..) |*v, c| {
                v.* = try lane.sample(F, masks, 1, m + c, sample_index, 5);
            };
            for (&scratch.previous_header, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + L.ACTIVE_A + c, 1, 2);
            for (&scratch.interaction, 0..) |*v, batch| v.* = try lane.secureSample(F, masks, 2, i + 4 * batch, 0, if (4 * batch + 4 >= inter_count) 2 else 1);
            E.emitFor(F, scratch.row(), &scratch.interaction, previous, self.claim, self.challenges, try self.callSpan(), sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            const p = self.proverParameters();
            return p.evaluateDomain(trace, accumulator, null);
        }
    };
}
pub const Component = ComponentFor(Q);
fn emitTripleQ(row: E.Row, interaction: []const Q, prior: Q, claim: Q, ch: E.Challenges, public: E.Public, sink: *Sink) void {
    E.emit(row, interaction, prior, claim, ch, public, sink);
}
fn emitTriplePacked(row: E.RowFor(@import("../../evaluation.zig").PackedBase), interaction: []const @import("../../evaluation.zig").PackedSecure, prior: @import("../../evaluation.zig").PackedSecure, claim: Q, ch: E.Challenges, public: E.Public, sink: *@import("../../evaluation.zig").PackedSink) void {
    E.emitFor(@import("../../evaluation.zig").PackedBase, row, interaction, prior, claim, ch, public, sink);
}
pub const ScalarEmitter = *const fn (E.Row, []const Q, Q, Q, E.Challenges, E.Public, *Sink) void;
pub const PackedEmitter = *const fn (E.RowFor(@import("../../evaluation.zig").PackedBase), []const @import("../../evaluation.zig").PackedSecure, @import("../../evaluation.zig").PackedSecure, Q, E.Challenges, E.Public, *@import("../../evaluation.zig").PackedSink) void;
/// Concrete K geometry and row callbacks shared by the two explicit adapters.
/// Read-only verifier descriptors never refer to a packed prover kernel.
pub const Parameters = struct {
    kind: Kind,
    log_size: u32,
    calls: u32 = 0,
    first_call_id: u32 = 1,
    offsets: Offsets = .{},
    challenges: E.Challenges,
    claim: Q,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    batches: usize,
    lookup_degree: u8,
    emit_q: ScalarEmitter,
    emit_packed: ?PackedEmitter = null,
    legacy_gather: bool = false,
    pub fn validate(self: *const Parameters) !void {
        switch (self.kind) {
            .permutation => try L.validateGeometry(self.calls, self.first_call_id, self.log_size),
            .chi => if (self.log_size != 13 or self.calls != 0) return error.InvalidKeccakComponentGeometry,
            .xor5 => if (self.log_size != 10 or self.calls != 0) return error.InvalidKeccakComponentGeometry,
        }
    }
    pub fn fixedCount(self: *const Parameters) usize {
        return if (self.kind == .permutation) L.FIXED else 7;
    }
    pub fn mainCount(self: *const Parameters) usize {
        return if (self.kind == .permutation) L.MAIN else 1;
    }
    pub fn interactionCount(self: *const Parameters) usize {
        return if (self.kind == .permutation) 4 * self.batches else 4;
    }
    pub fn nConstraints(self: *const Parameters) usize {
        return if (self.kind == .permutation) L.DIRECT + self.batches else 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Parameters) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Parameters) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(self: *const Parameters, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        if (self.kind != .permutation) return 2;
        return if (index < L.DIRECT) 4 else self.lookup_degree;
    }
    pub fn traceLogDegreeBounds(self: *const Parameters, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        try self.validate();
        const fixed = try points.emptyOrFilledLogs(a, self.fixedCount(), self.log_size);
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, self.mainCount(), self.log_size);
        errdefer a.free(main);
        const inter = try points.emptyOrFilledLogs(a, self.interactionCount(), self.log_size);
        errdefer a.free(inter);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
    }
    pub fn preprocessedColumnIndices(self: *const Parameters, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, self.fixedCount());
        for (result, 0..) |*v, i| v.* = self.offsets.fixed + i;
        return result;
    }
    pub fn maskPoints(self: *const Parameters, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        try self.validate();
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const fixed = try points.currentPointColumns(a, self.fixedCount(), point);
        errdefer points.freePointColumns(a, fixed);
        const main = try points.currentPointColumns(a, self.mainCount(), point);
        errdefer points.freePointColumns(a, main);
        const inter = try points.currentPointColumns(a, self.interactionCount(), point);
        errdefer points.freePointColumns(a, inter);
        const step = canonic.CanonicCoset.new(global_log).coset().step;
        const lifted: Point = .{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) };
        if (self.kind == .permutation) for (main[0..L.STATE]) |*column| {
            var samples: [5]Point = undefined;
            for (&samples, L.MASK_OFFSETS) |*sample, offset| sample.* = point.add(lifted.mulSigned(offset));
            const replacement = try a.dupe(Point, &samples);
            a.free(column.*);
            column.* = replacement;
        };
        if (self.kind == .permutation) for (main[L.ACTIVE_A..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        };
        for (inter[inter.len - 4 ..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Parameters, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        try self.validate();
        if (mask.items.len < 3 or mask.items[0].len < self.offsets.fixed + self.fixedCount() or mask.items[1].len < self.offsets.main + self.mainCount() or mask.items[2].len < self.offsets.interaction + self.interactionCount()) return error.InvalidKeccakMaskShape;
        const f = mask.items[0][self.offsets.fixed..][0..self.fixedCount()];
        const m = mask.items[1][self.offsets.main..][0..self.mainCount()];
        const inter = mask.items[2][self.offsets.interaction..][0..self.interactionCount()];
        for (f) |v| if (v.len != 1) return error.InvalidKeccakMaskShape;
        for (m, 0..) |v, i| if (v.len != @as(usize, if (self.kind == .permutation and i < L.STATE) 5 else if (self.kind == .permutation and i >= L.ACTIVE_A) 2 else 1)) return error.InvalidKeccakMaskShape;
        for (inter, 0..) |v, i| if (v.len != @as(usize, if (i >= inter.len - 4) 2 else 1)) return error.InvalidKeccakMaskShape;
        var sink = Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        const previous = try points.sampledSecure(inter, inter.len - 4, 1);
        if (self.kind != .permutation) {
            var tuple: [6]Q = undefined;
            for (&tuple, f[0..6]) |*v, column| v.* = column[0];
            sink.emit(tableResidualFor(Q, self, &tuple, f[6][0], m[0][0], try points.sampledSecure(inter, 0, 0), previous));
            return;
        }
        var scratch: Scratch = undefined;
        for (&scratch.fixed, f) |*v, column| v.* = column[0];
        for (&scratch.main, m) |*v, column| v.* = column[0];
        for (&scratch.shifted, 1..) |*state, sample| for (state, m[0..L.STATE]) |*v, column| {
            v.* = column[sample];
        };
        for (&scratch.previous_header, m[L.ACTIVE_A..]) |*v, column| v.* = column[1];
        for (scratch.interaction[0..self.batches], 0..) |*v, batch| v.* = try points.sampledSecure(inter, 4 * batch, 0);
        self.emit_q(scratch.row(), scratch.interaction[0..self.batches], previous, self.claim, self.challenges, .{ .calls = self.calls, .first_id = self.first_call_id }, &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Parameters, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, accumulator, null);
    }
    pub fn evaluateDomain(self: *const Parameters, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        if (self.kind == .permutation and self.emit_packed == null) return error.InvalidKeccakRowEvaluator;
        if (pool) |active| if (active.stackSize() < @import("parallel.zig").MIN_STACK) return error.InvalidKeccakWorkerStack;
        const a = accumulator.allocator;
        if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.offsets.fixed + self.fixedCount() or trace.polys.items[1].len < self.offsets.main + self.mainCount() or trace.polys.items[2].len < self.offsets.interaction + self.interactionCount()) return error.InvalidKeccakTraceShape;
        const total = self.fixedCount() + self.mainCount() + self.interactionCount();
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        const fm = self.fixedCount() + self.mainCount();
        @memcpy(polys[0..self.fixedCount()], trace.polys.items[0][self.offsets.fixed..][0..self.fixedCount()]);
        @memcpy(polys[self.fixedCount()..fm], trace.polys.items[1][self.offsets.main..][0..self.mainCount()]);
        @memcpy(polys[fm..], trace.polys.items[2][self.offsets.interaction..][0..self.interactionCount()]);
        const previous = try a.alloc(bool, total);
        defer a.free(previous);
        @memset(previous, false);
        if (self.kind == .permutation) {
            @memset(previous[self.fixedCount()..][0..L.STATE], true);
            @memset(previous[self.fixedCount() + L.ACTIVE_A ..][0..3], true);
        }
        @memset(previous[total - 4 ..], true);
        var evaluation = try cosets.Evaluation.init(a, polys, self.log_size, previous);
        defer evaluation.deinit();
        const outputs = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 2, .n_cols = self.nConstraints() }});
        defer a.free(outputs);
        var output = outputs[0];
        for (0..cosets.PARTS) |part| {
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_coset_fft", "Keccak quotient coset FFT");
                defer stage.end();
                try evaluation.evaluatePartWithPool(part, pool);
            }
            const inverse = try evaluation.denominatorInverse(part);
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_constraint_rows", "Keccak quotient constraint rows");
                defer stage.end();
                try @import("parallel.zig").evaluateParameters(self, &evaluation, part, &output, inverse, pool);
            }
        }
    }
};

pub const Scratch = ScratchFor(Q);
pub fn ScratchFor(comptime F: type) type {
    return struct {
        fixed: [L.FIXED]F,
        main: [L.MAIN]F,
        shifted: [4][L.STATE]F,
        previous_header: [3]F,
        interaction: [L.BATCHES]V.SecureFor(F),
        pub fn row(self: *const @This()) E.RowFor(F) {
            return .{ .fixed = &self.fixed, .main = &self.main, .previous_header = &self.previous_header, .state_minus_two = &self.shifted[0], .state_minus_one = &self.shifted[1], .state_plus_one = &self.shifted[2], .state_plus_two = &self.shifted[3] };
        }
    };
}
pub fn tableResidual(self: *const Component, tuple: *const [6]Q, first: Q, count: Q, current: Q, previous: Q) Q {
    return tableResidualFor(Q, self, tuple, first, count, current, previous);
}
pub fn tableResidualFor(comptime F: type, self: anytype, tuple: *const [6]F, first: F, count: F, current: V.SecureFor(F), previous: V.SecureFor(F)) V.SecureFor(F) {
    const challenges = if (self.kind == .chi) self.challenges.chi else self.challenges.xor5;
    return current.sub(previous).add(V.mulBaseFor(F, V.splatFor(F, self.claim), first)).mul(V.denominatorFor(F, challenges.offset, &challenges.coefficients, tuple, true)).sub(V.liftFor(F, count));
}
