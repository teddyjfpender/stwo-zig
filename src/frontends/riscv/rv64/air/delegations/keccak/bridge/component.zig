//! Concrete narrow RAM/service bridge in the same PCS/FRI transaction.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const cosets = @import("../../../full/coset_evaluation.zig");
const L = @import("layout.zig");
const E = @import("equations.zig");
const sinks = @import("../../../evaluation.zig");
const geometry = @import("../../../geometry.zig");
const points = @import("../../../../../air/component_point_support.zig");
const lane = @import("../../../lane.zig");
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        log_size: u32,
        calls: sinks.CountFor(Lane),
        first_call_id: sinks.CountFor(Lane) = sinks.countDefault(Lane, 1),
        /// External lanes supply the derived `calls != 0` wire here.
        calls_nonzero: sinks.FlagFor(Lane) = sinks.flagDefault(Lane),
        offsets: @import("../component.zig").Offsets = .{},
        challenges: E.ChallengesFor(Lane),
        claim: Lane,
        stage_recorder: ?*engine.stage_profile.Recorder = null,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        fn callSpan(self: *const Self) !sinks.CallSpanFor(Lane) {
            if (comptime sinks.isExternalLane(Lane)) return .{ .calls = self.calls, .first_id = self.first_call_id, .nonempty = self.calls_nonzero orelse return error.MissingRv64LaneFlag };
            return .{ .calls = self.calls, .first_id = self.first_call_id };
        }
        pub fn validate(self: *const Self) !void {
            try @import("trace.zig").validateGeometry(self.calls, self.first_call_id, self.log_size);
        }
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallelErased;
            return result;
        }
        fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, accumulator, pool);
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return L.CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 2;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 2;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= L.CONSTRAINTS) return error.InvalidConstraintIndex;
            return if (index < L.DIRECT) 3 else 4;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            try self.validate();
            const fixed = try points.emptyOrFilledLogs(a, L.FIXED, self.log_size);
            errdefer a.free(fixed);
            const main = try points.emptyOrFilledLogs(a, L.MAIN, self.log_size);
            errdefer a.free(main);
            const inter = try points.emptyOrFilledLogs(a, L.INTERACTION, self.log_size);
            errdefer a.free(inter);
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const result = try a.alloc(usize, L.FIXED);
            for (result, 0..) |*v, i| v.* = self.offsets.fixed + i;
            return result;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            try self.validate();
            _ = try geometry.localPoint(point, global_log, self.log_size);
            const fixed = try points.currentPointColumns(a, L.FIXED, point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, L.MAIN, point);
            errdefer points.freePointColumns(a, main);
            const inter = try points.currentPointColumns(a, L.INTERACTION, point);
            errdefer points.freePointColumns(a, inter);
            const previous = geometry.previousPoint(point, global_log);
            for (main[0..L.PREVIOUS_MAIN]) |*v| {
                const next = try a.dupe(Point, &.{ point, previous });
                a.free(v.*);
                v.* = next;
            }
            for (main[L.ACTIVE..]) |*v| {
                const next = try a.dupe(Point, &.{ point, previous });
                a.free(v.*);
                v.* = next;
            }
            for (inter[L.INTERACTION - 4 ..]) |*v| {
                const next = try a.dupe(Point, &.{ point, previous });
                a.free(v.*);
                v.* = next;
            }
            return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = sinks.Sink{ .values = null, .accumulator = accumulator };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidKeccakBridgeShape else err;
            std.debug.assert(sink.count == L.CONSTRAINTS);
        }
        /// Lane-generic point evaluation. Mask map: fixed[fixed + c] sample 0;
        /// main[main + c] samples 0/1 for c < L.PREVIOUS_MAIN and c >= L.ACTIVE,
        /// sample 0 otherwise; interaction[interaction + i] sample 0, plus sample 1
        /// for the last four columns.
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *sinks.SinkFor(F)) !void {
            comptime if (sinks.ConstFor(F) != Lane) @compileError("Keccak bridge lane mismatch");
            if (comptime !sinks.isExternalLane(F)) try self.validate();
            const f = self.offsets.fixed;
            const m = self.offsets.main;
            const i = self.offsets.interaction;
            var scratch: ScratchFor(F) = undefined;
            for (&scratch.fixed, 0..) |*v, c| v.* = try lane.sample(F, masks, 0, f + c, 0, 1);
            for (&scratch.main, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + c, 0, if (c < L.PREVIOUS_MAIN or c >= L.ACTIVE) 2 else 1);
            for (&scratch.previous, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + c, 1, 2);
            for (&scratch.previous_header, 0..) |*v, c| v.* = try lane.sample(F, masks, 1, m + L.ACTIVE + c, 1, 2);
            for (&scratch.interaction, 0..) |*v, b| v.* = try lane.secureSample(F, masks, 2, i + 4 * b, 0, if (4 * b + 4 >= L.INTERACTION) 2 else 1);
            const previous_final = try lane.secureSample(F, masks, 2, i + L.INTERACTION - 4, 1, 2);
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            E.emitFor(F, scratch.row(), &scratch.interaction, previous_final, self.claim, self.challenges, try self.callSpan(), sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, accumulator, null);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            try self.validate();
            if (pool) |active| if (active.stackSize() < @import("../parallel.zig").MIN_STACK) return error.InvalidKeccakWorkerStack;
            const a = accumulator.allocator;
            if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.offsets.fixed + L.FIXED or trace.polys.items[1].len < self.offsets.main + L.MAIN or trace.polys.items[2].len < self.offsets.interaction + L.INTERACTION) return error.InvalidKeccakBridgeShape;
            const total = L.FIXED + L.MAIN + L.INTERACTION;
            var polys: [total]cp.Poly = undefined;
            @memcpy(polys[0..L.FIXED], trace.polys.items[0][self.offsets.fixed..][0..L.FIXED]);
            @memcpy(polys[L.FIXED..][0..L.MAIN], trace.polys.items[1][self.offsets.main..][0..L.MAIN]);
            @memcpy(polys[L.FIXED + L.MAIN ..], trace.polys.items[2][self.offsets.interaction..][0..L.INTERACTION]);
            var previous: [total]bool = @splat(false);
            @memset(previous[L.FIXED..][0..L.PREVIOUS_MAIN], true);
            @memset(previous[L.FIXED + L.ACTIVE ..][0..2], true);
            @memset(previous[total - 4 ..], true);
            var evaluation = try cosets.Evaluation.init(a, &polys, self.log_size, &previous);
            defer evaluation.deinit();
            const outputs = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 2, .n_cols = L.CONSTRAINTS }});
            defer a.free(outputs);
            var output = outputs[0];
            for (0..cosets.PARTS) |part| {
                {
                    var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_bridge_fft", "Keccak bridge quotient coset FFT");
                    defer stage.end();
                    try evaluation.evaluatePartWithPool(part, pool);
                }
                const inverse = try evaluation.denominatorInverse(part);
                {
                    var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "keccak_bridge_rows", "Keccak bridge quotient constraint rows");
                    defer stage.end();
                    try @import("parallel.zig").evaluatePart(self, &evaluation, part, &output, inverse, pool);
                }
            }
        }
    };
}
pub const Component = ComponentFor(Q);
pub const Scratch = ScratchFor(Q);
pub fn ScratchFor(comptime F: type) type {
    return struct {
        fixed: [L.FIXED]F,
        main: [L.MAIN]F,
        previous: [L.PREVIOUS_MAIN]F,
        previous_header: [2]F,
        interaction: [L.BATCHES]sinks.SecureFor(F),
        pub fn row(self: *const @This()) E.RowFor(F) {
            return .{ .fixed = &self.fixed, .main = &self.main, .previous_main = &self.previous, .previous_header = &self.previous_header };
        }
    };
}
pub const testing = if (@import("builtin").is_test) struct {
    pub const parallel = @import("parallel.zig");
    pub const Evaluation = cosets.Evaluation;
} else struct {};
