//! Immutable-policy certificate adapter. Reuses the existing bounded four-coset matrix
//! evaluator and prover WorkPool; every quotient/OODS residual comes from AIR.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const AIR = @import("permit_air.zig");
const E = @import("../evaluation.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const cosets = @import("../full/coset_evaluation.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const work = engine.work_pool;
const WIDTHS = [3]usize{ AIR.FIXED, AIR.MAIN, AIR.INTERACTION };
const TOTAL = AIR.FIXED + AIR.MAIN + AIR.INTERACTION;
pub const Offsets = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
const lane = @import("../lane.zig");
const prefix = @import("prefix.zig");
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        shape: AIR.Shape,
        offsets: Offsets,
        challenges: AIR.ChallengesFor(Lane),
        claims: AIR.ClaimsFor(Lane),
        /// External lanes supply the active-row publics here.
        active: prefix.ActiveFor(Lane) = prefix.activeDefault(Lane),
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn init(shape: AIR.Shape, offsets: Offsets, challenges: AIR.ChallengesFor(Lane), claims: AIR.ClaimsFor(Lane)) !Self {
            try shape.validate();
            return .{ .shape = shape, .offsets = offsets, .challenges = challenges, .claims = claims };
        }
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = parallelErased;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return AIR.CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.shape.log_size + 2;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 2;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= AIR.CONSTRAINTS) return error.InvalidConstraintIndex;
            return 4;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            const fixed = try points.emptyOrFilledLogs(a, AIR.FIXED, self.shape.log_size);
            errdefer a.free(fixed);
            const main = try points.emptyOrFilledLogs(a, AIR.MAIN, self.shape.log_size);
            errdefer a.free(main);
            const inter = try points.emptyOrFilledLogs(a, AIR.INTERACTION, self.shape.log_size);
            errdefer a.free(inter);
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const result = try a.alloc(usize, AIR.FIXED);
            for (result, 0..) |*index, i| index.* = self.offsets.fixed + i;
            return result;
        }
        fn priorMain(column: usize) bool {
            return column == AIR.ACTIVE;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.shape.log_size);
            const fixed = try points.currentPointColumns(a, AIR.FIXED, point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, AIR.MAIN, point);
            errdefer points.freePointColumns(a, main);
            const inter = try points.currentPointColumns(a, AIR.INTERACTION, point);
            errdefer points.freePointColumns(a, inter);
            const prior = geometry.previousPoint(point, global_log);
            for (main, 0..) |*column, i| if (priorMain(i)) {
                const replacement = try a.dupe(Point, &.{ point, prior });
                a.free(column.*);
                column.* = replacement;
            };
            for (inter) |*column| {
                const replacement = try a.dupe(Point, &.{ point, prior });
                a.free(column.*);
                column.* = replacement;
            }
            return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = accumulator };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidRamMessageSamples else err;
        }
        /// Lane-generic point evaluation. Mask map: fixed[fixed + c] sample 0;
        /// main[main + c] sample 0, plus sample 1 (previous row) when priorMain(c);
        /// interaction[interaction + c] samples 0/1 for every column.
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("RAM component lane mismatch");
            const f = self.offsets.fixed;
            const m = self.offsets.main;
            const i = self.offsets.interaction;
            var fixed: [AIR.FIXED]F = undefined;
            for (&fixed, 0..) |*value, c| value.* = try lane.sample(F, masks, 0, f + c, 0, 1);
            var main: [AIR.MAIN]F = undefined;
            var previous_main: [AIR.MAIN]F = @splat(F.zero());
            for (&main, 0..) |*value, c| {
                value.* = try lane.sample(F, masks, 1, m + c, 0, if (priorMain(c)) 2 else 1);
                if (priorMain(c)) previous_main[c] = try lane.sample(F, masks, 1, m + c, 1, 2);
            }
            var interaction: [AIR.INTERACTION]F = undefined;
            var previous_interaction: [AIR.INTERACTION]F = undefined;
            for (&interaction, &previous_interaction, 0..) |*value, *prior, c| {
                value.* = try lane.sample(F, masks, 2, i + c, 0, 2);
                prior.* = try lane.sample(F, masks, 2, i + c, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.shape.log_size);
            AIR.evaluateFor(F, self.shape, &fixed, &main, &previous_main, &interaction, &previous_interaction, self.claims, &self.challenges, try self.rowsFor(F), sink);
        }
        fn rowsFor(self: *const Self, comptime F: type) !prefix.RowsFor(F) {
            if (comptime E.isExternalLane(F)) {
                const active = self.active orelse return error.MissingRv64LaneFlag;
                return .{ .active = active.rows, .nonempty = active.nonempty, .total = E.qFor(F, @intCast(self.shape.size())) };
            }
            return prefix.rows(self.shape.activeRows(), @intCast(self.shape.size()));
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, accumulator, null);
        }
        fn parallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *work.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, accumulator, pool);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*work.WorkPool) !void {
            if (trace.polys.items.len != 3) return error.InvalidRamMessageSamples;
            const offsets = [_]usize{ self.offsets.fixed, self.offsets.main, self.offsets.interaction };
            var sources: [TOTAL]cp.Poly = undefined;
            var at: usize = 0;
            for (trace.polys.items, offsets, WIDTHS) |tree, offset, width| {
                if (tree.len < offset + width) return error.InvalidRamMessageSamples;
                @memcpy(sources[at..][0..width], tree[offset..][0..width]);
                at += width;
            }
            var previous: [TOTAL]bool = @splat(false);
            for (0..AIR.MAIN) |i| previous[AIR.FIXED + i] = priorMain(i);
            @memset(previous[AIR.FIXED + AIR.MAIN ..], true);
            const a = accumulator.allocator;
            var evaluation = try cosets.Evaluation.init(a, &sources, self.shape.log_size, &previous);
            defer evaluation.deinit();
            const columns = try accumulator.columns(a, &.{.{ .log_size = self.shape.log_size + 2, .n_cols = AIR.CONSTRAINTS }});
            defer a.free(columns);
            var output = columns[0];
            for (0..cosets.PARTS) |part| {
                try evaluation.evaluatePartWithPool(part, pool);
                try self.evaluatePart(&evaluation, part, &output, try evaluation.denominatorInverse(part), pool);
            }
        }
        fn evaluatePart(self: *const Self, evaluation: *const cosets.Evaluation, part: usize, output: *accumulation.ColumnAccumulator, inverse: M, pool: ?*work.WorkPool) !void {
            const workers = if (pool) |p| @min(p.workerCount(), @max(1, evaluation.size / 128)) else 1;
            const scratch = try evaluation.allocator.alloc(Scratch, workers);
            defer evaluation.allocator.free(scratch);
            var jobs: [work.MAX_WORKERS]Job = undefined;
            if (workers == 1) {
                jobs[0] = .{ .component = self, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = &scratch[0], .start = 0, .end = evaluation.size };
                jobs[0].run();
                output.* = jobs[0].output;
                return;
            }
            var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
            defer lease.deinit();
            var wait_group = std.Thread.WaitGroup{};
            defer {
                wait_group.wait();
                lease.completeWave();
            }
            output.next_fresh_index = null;
            for (jobs[0..workers], 0..) |*job, i| job.* = .{ .component = self, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = &scratch[i], .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
            for (jobs[1..workers]) |*job| try lease.spawnWg(&wait_group, Job.run, .{job});
            jobs[0].run();
        }
    };
}
pub const Component = ComponentFor(Q);
const Scratch = struct { fixed: AIR.Fixed, main: AIR.SecureRow, previous_main: AIR.SecureRow, interaction: [AIR.INTERACTION]Q, previous_interaction: [AIR.INTERACTION]Q };
const Job = struct {
    component: *const Component,
    evaluation: *const cosets.Evaluation,
    part: usize,
    output: accumulation.ColumnAccumulator,
    inverse: M,
    scratch: *Scratch,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const columns = self.evaluation.current_values;
        const prior = self.evaluation.previous_values;
        const s = self.scratch;
        @memset(&s.previous_main, Q.zero());
        for (self.start..self.end) |row| {
            const previous_row = self.evaluation.previousRow(self.part, row);
            for (&s.fixed, columns[0..AIR.FIXED]) |*value, column| value.* = Q.fromBase(column[row]);
            for (&s.main, 0..) |*value, i| {
                value.* = Q.fromBase(columns[AIR.FIXED + i][row]);
                if (Component.priorMain(i)) s.previous_main[i] = Q.fromBase(prior[AIR.FIXED + i][previous_row]);
            }
            for (&s.interaction, &s.previous_interaction, 0..) |*value, *old, i| {
                value.* = Q.fromBase(columns[AIR.FIXED + AIR.MAIN + i][row]);
                old.* = Q.fromBase(prior[AIR.FIXED + AIR.MAIN + i][previous_row]);
            }
            var accumulator = E.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
            AIR.evaluate(self.component.shape, &s.fixed, &s.main, &s.previous_main, &s.interaction, &s.previous_interaction, self.component.claims, &self.component.challenges, &sink);
            self.output.accumulate(self.evaluation.globalRow(self.part, row), accumulator.accumulation.mulM31(self.inverse));
        }
    }
};
