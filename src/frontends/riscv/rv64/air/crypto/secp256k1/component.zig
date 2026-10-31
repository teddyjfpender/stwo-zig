//! Concrete modular product/linear adapters in one heterogeneous three-tree PCS.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const acc = engine.air.accumulation;
const L = @import("layout.zig");
const E = @import("equations.zig");
const Eval = @import("../../evaluation.zig");
const geometry = @import("../../geometry.zig");
const points = @import("../../../../air/component_point_support.zig");
pub const Offsets = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
pub const Component = struct {
    kind: L.Kind,
    program: *const L.P.Program,
    log_size: u32,
    public: E.Public,
    offsets: Offsets = .{},
    challenges: E.Challenges,
    claim: Q,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, acc.DomainEvaluationAccumulator);
    pub fn validate(self: *const Component) !void {
        try L.validate(self.kind, self.program, self.public.calls, self.public.first_id, self.log_size);
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var out = Adapter.asProverComponent(self);
        out.domain_parallel_evaluator = evaluateParallel;
        return out;
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Component) usize {
        return L.constraints(self.kind);
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 4;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        try self.validate();
        const f = try points.emptyOrFilledLogs(a, L.FIXED, self.log_size);
        errdefer a.free(f);
        const m = try points.emptyOrFilledLogs(a, L.main(self.kind), self.log_size);
        errdefer a.free(m);
        const i = try points.emptyOrFilledLogs(a, L.interaction(self.kind), self.log_size);
        errdefer a.free(i);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ f, m, i }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, L.FIXED);
        for (out, 0..) |*v, i| v.* = self.offsets.fixed + i;
        return out;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        try self.validate();
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const f = try points.currentPointColumns(a, L.FIXED, point);
        errdefer points.freePointColumns(a, f);
        const m = try points.currentPointColumns(a, L.main(self.kind), point);
        errdefer points.freePointColumns(a, m);
        for ([_]usize{ 0, L.base(self.kind) }) |index| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(m[index]);
            m[index] = replacement;
        }
        const inter = try points.currentPointColumns(a, L.interaction(self.kind), point);
        errdefer points.freePointColumns(a, inter);
        for (inter[inter.len - 4 ..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ f, m, inter }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        try self.validate();
        if (mask.items.len < 3) return error.InvalidSecpMaskShape;
        try self.shape(mask.items[0].len, mask.items[1].len, mask.items[2].len);
        const f = mask.items[0][self.offsets.fixed..][0..L.FIXED];
        const m = mask.items[1][self.offsets.main..][0..L.main(self.kind)];
        const inter = mask.items[2][self.offsets.interaction..][0..L.interaction(self.kind)];
        var fixed: [L.FIXED]Q = undefined;
        var main: [319]Q = undefined;
        var current: [96]Q = undefined;
        for (&fixed, f) |*v, column| {
            if (column.len != 1) return error.InvalidSecpMaskShape;
            v.* = column[0];
        }
        for (main[0..m.len], m, 0..) |*v, column, i| {
            if (column.len != @as(usize, if (i == 0 or i == L.base(self.kind)) 2 else 1)) return error.InvalidSecpMaskShape;
            v.* = column[0];
        }
        for (inter, 0..) |column, i| if (column.len != @as(usize, if (i >= inter.len - 4) 2 else 1)) return error.InvalidSecpMaskShape;
        for (current[0..L.batches(self.kind)], 0..) |*v, i| v.* = try points.sampledSecure(inter, 4 * i, 0);
        var sink = Eval.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        E.emit(self.kind, self.program, .{ .fixed = &fixed, .main = main[0..m.len], .previous_active = m[0][1], .previous_id = m[L.base(self.kind)][1] }, current[0..L.batches(self.kind)], try points.sampledSecure(inter, inter.len - 4, 1), self.claim, self.challenges, self.public, &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) !void {
        return self.domain(trace, accumulator, null);
    }
    fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.domain(trace, accumulator, pool);
    }
    fn domain(self: *const Component, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        if (pool) |active| if (active.stackSize() < @import("parallel.zig").MIN_STACK) return error.InvalidSecpWorkerStack;
        if (trace.polys.items.len != 3) return error.InvalidSecpMaskShape;
        try self.shape(trace.polys.items[0].len, trace.polys.items[1].len, trace.polys.items[2].len);
        const a = accumulator.allocator;
        const width = L.main(self.kind);
        const inter = L.interaction(self.kind);
        const total = L.FIXED + width + inter;
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        @memcpy(polys[0..L.FIXED], trace.polys.items[0][self.offsets.fixed..][0..L.FIXED]);
        @memcpy(polys[L.FIXED..][0..width], trace.polys.items[1][self.offsets.main..][0..width]);
        @memcpy(polys[L.FIXED + width ..], trace.polys.items[2][self.offsets.interaction..][0..inter]);
        const prev = try a.alloc(bool, total);
        defer a.free(prev);
        @memset(prev, false);
        prev[L.FIXED] = true;
        prev[L.FIXED + L.base(self.kind)] = true;
        @memset(prev[total - 4 ..], true);
        var evaluation = try @import("../../full/coset_evaluation.zig").Evaluation.init(a, polys, self.log_size, prev);
        defer evaluation.deinit();
        const columns = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 2, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        for (0..4) |part| {
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "secp_coset_fft", "Projective modular quotient coset FFT");
                defer stage.end();
                try evaluation.evaluatePartWithPool(part, pool);
            }
            const inverse = try evaluation.denominatorInverse(part);
            var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "secp_constraint_rows", "Projective modular quotient rows");
            defer stage.end();
            try @import("parallel.zig").evaluatePart(self, &evaluation, part, &output, inverse, pool);
        }
    }
    pub fn evaluateRows(self: *const Component, evaluation: *const @import("../../full/coset_evaluation.zig").Evaluation, part: usize, r: usize, count: usize, output: *acc.ColumnAccumulator, inverse: core.fields.m31.M31, scratch: *Scratch) void {
        const D = @import("packed_domain.zig");
        const F = D.F;
        const width = L.main(self.kind);
        const inter = L.interaction(self.kind);
        var prior: [D.LANES]usize = undefined;
        for (prior[0..count], 0..) |*value, i| value.* = evaluation.previousRow(part, r + i);
        for (&scratch.fixed, 0..) |*v, c| v.* = D.load(evaluation.current_values[c], r, count);
        for (scratch.main[0..width], 0..) |*v, c| v.* = D.load(evaluation.current_values[L.FIXED + c], r, count);
        for (scratch.current[0..L.batches(self.kind)], 0..) |*v, b| v.* = D.secure(evaluation.current_values[L.FIXED + width + 4 * b ..], r, count);
        var weighted = Eval.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = Eval.PackedSink{ .weighted_accumulator = &weighted };
        E.emitGeneric(F, self.kind, self.program, .{ .fixed = &scratch.fixed, .main = scratch.main[0..width], .previous_active = D.gather(evaluation.previous_values[L.FIXED], prior[0..count]), .previous_id = D.gather(evaluation.previous_values[L.FIXED + L.base(self.kind)], prior[0..count]) }, scratch.current[0..L.batches(self.kind)], D.previousSecure(evaluation.previous_values[L.FIXED + width + inter - 4 ..], prior[0..count]), self.claim, self.challenges, self.public, &sink);
        std.debug.assert(sink.count == self.nConstraints());
        D.accumulate(output, evaluation.globalRow(part, r), count, weighted.accumulation.mulBase(F.splat(inverse)));
    }
    fn shape(self: *const Component, f: usize, m: usize, i: usize) !void {
        if (f < self.offsets.fixed + L.FIXED or m < self.offsets.main + L.main(self.kind) or i < self.offsets.interaction + L.interaction(self.kind)) return error.InvalidSecpMaskShape;
    }
};

pub const Scratch = struct { fixed: [L.FIXED]Eval.PackedBase, main: [319]Eval.PackedBase, current: [96]Eval.PackedSecure };
