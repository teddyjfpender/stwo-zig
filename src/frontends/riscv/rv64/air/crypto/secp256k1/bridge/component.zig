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
pub const Component = struct {
    log_size: u32,
    program: *const @import("../program.zig").Program,
    calls: u32,
    packet_format: E.PacketFormat = .big_endian_bytes_v1,
    first_call_id: u32 = 1,
    offsets: @import("../component.zig").Offsets = .{},
    challenges: E.Challenges,
    claim: Q,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn validate(self: *const Component) !void {
        try @import("trace.zig").validateGeometry(self.program, self.calls, self.first_call_id, self.log_size);
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallelErased;
        return result;
    }
    fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.evaluateDomain(trace, accumulator, pool);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Component) usize {
        return L.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(_: *const Component, index: usize) !u8 {
        if (index >= L.CONSTRAINTS) return error.InvalidConstraintIndex;
        return if (index < L.DIRECT) 3 else 4;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        try self.validate();
        const fixed = try points.emptyOrFilledLogs(a, L.FIXED, self.log_size);
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, L.MAIN, self.log_size);
        errdefer a.free(main);
        const inter = try points.emptyOrFilledLogs(a, L.INTERACTION, self.log_size);
        errdefer a.free(inter);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, L.FIXED);
        for (result, 0..) |*v, i| v.* = self.offsets.fixed + i;
        return result;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
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
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        try self.validate();
        if (mask.items.len < 3 or mask.items[0].len < self.offsets.fixed + L.FIXED or mask.items[1].len < self.offsets.main + L.MAIN or mask.items[2].len < self.offsets.interaction + L.INTERACTION) return error.InvalidSecpBridgeShape;
        const f = mask.items[0][self.offsets.fixed..][0..L.FIXED];
        const m = mask.items[1][self.offsets.main..][0..L.MAIN];
        const inter = mask.items[2][self.offsets.interaction..][0..L.INTERACTION];
        for (f) |v| if (v.len != 1) return error.InvalidSecpBridgeShape;
        for (m, 0..) |v, i| if (v.len != @as(usize, if (i < L.PREVIOUS_MAIN or i >= L.ACTIVE) 2 else 1)) return error.InvalidSecpBridgeShape;
        for (inter, 0..) |v, i| if (v.len != @as(usize, if (i >= L.INTERACTION - 4) 2 else 1)) return error.InvalidSecpBridgeShape;
        var scratch: Scratch = undefined;
        for (&scratch.fixed, f) |*v, column| v.* = column[0];
        for (&scratch.main, m) |*v, column| v.* = column[0];
        for (&scratch.previous, m[0..L.PREVIOUS_MAIN]) |*v, column| v.* = column[1];
        for (&scratch.previous_header, m[L.ACTIVE..]) |*v, column| v.* = column[1];
        for (&scratch.interaction, 0..) |*v, b| v.* = try points.sampledSecure(inter, 4 * b, 0);
        var sink = sinks.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        E.emit(self.program, scratch.row(self.packet_format), &scratch.interaction, try points.sampledSecure(inter, L.INTERACTION - 4, 1), self.claim, self.challenges, .{ .calls = self.calls, .first_id = self.first_call_id }, &sink);
        std.debug.assert(sink.count == L.CONSTRAINTS);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, accumulator, null);
    }
    fn evaluateDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        if (pool) |active| if (active.stackSize() < @import("../parallel.zig").MIN_STACK) return error.InvalidSecpWorkerStack;
        const a = accumulator.allocator;
        if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.offsets.fixed + L.FIXED or trace.polys.items[1].len < self.offsets.main + L.MAIN or trace.polys.items[2].len < self.offsets.interaction + L.INTERACTION) return error.InvalidSecpBridgeShape;
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
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "secp_bridge_fft", "Secp bridge quotient coset FFT");
                defer stage.end();
                try evaluation.evaluatePartWithPool(part, pool);
            }
            const inverse = try evaluation.denominatorInverse(part);
            {
                var stage = try engine.stage_profile.StageScope.begin(self.stage_recorder, "secp_bridge_rows", "Secp bridge quotient constraint rows");
                defer stage.end();
                try @import("parallel.zig").evaluatePart(self, &evaluation, part, &output, inverse, pool);
            }
        }
    }
};
pub const Scratch = struct {
    fixed: [L.FIXED]Q,
    main: [L.MAIN]Q,
    previous: [L.PREVIOUS_MAIN]Q,
    previous_header: [2]Q,
    interaction: [L.BATCHES]Q,
    pub fn row(self: *const Scratch, format: E.PacketFormat) E.Row {
        return .{ .packet_format = format, .fixed = &self.fixed, .main = &self.main, .previous_main = &self.previous, .previous_header = &self.previous_header };
    }
};

/// Per-worker domain scratch; OODS continues through the scalar Scratch above.
pub const PackedScratch = struct {
    fixed: [L.FIXED]sinks.PackedBase,
    main: [L.MAIN]sinks.PackedBase,
    previous: [L.PREVIOUS_MAIN]sinks.PackedBase,
    previous_header: [2]sinks.PackedBase,
    interaction: [L.BATCHES]sinks.PackedSecure,
    pub fn row(self: *const PackedScratch, format: E.PacketFormat) E.RowFor(sinks.PackedBase) {
        return .{ .packet_format = format, .fixed = &self.fixed, .main = &self.main, .previous_main = &self.previous, .previous_header = &self.previous_header };
    }
};
