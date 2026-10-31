//! Concrete index CPU / two-projection ROM adapters. No execution selection
//! enum enters the qualified byte/word CPU or the Ethereum runtime.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const A = @import("authority.zig");
const L = @import("../word16_cpu/layout.zig");
const P = @import("../word16_cpu/public.zig");
const Lookup = @import("../word16_cpu/lookup.zig");
const Eq = @import("equations.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const Air = core.air.components;
const M = core.fields.m31.M31;
const Q = E.Q;
const Point = core.circle.CirclePointQM31;
pub const MAX_COLUMNS = 3 + Eq.MAIN + Eq.INTERACTION;
pub const Kind = enum { cpu, rom };
pub const Component = struct {
    kind: Kind,
    log_size: u32,
    offsets: [3]usize,
    public: Eq.Public,
    cpu_claims: P.Claims,
    rom_claims: [2]Q,
    rom_challenges: Eq.RomChallenges,
    map_challenges: Eq.MapChallenges,
    challenges: Lookup.Challenges,
    scalar_reference: bool = false,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        if (self.kind == .cpu) {
            result.domain_parallel_evaluator = evaluateParallel;
            result.pool_exclusive_domain = true;
        }
        return result;
    }
    fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.evaluateDomain(trace, accumulator, pool);
    }
    pub fn asVerifierComponent(self: *const Component) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn widths(self: *const Component) [3]usize {
        return switch (self.kind) {
            .cpu => .{ 3, Eq.MAIN, Eq.INTERACTION },
            .rom => .{ A.FIXED, 2, 16 },
        };
    }
    pub fn nConstraints(self: *const Component) usize {
        return switch (self.kind) {
            .cpu => Eq.CONSTRAINTS,
            .rom => 7,
        };
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    fn validate(self: *const Component) !void {
        if (self.log_size < 5 or self.log_size > 24 or (self.kind == .cpu and self.log_size > 22)) return error.InvalidIndexGeometry;
        if (self.kind == .cpu) try self.public.state.validate(self.log_size);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |list| a.free(list);
        for (self.widths(), &logs) |width, *list| {
            list.* = try points.emptyOrFilledLogs(a, width, self.log_size);
            initialized += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, self.widths()[0]);
        for (result, 0..) |*value, i| value.* = self.offsets[0] + i;
        return result;
    }
    pub fn needsPrevious(self: *const Component, tree: usize, column: usize) bool {
        if (tree == 1) return self.kind == .cpu and (column == Eq.next_id or column == Eq.active);
        if (tree != 2) return false;
        return if (self.kind == .cpu) L.previousInteraction(column) else (column >= 4 and column < 8) or column >= 12;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        var masks: [3][][]Point = undefined;
        var initialized: usize = 0;
        errdefer for (masks[0..initialized]) |columns| points.freePointColumns(a, columns);
        for (self.widths(), &masks, 0..) |width, *columns, tree| {
            columns.* = try points.currentPointColumns(a, width, point);
            initialized += 1;
            for (columns.*, 0..) |*mask, i| if (self.needsPrevious(tree, i)) {
                const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(mask.*);
                mask.* = replacement;
            };
        }
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn emitFor(self: *const Component, comptime F: type, fixed: []const F, main: []const F, current: []const F, previous_main: []const F, previous: []const F, sink: *E.SinkFor(F)) void {
        switch (self.kind) {
            .cpu => Eq.emitFor(F, fixed, main, previous_main, current, previous, self.public, self.cpu_claims, self.challenges, self.rom_challenges, sink),
            .rom => Eq.emitRomFor(F, fixed, main, current, previous, self.rom_claims, self.rom_challenges, self.map_challenges, sink),
        }
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidWord16CpuMask;
        var values: [MAX_COLUMNS]Q = undefined;
        var previous_main: [Eq.MAIN]Q = @splat(Q.zero());
        var previous: [56]Q = @splat(Q.zero());
        var cursor: usize = 0;
        const widths_ = self.widths();
        for (widths_, 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidWord16CpuMask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, column| {
                const needs = self.needsPrevious(tree, column);
                if (samples.len != @as(usize, if (needs) 2 else 1)) return error.InvalidWord16CpuMask;
                values[cursor] = samples[0];
                cursor += 1;
                if (needs) {
                    if (tree == 1) previous_main[column] = samples[1] else previous[column] = samples[1];
                }
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        self.emitFor(Q, values[0..widths_[0]], values[widths_[0]..][0..widths_[1]], values[widths_[0] + widths_[1] ..][0..widths_[2]], &previous_main, &previous, &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, accumulator, null);
    }
    fn evaluateDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        const a = accumulator.allocator;
        const widths_ = self.widths();
        const total = widths_[0] + widths_[1] + widths_[2];
        var polys: [MAX_COLUMNS]cp.Poly = undefined;
        var cursor: usize = 0;
        for (widths_, 0..) |width, tree| {
            if (trace.polys.items.len <= tree or trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidWord16CpuTrace;
            @memcpy(polys[cursor..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
            cursor += width;
        }
        const eval_log = self.log_size + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        var owned_count: usize = 0;
        for (polys[0..total]) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var evaluations: [MAX_COLUMNS][]const M = undefined;
        for (polys[0..total], evaluations[0..total]) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, n, owned, &initialized);
        if (owned_count != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try @import("../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles), pool);
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
        defer a.free(inverses);
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        const rows = Rows{ .component = self, .columns = evaluations[0..total], .inverses = inverses };
        try @import("../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, n, &output, pool);
    }
};

const Rows = struct {
    component: *const Component,
    columns: []const []const M,
    inverses: []const M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, output: *accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Rows = @ptrCast(@alignCast(ctx));
        return @import("packed_rows.zig").evaluateRange(self.component, self.columns, start, end, self.inverses, output);
    }
};
