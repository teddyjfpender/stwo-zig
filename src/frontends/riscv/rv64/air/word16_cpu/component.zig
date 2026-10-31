//! Concrete mixed-domain adapters for CPU, immutable ROM, public register
//! boundary and typed clock ranges. BINARY/AND use their existing authorities.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const Profile = @import("profile.zig");
const L = @import("layout.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
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
pub const MAX_COLUMNS = L.fixed.COUNT + Profile.MAX_MAIN + L.inter.COUNT;
pub const Kind = enum { cpu, rom, boundary, range16, range8 };
pub const Component = struct {
    kind: Kind,
    profile: Profile.Profile = .binary_v1,
    log_size: u32,
    offsets: [3]usize,
    public: P.Public,
    cpu_claims: P.Claims,
    claim: Q,
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
            .cpu => .{ 3, Profile.mainCount(self.profile), 56 },
            .rom => .{ Profile.romCount(self.profile) + 2, 1, 8 },
            .boundary => .{ 34, 0, 8 },
            .range16, .range8 => .{ 3, 1, 8 },
        };
    }
    pub fn nConstraints(self: *const Component) usize {
        return switch (self.kind) {
            .cpu => L.CONSTRAINTS,
            .rom => 4,
            .boundary, .range16, .range8 => 3,
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
        if (self.log_size < 5 or self.log_size > 22 or (self.kind == .boundary and self.log_size != 5) or (self.kind == .range16 and self.log_size != 16) or (self.kind == .range8 and self.log_size != 8)) return error.InvalidWord16CpuGeometry;
        if (self.kind == .cpu) try self.public.validate(self.log_size);
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
        if (tree == 1) return self.kind == .cpu and L.previousMain(column);
        if (tree != 2) return false;
        return if (self.kind == .cpu) L.previousInteraction(column) else column >= 4;
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
            .cpu => Eq.emitProfileFor(F, self.profile, fixed, main, previous_main, current, previous, self.public, self.cpu_claims, self.challenges, sink),
            .rom => @import("table.zig").romProfileFor(F, self.profile, fixed, main, current, previous, self.claim, self.challenges.rom, sink),
            .boundary => @import("boundary.zig").emitFor(F, fixed, current, previous, self.public, self.claim, self.challenges.register, sink),
            .range16 => @import("table.zig").rangeFor(F, fixed, main, current, previous, self.claim, self.challenges.range16, sink),
            .range8 => @import("table.zig").rangeFor(F, fixed, main, current, previous, self.claim, self.challenges.range8, sink),
        }
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidWord16CpuMask;
        var values: [MAX_COLUMNS]Q = undefined;
        var previous_main: [Profile.MAX_MAIN]Q = @splat(Q.zero());
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
