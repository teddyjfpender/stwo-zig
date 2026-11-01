//! SHA-256 truth component in its own three-tree PCS: degree 3, native 2n.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const Eq = @import("equations.zig");
const geometry = @import("../../geometry.zig");
const points = @import("../../../../air/component_point_support.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;

pub const Component = struct {
    log_size: u32,
    public: E.CallSpanFor(Q),
    offsets: [3]usize = .{ 0, 0, 0 },
    claim: Q,
    wire: Eq.Wire,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn validate(self: *const Component) !void {
        try L.validateGeometry(self.public.calls, self.public.first_id, self.log_size);
        if (self.public.calls == 0) return error.InvalidSha256Geometry;
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallel;
        result.pool_exclusive_domain = true;
        result.cooperative_domain = true;
        return result;
    }
    fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.evaluateDomain(trace, acc, pool);
    }
    pub fn asVerifierComponent(self: *const Component) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn widths(_: *const Component) [3]usize {
        return L.widths();
    }
    pub fn nConstraints(_: *const Component) usize {
        return L.CONSTRAINTS;
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
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        try self.validate();
        var logs: [3][]u32 = undefined;
        var n: usize = 0;
        errdefer for (logs[0..n]) |data| a.free(data);
        for (self.widths(), &logs) |width, *data| {
            data.* = try points.emptyOrFilledLogs(a, width, self.log_size);
            n += 1;
        }
        return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const data = try a.alloc(usize, L.FIXED);
        for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
        return data;
    }
    fn previousMask(tree: usize, c: usize) bool {
        return (tree == 1 and c == L.ACTIVE) or (tree == 2 and c >= 4);
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !core.air.components.MaskPoints {
        try self.validate();
        _ = try geometry.localPoint(point, global_log, self.log_size);
        var masks: [3][][]Point = undefined;
        var n: usize = 0;
        errdefer for (masks[0..n]) |data| points.freePointColumns(a, data);
        for (self.widths(), &masks) |width, *data| {
            data.* = try points.currentPointColumns(a, width, point);
            n += 1;
        }
        for (1..3) |tree| for (masks[tree], 0..) |*data, c| if (previousMask(tree, c)) {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(data.*);
            data.* = replacement;
        };
        return core.air.components.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    const MaskView = struct {
        mask: *const core.air.components.MaskValues,
        offsets: [3]usize,
        pub fn fixed(self: *const MaskView, c: usize) Q {
            return self.mask.items[0][self.offsets[0] + c][0];
        }
        pub fn main(self: *const MaskView, c: usize) Q {
            return self.mask.items[1][self.offsets[1] + c][0];
        }
        pub fn previousActive(self: *const MaskView) Q {
            return self.mask.items[1][self.offsets[1] + L.ACTIVE][1];
        }
        pub fn interaction(self: *const MaskView, c: usize) Q {
            return self.mask.items[2][self.offsets[2] + c][0];
        }
        pub fn previousInteraction(self: *const MaskView, c: usize) Q {
            return self.mask.items[2][self.offsets[2] + c][1];
        }
    };
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        try self.validate();
        if (mask.items.len < 3) return error.InvalidSha256Mask;
        for (self.widths(), 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidSha256Mask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, c| {
                if (samples.len != @as(usize, if (previousMask(tree, c)) 2 else 1)) return error.InvalidSha256Mask;
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = acc, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        const view = MaskView{ .mask = mask, .offsets = self.offsets };
        Eq.emit(Q, &view, self.public, self.claim, self.wire, &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, acc, null);
    }
    fn evaluateDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        try self.validate();
        const a = acc.allocator;
        const widths_ = self.widths();
        const total = widths_[0] + widths_[1] + widths_[2];
        if (trace.polys.items.len != 3) return error.InvalidSha256Mask;
        for (widths_, 0..) |width, tree| if (trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidSha256Mask;
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        var at: usize = 0;
        for (widths_, 0..) |width, tree| {
            @memcpy(polys[at..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
            at += width;
        }
        const log = self.log_size + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const n = domain.size();
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const evals = try a.alloc([]const M, total);
        defer a.free(evals);
        for (polys, evals) |poly, *data| data.* = try support.evaluationValues(a, poly, log, n, owned, &initialized);
        if (owned_count != 0) {
            var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &tw);
            try @import("../../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles), pool);
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, log);
        defer a.free(inverses);
        const columns = try acc.columns(a, &.{.{ .log_size = log, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        const rows = Rows{ .component = self, .columns = evals, .inverses = inverses };
        try @import("../../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, n, &output, pool);
    }
};

const F = E.PackedBase;
const LANES = E.LANES;
const PackedView = struct {
    columns: []const []const M,
    begin: usize,
    previous_active: F,
    previous_inter: [4]F,
    pub fn fixed(self: *const PackedView, c: usize) F {
        return F.load(self.columns[c].ptr + self.begin);
    }
    pub fn main(self: *const PackedView, c: usize) F {
        return F.load(self.columns[L.FIXED + c].ptr + self.begin);
    }
    pub fn previousActive(self: *const PackedView) F {
        return self.previous_active;
    }
    pub fn interaction(self: *const PackedView, c: usize) F {
        return F.load(self.columns[L.FIXED + L.MAIN + c].ptr + self.begin);
    }
    pub fn previousInteraction(self: *const PackedView, c: usize) F {
        return self.previous_inter[c - 4];
    }
};
const Rows = struct {
    component: *const Component,
    columns: []const []const M,
    inverses: []const M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, output: *accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Rows = @ptrCast(@alignCast(ctx));
        return evaluateRows(self.component, self.columns, start, end, self.inverses, output);
    }
};
pub fn evaluateRows(component: *const Component, columns: []const []const M, start: usize, end: usize, inverses: []const M, output: *accumulation.ColumnAccumulator) !void {
    const log = component.log_size;
    const n = @as(usize, 1) << @intCast(log + 1);
    if (columns.len != L.FIXED + L.MAIN + L.INTERACTION or start > end or end > n or start % LANES != 0 or end % LANES != 0 or inverses.len != 2 or output.random_coeff_powers.len != component.nConstraints()) return error.InvalidSha256Domain;
    for (columns) |column| if (column.len != n) return error.InvalidSha256Domain;
    for (output.col.columns) |column| if (column.len < n) return error.InvalidSha256Domain;
    var begin = start;
    while (begin < end) : (begin += LANES) {
        var indices: [LANES]usize = undefined;
        for (&indices, 0..) |*index, i| index.* = core.utils.previousBitReversedCircleDomainIndex(begin + i, log, log + 1);
        var view = PackedView{ .columns = columns, .begin = begin, .previous_active = undefined, .previous_inter = undefined };
        view.previous_active = gather(columns[L.FIXED + L.ACTIVE], &indices);
        for (&view.previous_inter, 0..) |*v, c| v.* = gather(columns[L.FIXED + L.MAIN + 4 + c], &indices);
        var weighted = E.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.PackedSink{ .weighted_accumulator = &weighted };
        Eq.emit(F, &view, component.public, component.claim, component.wire, &sink);
        std.debug.assert(sink.count == component.nConstraints());
        var denominators: [LANES]M = undefined;
        for (&denominators, 0..) |*value, lane| value.* = inverses[(begin + lane) >> @intCast(log)];
        accumulate(output, begin, weighted.accumulation.mulBase(F.fromLanes(denominators)));
    }
}
fn gather(column: []const M, indices: *const [LANES]usize) F {
    var lanes: [LANES]M = undefined;
    for (&lanes, indices) |*v, i| v.* = column[i];
    return F.fromLanes(lanes);
}
fn accumulate(output: *accumulation.ColumnAccumulator, start: usize, value: E.PackedSecure) void {
    const coordinates = value.coordinates();
    if (output.next_fresh_index) |next| {
        if (next == start) {
            for (output.col.columns, coordinates) |column, coordinate| coordinate.store(column.ptr + start);
            output.next_fresh_index = start + LANES;
            return;
        }
        output.next_fresh_index = null;
    }
    for (output.col.columns, coordinates) |column, coordinate| F.load(column.ptr + start).add(coordinate).store(column.ptr + start);
}
