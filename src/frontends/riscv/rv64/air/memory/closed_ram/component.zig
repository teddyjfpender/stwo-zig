const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const geometry = @import("../../geometry.zig");
const points = @import("../../../../air/component_point_support.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = T.Q;
const Point = core.circle.CirclePointQM31;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
pub const Component = struct {
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    offsets: [3]usize,
    public_rows: ?*const T.PublicRows = null,
    claims: T.Claims,
    challenges: T.Challenges,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn widths(self: *const Component) [3]usize {
        return L.widths(self.kind);
    }
    pub fn nConstraints(self: *const Component) usize {
        return L.constraints(self.kind);
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
    pub fn emitFor(self: *const Component, comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, sink: *E.SinkFor(F)) void {
        Eq.emitFor(F, self.kind, f, m, pm, i, pi, self.rows, self.public_rows, self.claims, self.challenges, sink);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
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
        const data = try a.alloc(usize, self.widths()[0]);
        for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
        return data;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !core.air.components.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        var masks: [3][][]Point = undefined;
        var n: usize = 0;
        errdefer for (masks[0..n]) |data| points.freePointColumns(a, data);
        for (self.widths(), &masks) |width, *data| {
            data.* = try points.currentPointColumns(a, width, point);
            n += 1;
        }
        for (1..3) |tree| for (masks[tree], 0..) |*data, c| {
            if (if (tree == 1) L.previousMain(self.kind, c) else L.previousInter(self.kind, c)) {
                const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(data.*);
                data.* = replacement;
            }
        };
        return core.air.components.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidClosedRamMask;
        const widths_ = self.widths();
        var data: [128]Q = undefined;
        var pm: [28]Q = @splat(Q.zero());
        var pi: [68]Q = @splat(Q.zero());
        var at: usize = 0;
        for (widths_, 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidClosedRamMask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, c| {
                const prev = if (tree == 1) L.previousMain(self.kind, c) else tree == 2 and L.previousInter(self.kind, c);
                if (samples.len != @as(usize, if (prev) 2 else 1)) return error.InvalidClosedRamMask;
                data[at] = samples[0];
                at += 1;
                if (prev) {
                    if (tree == 1) pm[c] = samples[1] else pi[c] = samples[1];
                }
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = acc, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        self.emitFor(Q, data[0..widths_[0]], data[widths_[0]..][0..widths_[1]], pm[0..widths_[1]], data[widths_[0] + widths_[1] ..][0..widths_[2]], pi[0..widths_[2]], &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const widths_ = self.widths();
        const total = widths_[0] + widths_[1] + widths_[2];
        var polys_buffer: [128]cp.Poly = undefined;
        const polys = polys_buffer[0..total];
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
        var eval_buffer: [128][]const M = undefined;
        const evals = eval_buffer[0..total];
        for (polys, evals) |poly, *data| data.* = try support.evaluationValues(a, poly, log, n, owned, &initialized);
        if (owned_count != 0) {
            var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &tw);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles));
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, log);
        defer a.free(inverses);
        const columns = try acc.columns(a, &.{.{ .log_size = log, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        for (0..n) |row| {
            var data: [128]Q = undefined;
            var pm: [28]Q = @splat(Q.zero());
            var pi: [68]Q = @splat(Q.zero());
            const prev = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, log);
            for (evals, 0..) |column, c| data[c] = Q.fromBase(column[row]);
            for (0..widths_[1]) |c| if (L.previousMain(self.kind, c)) {
                pm[c] = Q.fromBase(evals[widths_[0] + c][prev]);
            };
            for (0..widths_[2]) |c| if (L.previousInter(self.kind, c)) {
                pi[c] = Q.fromBase(evals[widths_[0] + widths_[1] + c][prev]);
            };
            var weighted = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
            self.emitFor(Q, data[0..widths_[0]], data[widths_[0]..][0..widths_[1]], pm[0..widths_[1]], data[widths_[0] + widths_[1] ..][0..widths_[2]], pi[0..widths_[2]], &sink);
            std.debug.assert(sink.count == self.nConstraints());
            const value = weighted.accumulation.mulM31(inverses[row >> @intCast(self.log_size)]);
            const fresh = output.next_fresh_index != null and output.next_fresh_index.? == row;
            for (value.toM31Array(), 0..) |coordinate, c| {
                output.col.columns[c][row] = if (fresh) coordinate else output.col.columns[c][row].add(coordinate);
            }
            output.next_fresh_index = if (fresh) row + 1 else null;
        }
    }
};
