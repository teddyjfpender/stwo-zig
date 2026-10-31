//! Concrete U16 adapter for the experimental ALU proof. It delegates all
//! accepting range equations to the shared scalar range provider authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const Source = @import("u16_source.zig");
const Table = @import("../providers/scalar_range.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const Point = core.circle.CirclePointQM31;
const Air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
pub const Component = struct {
    offsets: [3]usize,
    challenges: Source.Challenges,
    claim: Q,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Component) usize {
        return 3;
    }
    pub fn maxConstraintLogDegreeBound(_: *const Component) u32 {
        return 17;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(_: *const Component, i: usize) !u8 {
        if (i >= 3) return error.InvalidConstraintIndex;
        return 2;
    }
    pub fn traceLogDegreeBounds(_: *const Component, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |v| a.free(v);
        for ([_]usize{ 3, 1, 8 }, &logs) |width, *v| {
            v.* = try points.emptyOrFilledLogs(a, width, 16);
            initialized += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const indices = try a.alloc(usize, 3);
        for (indices, 0..) |*v, i| v.* = self.offsets[0] + i;
        return indices;
    }
    pub fn maskPoints(_: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, 16);
        var masks: [3][][]Point = undefined;
        var initialized: usize = 0;
        errdefer for (masks[0..initialized]) |cols| points.freePointColumns(a, cols);
        for ([_]usize{ 3, 1, 8 }, &masks) |width, *cols| {
            cols.* = try points.currentPointColumns(a, width, point);
            initialized += 1;
        }
        for (masks[2][4..]) |*col| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(col.*);
            col.* = replacement;
        }
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn emitFor(self: *const Component, comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) void {
        Table.rangeFor(F, fixed, main, current, previous, self.claim, self.challenges, sink);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidU16Mask;
        var values: [12]Q = undefined;
        var previous: [8]Q = @splat(Q.zero());
        var cursor: usize = 0;
        for ([_]usize{ 3, 1, 8 }, 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidU16Mask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, i| {
                const prior = tree == 2 and i >= 4;
                if (samples.len != @as(usize, if (prior) 2 else 1)) return error.InvalidU16Mask;
                values[cursor] = samples[0];
                cursor += 1;
                if (prior) previous[i] = samples[1];
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = acc, .scale = try geometry.denominatorInverse(point, global_log, 16) };
        self.emitFor(Q, values[0..3], values[3..4], values[4..12], &previous, &sink);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        var polys: [12]cp.Poly = undefined;
        var cursor: usize = 0;
        if (trace.polys.items.len != 3) return error.InvalidU16Trace;
        for ([_]usize{ 3, 1, 8 }, 0..) |width, tree| {
            if (trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidU16Trace;
            @memcpy(polys[cursor..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
            cursor += width;
        }
        const domain = core.poly.circle.canonic.CanonicCoset.new(17).circleDomain();
        const n = domain.size();
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, 16, 17));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var values: [12][]const M = undefined;
        for (polys, &values) |poly, *v| v.* = try support.evaluationValues(a, poly, 17, n, owned, &initialized);
        if (owned_count != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inv = try geometry.denominatorInverses(a, 16, 17);
        defer a.free(inv);
        const columns = try acc.columns(a, &.{.{ .log_size = 17, .n_cols = 3 }});
        defer a.free(columns);
        var output = columns[0];
        var row: usize = 0;
        while (row < n) : (row += E.LANES) {
            var fields: [12]E.PackedBase = undefined;
            var previous: [8]E.PackedBase = @splat(E.PackedBase.zero());
            for (values, &fields) |column, *v| v.* = E.PackedBase.load(column.ptr + row);
            for (4..8) |c| {
                var lanes: [E.LANES]M = undefined;
                for (&lanes, 0..) |*v, lane| v.* = values[4 + c][core.utils.previousBitReversedCircleDomainIndex(row + lane, 16, 17)];
                previous[c] = E.PackedBase.fromLanes(lanes);
            }
            var accumulator = E.PackedWeightedAccumulator{ .powers = output.random_coeff_powers };
            var sink = E.PackedSink{ .weighted_accumulator = &accumulator };
            self.emitFor(E.PackedBase, fields[0..3], fields[3..4], fields[4..12], &previous, &sink);
            const result = accumulator.accumulation.mulBase(E.PackedBase.splat(inv[row >> 16]));
            const coordinates = result.coordinates();
            const fresh = if (output.next_fresh_index) |next| next == row else false;
            for (output.col.columns, coordinates) |column, coordinate| {
                if (fresh) coordinate.store(column.ptr + row) else E.PackedBase.load(column.ptr + row).add(coordinate).store(column.ptr + row);
            }
            output.next_fresh_index = if (fresh) row + E.LANES else null;
        }
    }
};
