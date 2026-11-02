//! Concrete full64 CPU adapter: one authority for SIMD, QM31 and circuit OODS.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const Eq = @import("equations.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const COLUMNS = 3 + L.main.COUNT + L.inter.COUNT;
pub const Component = ComponentFor(Q);
pub fn ComponentFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct {
        log_size: u32,
        offsets: [3]usize,
        public: T.InputsFor(C),
        claim: C,
        challenges: T.ChallengesFor(C),
        /// Opt-in fused-tail interaction (36 columns, 51 residuals). Default
        /// false keeps the historical 40-column transcript byte-identical.
        fused: bool = false,
        /// Opt-in byte-pair lookups (requires `fused`): the AND relation's
        /// challenges. Null keeps the fused (or legacy) encoding.
        pairs: ?Eq.PairChallengesFor(C) = null,
        /// Opt-in compact decode MAIN (requires `pairs`): 37 MAIN columns,
        /// PC read from the previous row, immediates in the unused operand slot.
        compact: bool = false,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallel;
            result.pool_exclusive_domain = true;
            // Domain splits go only through the shared row/column providers.
            result.cooperative_domain = true;
            return result;
        }
        fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, acc, pool);
        }
        pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            if (self.compact) return Eq.COMPACT_CONSTRAINTS;
            return Eq.constraintCountFor(self.fused, self.pairs != null);
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn widths(self: *const Self) [3]usize {
            return .{ 3, L.mainCount(self.compact), L.interCountFor(self.fused, self.pairs != null) };
        }
        pub fn needsPrevious(self: *const Self, tree: usize, column: usize) bool {
            return if (tree == 1) L.previousMainFor(self.compact, column) else tree == 2 and L.previousInterMode(self.fused, self.pairs != null, column);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            if (self.log_size < L.MIN_LOG or self.log_size > L.MAX_LOG) return error.InvalidExecutionGeometry;
            if (comptime C == Q) try self.validatePublic();
            var logs: [3][]u32 = undefined;
            var done: usize = 0;
            errdefer for (logs[0..done]) |data| a.free(data);
            for (self.widths(), &logs) |width, *data| {
                data.* = try points.emptyOrFilledLogs(a, width, self.log_size);
                done += 1;
            }
            return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const data = try a.alloc(usize, 3);
            for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
            return data;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, global_log: u32) !core.air.components.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            var masks: [3][][]core.circle.CirclePointQM31 = undefined;
            var done: usize = 0;
            errdefer for (masks[0..done]) |data| points.freePointColumns(a, data);
            for (self.widths(), &masks, 0..) |width, *data, tree| {
                data.* = try points.currentPointColumns(a, width, point);
                done += 1;
                for (data.*, 0..) |*column, c| if (self.needsPrevious(tree, c)) {
                    const replacement = try a.dupe(core.circle.CirclePointQM31, &.{ point, geometry.previousPoint(point, global_log) });
                    a.free(column.*);
                    column.* = replacement;
                };
            }
            return core.air.components.MaskPoints.initOwned(try a.dupe([][]core.circle.CirclePointQM31, &masks));
        }
        /// Compact decode is defined only on top of the byte-pair encoding and
        /// requires canonical sub-2^31 endpoints (types.validateCompactInputs).
        pub fn validatePublic(self: *const Self) !void {
            if (self.compact and (self.pairs == null or !self.fused)) return error.InvalidExecutionGeometry;
            return if (self.compact) T.validateCompactInputs(self.public, self.log_size) else T.validateInputs(self.public, self.log_size);
        }
        pub fn emitFor(self: *const Self, comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, sink: *E.SinkFor(F)) void {
            if (self.compact) {
                Eq.emitCompactFor(F, f, m, pm, i, pi, self.public, self.claim, self.challenges, self.pairs.?, sink);
            } else if (self.pairs) |pair_ch| {
                Eq.emitPairsFor(F, f, m, pm, i, pi, self.public, self.claim, self.challenges, pair_ch, sink);
            } else if (self.fused) {
                Eq.emitFusedFor(F, f, m, pm, i, pi, self.public, self.claim, self.challenges, sink);
            } else Eq.emitFor(F, f, m, pm, i, pi, self.public, self.claim, self.challenges, sink);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = acc };
            try self.evaluateQuotientsAtPointFor(Q, point, global_log, E.lane.NativeMasks{ .values = mask }, &sink);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != C) @compileError("execution component lane mismatch");
            if (comptime C == Q) try self.validatePublic();
            if (self.compact and self.pairs == null) return error.InvalidExecutionGeometry;
            var fixed: [3]F = undefined;
            var main: [L.main.COUNT]F = undefined;
            var pm: [L.main.COUNT]F = @splat(F.zero());
            var inter: [L.inter.COUNT]F = undefined;
            var pi: [L.inter.COUNT]F = @splat(F.zero());
            for (&fixed, 0..) |*v, c| v.* = try E.lane.sample(F, masks, 0, self.offsets[0] + c, 0, 1);
            const main_count = L.mainCount(self.compact);
            for (main[0..main_count], 0..) |*v, c| {
                const prior = L.previousMainFor(self.compact, c);
                v.* = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 0, if (prior) 2 else 1);
                if (prior) pm[c] = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 1, 2);
            }
            const inter_count = L.interCountFor(self.fused, self.pairs != null);
            for (inter[0..inter_count], 0..) |*v, c| {
                const prior = L.previousInterMode(self.fused, self.pairs != null, c);
                v.* = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 0, if (prior) 2 else 1);
                if (prior) pi[c] = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            self.emitFor(F, &fixed, main[0..main_count], pm[0..main_count], inter[0..inter_count], pi[0..inter_count], sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, acc, null);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            comptime if (C != Q) @compileError("external lane has no native domain evaluator");
            if (self.log_size < L.MIN_LOG or self.log_size > L.MAX_LOG or trace.polys.items.len != 3) return error.InvalidExecutionGeometry;
            try self.validatePublic();
            const a = acc.allocator;
            var polys: [COLUMNS]cp.Poly = undefined;
            var at: usize = 0;
            for (self.widths(), 0..) |width, tree| {
                if (trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidExecutionShape;
                @memcpy(polys[at..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
                at += width;
            }
            const log = self.log_size + 1;
            const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
            const n = domain.size();
            const total = at;
            var count: usize = 0;
            for (polys[0..total]) |poly| count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, log));
            const owned = try a.alloc([]M, count);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |data| a.free(data);
                a.free(owned);
            }
            var evals: [COLUMNS][]const M = undefined;
            for (polys[0..total], evals[0..total]) |poly, *data| data.* = try support.evaluationValues(a, poly, log, n, owned, &initialized);
            if (count != 0) {
                var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &tw);
                try @import("../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles), pool);
            }
            const inverses = try geometry.denominatorInverses(a, self.log_size, log);
            defer a.free(inverses);
            const columns = try acc.columns(a, &.{.{ .log_size = log, .n_cols = self.nConstraints() }});
            defer a.free(columns);
            var output = columns[0];
            const rows = Rows{ .component = self, .columns = evals[0..total], .inverses = inverses };
            try @import("../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, n, &output, pool);
        }
    };
}
const Rows = struct {
    component: *const Component,
    columns: []const []const M,
    inverses: []const M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, output: *accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Rows = @ptrCast(@alignCast(ctx));
        return @import("packed_rows.zig").evaluate(self.component, self.columns, start, end, self.inverses, output);
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub const packedRows = @import("packed_rows.zig");
} else struct {};
