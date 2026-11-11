//! CPU evaluation of receiver-derived hybrid IR. Public Eq auxiliaries are
//! reconstructed from the verified GKR point, never read from committed masks.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const HC = @import("hybrid_component.zig");
const H = @import("hybrid_air.zig");
const P = @import("profile.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const Aux = @import("../word16_global_execution/services/gkr_local/public_aux.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const Pack = core.fields.packed_om31;
const PA = engine.air.component_prover.ForField(O);
const DA = engine.air.accumulation.ForField(O);
const Polynomial = @import("cpu_polynomial.zig");
const Native = @import("cpu_native.zig");
pub var test_failure: ?P.Component = null;
const Col = struct { polynomial: PA.Poly = undefined, offset: i8 = 0, carry: ?[8][]const M.M31 = null, zero: bool = false };
const Work = struct {
    component: *const HC.Component,
    plan: *const Polynomial.Plan,
    scratch: []Polynomial.Workspace,
    native: ?*const Native.Prepared = null,
    accumulator: DA.ColumnAccumulator,
    mutex: std.Thread.Mutex = .{},
    failure: ?anyerror = null,
    pub fn runRange(self: *@This(), shard: usize, first: usize, end: usize) void {
        self.run(shard, first, end) catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.failure = err;
        };
    }
    fn run(self: *@This(), shard: usize, first: usize, end: usize) !void {
        if (self.native) |native| return native.evaluateRange(first * M.PACK_WIDTH, end * M.PACK_WIDTH);
        const c = self.component;
        const log = c.source.trace_log_size;
        const values = &self.scratch[shard];
        const program = &c.artifact.program;
        for (first..end) |tile| {
            const row = tile * M.PACK_WIDTH;
            try values.evaluate(self.plan, row);
            var total = Pack.splat(O.zero());
            for (program.roots, 0..) |root, i| {
                const coefficient = Pack.splat(self.accumulator.random_coeff_powers[program.roots.len - 1 - i]);
                total = total.add(if (self.plan.sorts[root] == .base) coefficient.mulBase(values.baseValue(self.plan, root)) else Pack.mul(coefficient, values.value(self.plan, root)));
            }
            const inverse = c.source.denominator_inverses[row >> @intCast(log)];
            total = total.mulBase(@as(M.PackedM31, @splat(inverse)));
            inline for (0..M.PACK_WIDTH) |lane| self.accumulator.accumulate(row + lane, Pack.lane(total, lane));
        }
    }
};
pub fn evaluate(c: *const HC.Component, trace: *const PA.Trace, acc: *DA.DomainEvaluationAccumulator) !void {
    if (@import("builtin").is_test) if (test_failure) |kind| if (kind == c.artifact.component) return error.InjectedHybridDomainFailure;
    const a = acc.allocator;
    const log = c.source.trace_log_size;
    if (log < 4 or c.source.evaluation_log_size != log + 1) return error.InvalidHybridMaskGeometry;
    var timer: ?std.time.Timer = if (c.cpu_metrics != null) try std.time.Timer.start() else null;
    var aux: [10]?engine.poly.circle.CircleEvaluation = @splat(null);
    defer for (aux) |maybe| if (maybe) |evaluation| a.free(evaluation.values);
    if (P.gkrBound(c.artifact.component)) {
        const point = c.verified.artifact.ood_point;
        const row_point = try MP.MleEvalPointFor(O).init(point[point.len - log ..]);
        var coefficients = try Aux.initWithLogBound(a, &row_point, log, P.MAX_VARIABLES, engine.work_pool.currentScopedPool());
        defer for (&coefficients) |*coefficient| coefficient.deinit(a);
        const evaluations = try @import("cpu_aux.zig").evaluate(a, &coefficients, log);
        for (evaluations, &aux) |evaluation, *slot| slot.* = evaluation;
    }
    const aux_ns = if (timer) |*clock| clock.lap() else 0;
    const program = &c.artifact.program;
    const reads = try a.alloc(Col, program.inputs.len);
    defer a.free(reads);
    for (program.inputs, reads) |input, *read| {
        if (P.gkrBound(c.artifact.component) and input.tree == 2 and input.column >= 16) {
            if (input.column >= 26 or input.offset != 0) return error.InvalidHybridInteractionMask;
            read.* = switch (input.column) {
                16, 17 => .{ .polynomial = .{ .log_size = log + 1, .values = aux[8 + input.column - 16].?.values } },
                18 => blk: {
                    var carry: [8][]const M.M31 = undefined;
                    for (&carry, aux[0..8]) |*column, evaluation| column.* = evaluation.?.values;
                    break :blk .{ .carry = carry };
                },
                else => .{ .zero = true },
            };
        } else {
            const index = switch (input.tree) {
                0 => c.source.preprocessed_indices[input.column],
                1 => (try Outer.geometry.span(c.source.*, 1)).start + input.column,
                2 => H.interactionStart(c.artifact.component) + input.column,
                else => return error.InvalidHybridMaskTree,
            };
            if (input.tree >= trace.polys.items.len or index >= trace.polys.items[input.tree].len) return error.MissingHybridMask;
            const polynomial = trace.polys.items[input.tree][index];
            if (polynomial.values.len == 0 or polynomial.device != null) return error.HybridCpuRequiresHostLde;
            read.* = .{ .polynomial = polynomial, .offset = input.offset };
        }
    }
    const inputs = try a.alloc(Polynomial.Input, reads.len);
    defer a.free(inputs);
    for (reads, inputs) |read, *input| {
        if (read.zero) {
            input.* = .zero;
        } else if (read.carry) |carry| {
            input.* = .{ .secure = .{ .values = carry, .offset = read.offset } };
        } else {
            try read.polynomial.validate();
            input.* = .{ .base = .{ .values = read.polynomial.values, .log = read.polynomial.log_size, .offset = read.offset } };
        }
    }
    var plan = try Polynomial.Plan.init(a, program, inputs, c.parameters, log);
    defer plan.deinit();
    const tiles = (@as(usize, 1) << @intCast(log + 1)) / M.PACK_WIDTH;
    const pool_limit = if (engine.work_pool.cooperative.current() != null) 1 else if (engine.work_pool.currentScopedPool()) |pool| @min(engine.lookups.row_work.MAX_SHARDS, pool.availableWorkers()) else 1;
    const shards = @max(1, @min(pool_limit, tiles / 256));
    const columns = try acc.columns(a, &.{.{ .log_size = log + 1, .n_cols = program.roots.len }});
    defer a.free(columns);
    columns[0].next_fresh_index = null;
    var native = if (Native.enabled()) try Native.Prepared.init(a, c.artifact, c.source, inputs, c.parameters, columns[0]) else null;
    defer if (native) |*owner| owner.deinit();
    var scratch: [engine.lookups.row_work.MAX_SHARDS]Polynomial.Workspace = undefined;
    var made: usize = 0;
    defer for (scratch[0..made]) |*values| values.deinit();
    for (scratch[0..if (native == null) shards else 0]) |*values| {
        values.* = try Polynomial.Workspace.init(a, &plan);
        made += 1;
    }
    const prepare_ns = if (timer) |*clock| clock.lap() else 0;
    var work = Work{ .component = c, .plan = &plan, .scratch = scratch[0..made], .accumulator = columns[0], .native = if (native) |*prepared| prepared else null };
    const actual = engine.lookups.row_work.forEachRange(tiles, &work, .{ .max_shards = shards, .min_rows_per_shard = 256 });
    if (work.failure) |err| return err;
    if (c.cpu_metrics) |metrics| {
        _ = metrics.calls.fetchAdd(1, .monotonic);
        _ = metrics.compiled_calls.fetchAdd(@intFromBool(native != null), .monotonic);
        _ = metrics.aux_ns.fetchAdd(aux_ns, .monotonic);
        _ = metrics.prepare_ns.fetchAdd(prepare_ns, .monotonic);
        _ = metrics.rows_ns.fetchAdd(timer.?.read(), .monotonic);
        metrics.base_nodes.store(plan.initial.base.len, .monotonic);
        metrics.secure_nodes.store(plan.initial.secure.len, .monotonic);
        metrics.invariant_nodes.store(program.nodes.len - plan.steps.len, .monotonic);
        metrics.workspace_bytes.store((made + 1) * (plan.initial.base.len * @sizeOf(M.PackedM31) + plan.initial.secure.len * @sizeOf(Pack.PackedOM31)), .monotonic);
        metrics.allocated_slots.store(made, .monotonic);
        metrics.actual_shards.store(actual, .monotonic);
    }
}
