//! Exact caller-original wrapper: preserves every arithmetic/projection
//! equation, elides ONLY its independently checked empty witness tree, and
//! appends per-access halt constraints over the shared current/+27 openings.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = core.air.components;
const CP = engine.air.component_prover;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const Access = @import("block_v8_caller_ram_component_v1.zig");
const Halt = @import("block_v8_caller_halt_policy_v1.zig");
const NativeHalt = @import("block_v8_native_halt_policy_v1.zig");
const Plan = @import("block_v8_endpoint_caller_plan_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const production_active = false;
const Ref = struct { tree: usize, column: usize };
const Requirements = struct {
    a: std.mem.Allocator,
    refs: std.ArrayList(Ref) = .empty,
    fixed: []usize,
    main: []usize,
    fn init(a: std.mem.Allocator, fixed: usize, main: usize) !Requirements {
        const f = try a.alloc(usize, fixed);
        errdefer a.free(f);
        const m = try a.alloc(usize, main);
        @memset(f, std.math.maxInt(usize));
        @memset(m, std.math.maxInt(usize));
        return .{ .a = a, .fixed = f, .main = m };
    }
    fn deinit(self: *Requirements) void {
        self.refs.deinit(self.a);
        self.a.free(self.fixed);
        self.a.free(self.main);
    }
    pub fn at(self: *Requirements, tree: usize, column: usize, ordinal: usize) !Q {
        if (tree > 1 or ordinal > 1) return error.InvalidCallerHaltSample;
        const map = if (tree == 0) self.fixed else self.main;
        if (column >= map.len) return error.InvalidCallerHaltSample;
        if (map[column] == std.math.maxInt(usize)) {
            map[column] = self.refs.items.len;
            try self.refs.append(self.a, .{ .tree = tree, .column = column });
        }
        return Q.zero();
    }
};
pub fn mainLogs(a: std.mem.Allocator, plan: *const Plan.Owned) ![]u32 {
    const logs = try a.alloc(u32, plan.arithmetic_main_columns + plan.halt_main_columns);
    @memcpy(logs[0..plan.arithmetic_main_columns], plan.schedule.main);
    for (plan.ram.descriptors, 0..) |descriptor, index| @memset(logs[plan.arithmetic_main_columns + 2 * index ..][0..2], descriptor.log_size);
    return logs;
}
pub fn prepare(a: std.mem.Allocator, plan: *const Plan.Owned, fixed: []const Column, original: []const Column, policy: Halt.Policy) !NativeHalt.Owned {
    try Halt.validate(policy);
    if (fixed.len != plan.schedule.fixed.len or original.len != plan.arithmetic_main_columns) return error.InvalidCallerHaltColumns;
    const columns = try a.alloc(Column, original.len + plan.halt_main_columns);
    errdefer a.free(columns);
    @memcpy(columns[0..original.len], original);
    var ready = original.len;
    errdefer for (columns[original.len..ready]) |column| a.free(column.values);
    for (plan.ram.descriptors) |descriptor| {
        const rows = @as(usize, 1) << @intCast(descriptor.log_size);
        for (0..2) |_| {
            columns[ready] = .{ .log_size = descriptor.log_size, .values = try a.alloc(M, rows) };
            ready += 1;
        }
        for (0..rows) |row| {
            const Samples = struct {
                fixed: []const Column,
                main: []const Column,
                descriptor: @TypeOf(descriptor),
                row: usize,
                pub fn at(self: @This(), tree: usize, index: usize, ordinal: usize) !Q {
                    const source = if (tree == 0) self.fixed else if (tree == 1) self.main else return error.InvalidCallerHaltSample;
                    if (index >= source.len or source[index].log_size != self.descriptor.log_size or ordinal > 1) return error.InvalidCallerHaltSample;
                    const physical = if (ordinal == 0) self.row else core.utils.offsetBitReversedCircleDomainIndex(self.row, self.descriptor.log_size, self.descriptor.log_size, 27);
                    return Q.fromBase(source[index].values[physical]);
                }
            };
            const access = try Access.accessFromSamples(descriptor, Samples{ .fixed = fixed, .main = original, .descriptor = descriptor, .row = row });
            const aux = try Halt.witness(access.pair, policy);
            @constCast(columns[ready - 2].values)[row] = aux[0];
            @constCast(columns[ready - 1].values)[row] = aux[1];
        }
    }
    return .{ .allocator = a, .original_count = original.len, .columns = columns };
}
pub const Component = struct {
    a: std.mem.Allocator = undefined,
    inner: C.Component,
    prover: ?CP.ComponentProver,
    plan: *const Plan.Owned,
    policy: Halt.Policy,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);
    pub fn init(self: Self, a: std.mem.Allocator) !Self {
        try Halt.validate(self.policy);
        var logs = try self.inner.traceLogDegreeBounds(a);
        defer logs.deinitDeep(a);
        if (logs.items.len != 5 or logs.items[2].len != 0 or logs.items[1].len != self.plan.arithmetic_main_columns or self.plan.ram.descriptors.len == 0) return error.InvalidCallerHaltGeometry;
        var result = self;
        result.a = a;
        return result;
    }
    pub fn asProverComponent(self: *const Self) CP.ComponentProver {
        var out = Adapter.asProverComponent(self);
        if (self.prover) |p| {
            out.pool_exclusive_domain = p.pool_exclusive_domain;
            if (p.domain_parallel_evaluator != null) out.domain_parallel_evaluator = parallel;
        }
        return out;
    }
    pub fn asVerifierComponent(self: *const Self) C.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        return self.inner.nConstraints() + Halt.CONSTRAINT_COUNT * self.plan.ram.descriptors.len;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return @max(2, self.inner.compositionLogSplit());
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        var bound = self.inner.maxConstraintLogDegreeBound();
        for (self.plan.ram.descriptors) |d| bound = @max(bound, d.log_size + 2);
        return bound;
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return self.inner.preprocessedColumnIndices(a);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        var old = try self.inner.traceLogDegreeBounds(a);
        defer old.deinitDeep(a);
        if (old.items.len != 5 or old.items[2].len != 0) return error.NonemptyCallerWitnessTree;
        const out = try a.alloc([]u32, 4);
        @memset(out, &.{});
        var result = C.TraceLogDegreeBounds.initOwned(out);
        errdefer result.deinitDeep(a);
        for ([_]usize{ 0, 1, 3, 4 }, out, 0..) |from, *tree, to| {
            tree.* = try a.alloc(u32, old.items[from].len + if (to == 1) self.plan.halt_main_columns else @as(usize, 0));
            @memcpy(tree.*[0..old.items[from].len], old.items[from]);
        }
        for (self.plan.ram.descriptors, 0..) |d, i| @memset(out[1][self.plan.arithmetic_main_columns + 2 * i ..][0..2], d.log_size);
        return result;
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        var old = try self.inner.maskPoints(a, point, max_log);
        defer old.deinitDeep(a);
        if (old.items.len != 5 or old.items[2].len != 0) return error.NonemptyCallerWitnessTree;
        for (self.plan.ram.descriptors) |d| {
            const Checker = struct {
                masks: *const C.MaskPoints,
                point: Point,
                output: Point,
                pub fn at(self_: @This(), tree: usize, column: usize, ordinal: usize) !Q {
                    if (tree > 1 or ordinal > 1 or column >= self_.masks.items[tree].len) return error.MissingCallerHaltSharedOpening;
                    const wanted = if (ordinal == 0) self_.point else self_.output;
                    for (self_.masks.items[tree][column]) |p| if (std.meta.eql(p, wanted)) return Q.zero();
                    return error.MissingCallerHaltSharedOpening;
                }
            };
            _ = try Access.accessFromSamples(d, Checker{ .masks = &old, .point = point, .output = point.add(@import("../air/logup.zig").liftPoint(Canonic.new(max_log).coset_value.step).mulSigned(27)) });
        }
        const trees = try a.alloc([][]Point, 4);
        @memset(trees, &.{});
        var out = C.MaskPoints.initOwned(trees);
        errdefer out.deinitDeep(a);
        for ([_]usize{ 0, 1, 3, 4 }, trees, 0..) |from, *tree, to| {
            tree.* = try a.alloc([]Point, old.items[from].len + if (to == 1) self.plan.halt_main_columns else @as(usize, 0));
            @memset(tree.*, &.{});
            for (old.items[from], tree.*[0..old.items[from].len]) |points, *dest| dest.* = try a.dupe(Point, points);
            if (to == 1) for (tree.*[old.items[from].len..]) |*dest| {
                dest.* = try a.dupe(Point, &.{point});
            };
        }
        return out;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, values: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (values.items.len != 4 and values.items.len != 5) return error.InvalidCallerHaltMask;
        const base = self.plan.arithmetic_main_columns;
        if (values.items[1].len != base + self.plan.halt_main_columns) return error.InvalidCallerHaltMask;
        var mapped = [_][][]Q{ values.items[0], values.items[1][0..base], &.{}, values.items[2], values.items[3] };
        try self.inner.evaluateConstraintQuotientsAtPoint(point, &.{ .items = &mapped }, accumulator, max_log);
        const a = self.a;
        var masks = try self.inner.maskPoints(a, point, max_log);
        defer masks.deinitDeep(a);
        const Samples = struct {
            masks: *const C.MaskPoints,
            values: *const C.MaskValues,
            point: Point,
            output: Point,
            pub fn at(self_: @This(), tree: usize, column: usize, ordinal: usize) !Q {
                if (tree > 1 or ordinal > 1 or column >= self_.masks.items[tree].len or column >= self_.values.items[tree].len) return error.InvalidCallerHaltMask;
                const wanted = if (ordinal == 0) self_.point else self_.output;
                for (self_.masks.items[tree][column], self_.values.items[tree][column]) |p, value| if (std.meta.eql(p, wanted)) return value;
                return error.MissingCallerHaltSharedOpening;
            }
        };
        const samples = Samples{ .masks = &masks, .values = values, .point = point, .output = point.add(@import("../air/logup.zig").liftPoint(Canonic.new(max_log).coset_value.step).mulSigned(27)) };
        for (self.plan.ram.descriptors, 0..) |d, index| {
            const aux = values.items[1][base + 2 * index ..][0..2];
            if (aux[0].len != 1 or aux[1].len != 1) return error.InvalidCallerHaltMask;
            const checks = try Halt.fromSamples(d, self.policy, samples, .{ aux[0][0], aux[1][0] });
            const inverse = try core.constraints.cosetVanishing(Q, Canonic.new(d.log_size).coset(), point.repeatedDouble(max_log - d.log_size)).inv();
            for (checks) |check| accumulator.accumulate(check.mul(inverse));
        }
    }
    fn parallel(raw: *const anyopaque, trace: *const CP.Trace, accumulator: *DA, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Self = @ptrCast(@alignCast(raw));
        try self.evaluateWithPool(trace, accumulator, pool);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, accumulator: *DA) !void {
        try self.evaluateWithPool(trace, accumulator, null);
    }
    fn evaluateWithPool(self: *const Self, trace: *const CP.Trace, accumulator: *DA, pool: ?*engine.work_pool.WorkPool) !void {
        if (trace.polys.items.len != 4 or trace.polys.items[1].len != self.plan.arithmetic_main_columns + self.plan.halt_main_columns) return error.InvalidCallerHaltTrees;
        const inner = self.prover orelse return error.MissingCallerHaltProver;
        var mapped = [_][]const CP.Poly{ trace.polys.items[0], trace.polys.items[1][0..self.plan.arithmetic_main_columns], &.{}, trace.polys.items[2], trace.polys.items[3] };
        var old = trace.*;
        old.polys = .initOwned(&mapped);
        if (pool) |shared| try inner.evaluateConstraintQuotientsOnDomainParallel(&old, accumulator, shared) else try inner.evaluateConstraintQuotientsOnDomain(&old, accumulator);
        var first: usize = 0;
        while (first < self.plan.ram.descriptors.len) {
            const d = self.plan.ram.descriptors[first];
            var end = first + 1;
            while (end < self.plan.ram.descriptors.len and self.plan.ram.descriptors[end].kind == d.kind and self.plan.ram.descriptors[end].main_offset == d.main_offset and self.plan.ram.descriptors[end].log_size == d.log_size) : (end += 1) {}
            try self.evaluateGroup(trace, accumulator, first, end, pool);
            first = end;
        }
    }
    fn evaluateGroup(self: *const Self, trace: *const CP.Trace, accumulator: *DA, first: usize, end: usize, pool_value: ?*engine.work_pool.WorkPool) !void {
        const a = accumulator.allocator;
        var requirements = try Requirements.init(a, trace.polys.items[0].len, trace.polys.items[1].len);
        defer requirements.deinit();
        for (self.plan.ram.descriptors[first..end], first..) |d, i| {
            _ = try Access.accessFromSamples(d, &requirements);
            _ = try requirements.at(1, self.plan.arithmetic_main_columns + 2 * i, 0);
            _ = try requirements.at(1, self.plan.arithmetic_main_columns + 2 * i + 1, 0);
        }
        const d = self.plan.ram.descriptors[first];
        const eval_log = d.log_size + 2;
        const domain = Canonic.new(eval_log).circleDomain();
        const support = @import("../recursion/air/universal_typed_component_contract.zig");
        const polys = try a.alloc(CP.Poly, requirements.refs.items.len);
        defer a.free(polys);
        var owned_count: usize = 0;
        for (requirements.refs.items, polys) |ref, *poly| {
            poly.* = trace.polys.items[ref.tree][ref.column];
            owned_count += @intFromBool(try support.sourceNeedsExtension(poly.*, d.log_size, eval_log));
        }
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const values = try a.alloc([]const M, polys.len);
        defer a.free(values);
        var twiddles = if (owned_count != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
        defer if (twiddles) |*tree| engine.poly.twiddles.deinitM31(a, tree);
        const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |tree| .init(tree.root_coset, tree.twiddles, tree.itwiddles) else null;
        for (polys, values) |poly, *value| value.* = try support.evaluationValues(a, poly, d.log_size, eval_log, domain.size(), transform, owned, &initialized);
        if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
        var inverse: [4]M = undefined;
        for (&inverse, 0..) |*v, i| v.* = try core.constraints.cosetVanishing(M, Canonic.new(d.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 2))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = Halt.CONSTRAINT_COUNT * (end - first) }});
        defer a.free(output);
        var lease: ?engine.work_pool.WorkLease = null;
        if (pool_value) |pool| {
            const workers = @min(pool.workerCount(), @max(@as(usize, 1), domain.size() / 64));
            if (workers > 1) lease = pool.acquire(try engine.work_pool.WorkerBudget.init(workers)) catch |err| switch (err) {
                error.WorkerBudgetUnavailable => null,
                else => return err,
            };
        }
        defer if (lease) |*held| held.deinit();
        const workers = if (lease) |*held| held.workerCount() else 1;
        var jobs: [engine.work_pool.MAX_WORKERS]HaltRowJob = undefined;
        var wait = std.Thread.WaitGroup{};
        {
            defer {
                wait.wait();
                if (lease) |*held| held.completeWave();
            }
            for (jobs[0..workers], 0..) |*job, worker| {
                job.* = .{ .component = self, .requirements = &requirements, .values = values, .first = first, .end = end, .inverse = inverse, .result = output[0], .begin_row = domain.size() * worker / workers, .end_row = domain.size() * (worker + 1) / workers };
                if (worker + 1 < workers) try lease.?.spawnWg(&wait, HaltRowJob.run, .{job}) else job.run();
            }
        }
        for (jobs[0..workers]) |job| if (job.failure) |err| return err;
    }
};

const HaltRowJob = struct {
    component: *const Component,
    requirements: *const Requirements,
    values: []const []const M,
    first: usize,
    end: usize,
    inverse: [4]M,
    result: engine.air.accumulation.ColumnAccumulator,
    begin_row: usize,
    end_row: usize,
    failure: ?anyerror = null,
    fn run(self: *HaltRowJob) void {
        self.fill() catch |err| {
            self.failure = err;
        };
    }
    fn fill(self: *HaltRowJob) !void {
        const component = self.component;
        const d = component.plan.ram.descriptors[self.first];
        const Samples = struct {
            requirements: *const Requirements,
            values: []const []const M,
            row: usize,
            log: u32,
            pub fn at(self_: @This(), tree: usize, column: usize, ordinal: usize) !M {
                if (tree > 1 or ordinal > 1) return error.InvalidCallerHaltSample;
                const map = if (tree == 0) self_.requirements.fixed else self_.requirements.main;
                if (column >= map.len or map[column] >= self_.values.len) return error.InvalidCallerHaltSample;
                const physical = if (ordinal == 0) self_.row else core.utils.offsetBitReversedCircleDomainIndex(self_.row, self_.log, self_.log + 2, 27);
                return self_.values[map[column]][physical];
            }
        };
        // Each job owns a disjoint row interval and its own accumulator cursor.
        // The immutable coefficients and source evaluations are shared.
        var result = self.result;
        for (self.begin_row..self.end_row) |row| {
            const samples = Samples{ .requirements = self.requirements, .values = self.values, .row = row, .log = d.log_size };
            var folded = Q.zero();
            for (component.plan.ram.descriptors[self.first..self.end], self.first..) |descriptor, i| {
                const access = try Access.accessFromSamplesAs(M, descriptor, samples);
                const aux: [2]M = .{ self.values[self.requirements.main[component.plan.arithmetic_main_columns + 2 * i]][row], self.values[self.requirements.main[component.plan.arithmetic_main_columns + 2 * i + 1]][row] };
                const checks = NativeHalt.constraints(M, component.policy, access.pair.active, access.pair.source_address, access.instruction_cycle, access.pair.after, aux);
                for (checks, 0..) |check, k| folded = folded.add(result.random_coeff_powers[result.random_coeff_powers.len - 1 - (i - self.first) * Halt.CONSTRAINT_COUNT - k].mulM31(check));
            }
            result.accumulate(row, folded.mulM31(self.inverse[row >> @intCast(d.log_size)]));
        }
    }
};
