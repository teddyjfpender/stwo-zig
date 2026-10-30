//! Prover-only batching of the existing physical projection equations.
//! Every original claim, mask, coefficient and OODS equation remains separate.
//! Typed opcode entries are derived once per row and batch, not once per slot.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const C = core.air.components;
const CP = engine.air.component_prover;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;
const Point = core.circle.CirclePointQM31;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const ProjectionModule = @import("block_v5_native_projection_fused_component_v1.zig");
const Projection = ProjectionModule.Component;
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Recipes = @import("block_v7_native_projection_batch_v1.zig");
const Opcode = @import("../runner/trace.zig");
const Pool = engine.work_pool;
pub const production_active = false;
pub const Options = struct {
    max_batch_slots: usize = 8,
    max_interaction_workspace_bytes: usize = 1 << 30,
};
const Group = struct { indices: []usize };
pub const Owned = struct {
    a: std.mem.Allocator,
    projections: []const Projection,
    originals: []const C.Component,
    groups: []Group,
    options: Options,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);

    pub fn init(a: std.mem.Allocator, projections: []const Projection, originals: []const C.Component, options: Options) !*Self {
        if (projections.len == 0 or projections.len != originals.len or projections.len > 4096 or options.max_batch_slots == 0 or options.max_batch_slots > 32 or options.max_interaction_workspace_bytes == 0) return error.InvalidProjectionDomainBatch;
        const first = projections[0];
        for (projections, 0..) |item, i| {
            if (item.root_owner != (i == 0) or item.composition_split != first.composition_split or item.relations != first.relations or item.fixed_logs.ptr != first.fixed_logs.ptr or item.main_logs.ptr != first.main_logs.ptr or item.interaction_logs.ptr != first.interaction_logs.ptr) return error.InvalidProjectionDomainBatch;
        }
        const self = try a.create(Self);
        errdefer a.destroy(self);
        var groups: std.ArrayList(Group) = .empty;
        errdefer {
            for (groups.items) |group| a.free(group.indices);
            groups.deinit(a);
        }
        const seen = try a.alloc(bool, projections.len);
        defer a.free(seen);
        @memset(seen, false);
        for (projections, 0..) |item, i| {
            if (seen[i]) continue;
            var ids: std.ArrayList(usize) = .empty;
            defer ids.deinit(a);
            for (projections[i..], i..) |other, j| if (!seen[j] and Recipes.sameSource(item.slot, other.slot)) {
                if (other.slot.register_custody_mode != item.slot.register_custody_mode) return error.InvalidProjectionDomainBatch;
                try ids.append(a, j);
                seen[j] = true;
            };
            const indices = try ids.toOwnedSlice(a);
            groups.append(a, .{ .indices = indices }) catch |err| {
                a.free(indices);
                return err;
            };
        }
        self.* = .{ .a = a, .projections = projections, .originals = originals, .groups = try groups.toOwnedSlice(a), .options = options };
        return self;
    }
    pub fn deinit(self: *Self) void {
        const a = self.a;
        for (self.groups) |group| a.free(group.indices);
        a.free(self.groups);
        a.destroy(self);
    }
    pub fn asProverComponent(self: *const Self) CP.ComponentProver {
        var out = Adapter.asProverComponent(self);
        // Rows are parallelized internally; no concurrent writers may update
        // the same composition accumulator bucket from another component.
        out.pool_exclusive_domain = true;
        out.domain_parallel_evaluator = parallel;
        return out;
    }
    pub fn nConstraints(self: *const Self) usize {
        return self.projections.len;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.projections[0].composition_split;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        var bound: u32 = 0;
        for (self.projections) |item| bound = @max(bound, item.maxConstraintLogDegreeBound());
        return bound;
    }
    pub fn constraintDegreeBound(self: *const Self, i: usize) !u8 {
        if (i >= self.projections.len) return error.InvalidConstraintIndex;
        return self.projections[i].slot.degree;
    }
    pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        const first = self.projections[0];
        const fixed = try a.dupe(u32, first.fixed_logs);
        errdefer a.free(fixed);
        const main = try a.dupe(u32, first.main_logs);
        errdefer a.free(main);
        const interactions = try a.alloc(u32, 4 * self.projections.len);
        errdefer a.free(interactions);
        for (self.projections, 0..) |item, i| @memset(interactions[4 * i ..][0..4], item.slot.log_size);
        return .initOwned(try a.dupe([]u32, &.{ fixed, main, interactions }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        return (C.Components{ .components = self.originals, .n_preprocessed_columns = self.projections[0].fixed_logs.len }).maskPoints(a, point, max_log, false);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        for (self.originals) |original| try original.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
    }
    fn parallel(raw: *const anyopaque, trace: *const CP.Trace, accumulator: *DA, pool: *Pool.WorkPool) anyerror!void {
        const self: *const Self = @ptrCast(@alignCast(raw));
        try self.evaluateWithPool(trace, accumulator, pool);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, accumulator: *DA) !void {
        try self.evaluateWithPool(trace, accumulator, Pool.currentScopedPool());
    }
    fn evaluateWithPool(self: *const Self, trace: *const CP.Trace, accumulator: *DA, pool: ?*Pool.WorkPool) !void {
        if (trace.polys.items.len != 3) return error.InvalidProjectionDomainBatch;
        const a = accumulator.allocator;
        const requests = try a.alloc(engine.air.accumulation.ColumnRequest, self.projections.len);
        defer a.free(requests);
        for (requests, self.projections) |*request, item| request.* = .{ .log_size = item.slot.log_size + item.composition_split, .n_cols = 1 };
        // Allocate coefficients in ORIGINAL slot order, before grouping. Each
        // row worker adds to its own disjoint row in the existing bucket.
        const output = try accumulator.columns(a, requests);
        defer a.free(output);
        for (self.groups) |group| try self.evaluateGroup(a, trace, group.indices, output, pool);
    }
    fn evaluateGroup(self: *const Self, a: std.mem.Allocator, trace: *const CP.Trace, ids: []const usize, output: []engine.air.accumulation.ColumnAccumulator, pool: ?*Pool.WorkPool) !void {
        const first = self.projections[ids[0]];
        const slot = first.slot;
        const eval_log = slot.log_size + first.composition_split;
        const domain = Canonic.new(eval_log).circleDomain();
        const size = domain.size();
        const width = slot.width;
        if (slot.main_offset > trace.polys.items[1].len or width > trace.polys.items[1].len - slot.main_offset) return error.InvalidProjectionDomainBatch;
        var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        const transform: engine.poly.twiddles.TwiddleTree([]const M) = .init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
        const main = try a.alloc([]const M, width);
        defer a.free(main);
        const owned_main = try a.alloc([]M, width);
        defer a.free(owned_main);
        var main_count: usize = 0;
        defer for (owned_main[0..main_count]) |column| a.free(column);
        const CacheLease = @import("block_v7_leased_quotient_cache_v1.zig").Lease;
        const leases = try a.alloc(CacheLease, width);
        defer a.free(leases);
        var lease_count: usize = 0;
        defer for (leases[0..lease_count]) |*lease| lease.release();
        for (main, 0..) |*value, i| {
            const poly = trace.polys.items[1][slot.main_offset + i];
            if (first.leased_quotient_cache) |cache| if (try cache.get(.lookup, poly, slot.log_size, eval_log, transform)) |lease| {
                leases[lease_count] = lease;
                lease_count += 1;
                value.* = lease.values;
                continue;
            };
            value.* = try ProjectionModule.domainValues(a, poly, slot.log_size, eval_log, size, owned_main, &main_count);
        }
        if (main_count != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned_main[0..main_count], domain, transform);
        const inverses = try a.alloc(M, @as(usize, 1) << @intCast(first.composition_split));
        defer a.free(inverses);
        for (inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, Canonic.new(slot.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, first.composition_split))).inv();
        const per_slot = try std.math.mul(usize, size, 4 * @sizeOf(M));
        const batch_slots = @min(self.options.max_batch_slots, @max(@as(usize, 1), self.options.max_interaction_workspace_bytes / per_slot));
        var begin: usize = 0;
        while (begin < ids.len) {
            const selected = ids[begin..@min(ids.len, begin + batch_slots)];
            try self.evaluateBatch(a, trace, selected, main, inverses, output, transform, pool);
            begin += selected.len;
        }
    }
    fn evaluateBatch(self: *const Self, a: std.mem.Allocator, trace: *const CP.Trace, ids: []const usize, main: []const []const M, inverses: []const M, output: []engine.air.accumulation.ColumnAccumulator, transform: engine.poly.twiddles.TwiddleTree([]const M), pool_value: ?*Pool.WorkPool) !void {
        const first = self.projections[ids[0]];
        const log = first.slot.log_size;
        const eval_log = log + first.composition_split;
        const domain = Canonic.new(eval_log).circleDomain();
        const interactions = try a.alloc([]const M, 4 * ids.len);
        defer a.free(interactions);
        const owned = try a.alloc([]M, interactions.len);
        defer a.free(owned);
        var count: usize = 0;
        defer for (owned[0..count]) |column| a.free(column);
        const normalized = try a.alloc(Q, ids.len);
        defer a.free(normalized);
        for (ids, 0..) |id, i| {
            const item = self.projections[id];
            if (item.interaction_offset > trace.polys.items[2].len or 4 > trace.polys.items[2].len - item.interaction_offset) return error.InvalidProjectionDomainBatch;
            normalized[i] = try item.claim.divM31(M.fromU64(@as(usize, 1) << @intCast(log)));
            for (0..4) |j| interactions[4 * i + j] = try ProjectionModule.domainValues(a, trace.polys.items[2][item.interaction_offset + j], log, eval_log, domain.size(), owned, &count);
        }
        if (count != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..count], domain, transform);
        var lease: ?Pool.WorkLease = null;
        if (pool_value) |pool| {
            const workers = @min(pool.workerCount(), @max(@as(usize, 1), domain.size() / 256));
            if (workers > 1) lease = pool.acquire(try Pool.WorkerBudget.init(workers)) catch |err| switch (err) {
                error.WorkerBudgetUnavailable => null,
                else => return err,
            };
        }
        defer if (lease) |*held| held.deinit();
        const workers = if (lease) |*held| held.workerCount() else 1;
        var jobs: [Pool.MAX_WORKERS]RowJob = undefined;
        var wait = std.Thread.WaitGroup{};
        {
            defer {
                wait.wait();
                if (lease) |*held| held.completeWave();
            }
            for (jobs[0..workers], 0..) |*job, worker| {
                job.* = .{ .owner = self, .ids = ids, .main = main, .interactions = interactions, .normalized = normalized, .inverses = inverses, .output = output, .begin = domain.size() * worker / workers, .end = domain.size() * (worker + 1) / workers };
                if (worker + 1 < workers) try lease.?.spawnWg(&wait, RowJob.run, .{job}) else job.run();
            }
        }
        for (jobs[0..workers]) |job| if (job.failure) |err| return err;
    }
};
const RowJob = struct {
    owner: *const Owned,
    ids: []const usize,
    main: []const []const M,
    interactions: []const []const M,
    normalized: []const Q,
    inverses: []const M,
    output: []engine.air.accumulation.ColumnAccumulator,
    begin: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *RowJob) void {
        self.fill() catch |err| {
            self.failure = err;
        };
    }
    fn fill(self: *RowJob) !void {
        const first = self.owner.projections[self.ids[0]];
        const slot = first.slot;
        const eval_log = slot.log_size + first.composition_split;
        const shift: std.math.Log2Int(usize) = @intCast(slot.log_size);
        for (self.begin..self.end) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, slot.log_size, eval_log);
            var cells: [Opcode.MAX_FAMILY_COLUMNS]M = undefined;
            for (self.main, cells[0..slot.width]) |column, *cell| cell.* = column[row];
            const entries = try Source.baseEntries(slot, cells[0..slot.width]);
            var total = Q.zero();
            for (self.ids, 0..) |id, i| {
                const item = self.owner.projections[id];
                var current: [4]Q = undefined;
                var previous: [4]Q = undefined;
                for (&current, &previous, 0..) |*now, *old, j| {
                    now.* = Q.fromBase(self.interactions[4 * i + j][row]);
                    old.* = Q.fromBase(self.interactions[4 * i + j][prior]);
                }
                const request = try Source.fromBaseEntries(item.slot, &entries, item.relations);
                const equation = Q.fromPartialEvals(current).sub(Q.fromPartialEvals(previous)).add(self.normalized[i]).mul(request.denominator()).sub(request.numerator());
                total = total.add(equation.mul(self.output[id].random_coeff_powers[0]));
            }
            const target = self.output[self.ids[0]].col;
            target.set(row, target.at(row).add(total.mulM31(self.inverses[row >> shift])));
        }
    }
};
