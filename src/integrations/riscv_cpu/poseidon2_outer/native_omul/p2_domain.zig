//! R6-only execution adapter for the existing P2 packed equations. It changes
//! neither constraint authority nor order. The wide-field engine visits AIRs
//! sequentially, so one bounded lease can split column expansion and rows.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const P2 = @import("../component.zig").Component;
const A = @import("../authority.zig");
const L = @import("../layout.zig");
const Lane = @import("../domain_lane.zig");
const Packed = Core.fields.packed_om31;
const MF = Core.fields.m31;
const M = MF.M31;
const PC = Engine.air.component_prover.ForField(A.O);
const Domain = Engine.air.accumulation.ForField(A.O);
const Poly = Engine.air.component_trace.Poly;
const COUNT = L.FIXED_COLUMNS + L.MAIN_COLUMNS + L.CLASSIC_INTERACTION_COLUMNS;
const vtable: PC.ComponentProverVTable = blk: {
    var table = P2.Adapter.asProverComponent(@as(*const P2, undefined)).vtable.*;
    table.evaluateConstraintQuotientsOnDomain = evaluate;
    break :blk table;
};
pub fn adapter(component: *const P2) PC.ComponentProver {
    var out = P2.Adapter.asProverComponent(component);
    out.vtable = &vtable;
    return out;
}
const Prepared = struct {
    allocator: std.mem.Allocator,
    columns: []Poly,
    owned: []bool,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    log: u32,
    fn init(a: std.mem.Allocator, trace: *const PC.Trace, log: u32) !Prepared {
        const columns = try a.alloc(Poly, COUNT);
        errdefer a.free(columns);
        const owned = try a.alloc(bool, COUNT);
        errdefer a.free(owned);
        @memset(owned, false);
        var at: usize = 0;
        for ([_]usize{ L.FIXED_COLUMNS, L.MAIN_COLUMNS, L.CLASSIC_INTERACTION_COLUMNS }, 0..) |width, t| {
            const start = switch (t) {
                0 => A.FIXED_START[3],
                1 => A.MAIN_START[3],
                2 => A.INTER_START[3],
                else => unreachable,
            };
            if (t >= trace.polys.items.len or start > trace.polys.items[t].len or width > trace.polys.items[t].len - start or at > columns.len or width > columns.len - at) return error.InvalidPoseidonTraceShape;
            for (columns[at..][0..width], trace.polys.items[t][start..][0..width]) |*out, source| out.* = source;
            at += width;
        }
        return .{ .allocator = a, .columns = columns, .owned = owned, .log = log };
    }
    fn deinit(self: *Prepared) void {
        for (self.columns, self.owned) |column, owned| if (owned) self.allocator.free(@constCast(column.values));
        self.allocator.free(self.columns);
        self.allocator.free(self.owned);
    }
};
const Expand = struct {
    prepared: *Prepared,
    failure: ?anyerror = null,
    fn run(self: *Expand) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Expand) !void {
        const p = self.prepared;
        while (true) {
            const index = p.next.fetchAdd(1, .monotonic);
            if (index >= p.columns.len) return;
            const source = p.columns[index];
            try source.validate();
            if (source.device != null) return error.DeviceColumnRequiresBackend;
            if (source.log_size == p.log and source.values.len != 0) continue;
            const coefficients = source.coefficients orelse return error.PoseidonQuotientRequiresCoefficients;
            if (coefficients.logSize() > p.log) return error.InvalidPoseidonQuotientDegree;
            const values = try coefficients.evaluate(p.allocator, Core.poly.circle.canonic.CanonicCoset.new(p.log).circleDomain());
            p.columns[index] = .{ .log_size = p.log, .values = values.values };
            p.owned[index] = true;
        }
    }
};
const Rows = struct {
    columns: []const Poly,
    lane: *const Lane.Prepared,
    output: Domain.ColumnAccumulator,
    inverse: [2]M,
    log: u32,
    first: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *Rows) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Rows) !void {
        const fixed_columns = self.columns[0..L.FIXED_COLUMNS];
        const main_columns = self.columns[L.FIXED_COLUMNS..][0..L.MAIN_COLUMNS];
        const inter_columns = self.columns[L.FIXED_COLUMNS + L.MAIN_COLUMNS ..];
        var row = self.first;
        while (row < self.end) : (row += Lane.WIDTH) {
            var fixed: [L.FIXED_COLUMNS]Lane.Base = undefined;
            var main: [L.MAIN_COLUMNS]Lane.Base = undefined;
            for (&fixed, fixed_columns) |*value, poly| value.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
            for (&main, main_columns) |*value, poly| value.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
            var current: [24]Lane.Secure = undefined;
            var previous: [8]MF.PackedM31 = undefined;
            for (&current, 0..) |*value, i| {
                var coords: [8]MF.PackedM31 = undefined;
                for (&coords, 0..) |*coordinate, j| {
                    const poly = inter_columns[8 * i + j];
                    coordinate.* = MF.loadPacked(poly.values[row..].ptr);
                    if (i == 23) inline for (0..Lane.WIDTH) |k| {
                        const index = Core.utils.offsetBitReversedCircleDomainIndex(row + k, self.log, self.log + 1, -1);
                        previous[j][k] = poly.values[index].v;
                    };
                }
                value.* = Packed.fromCoordinates(coords);
            }
            const inverse = self.inverse[row >> @intCast(self.log)];
            const sum = (try self.lane.accumulate(&main, &fixed, &current, Packed.fromCoordinates(previous))).mulBase(@as(MF.PackedM31, @splat(inverse.v)));
            inline for (0..Lane.WIDTH) |k| self.output.accumulate(row + k, Packed.lane(sum, k));
        }
    }
};
fn runWave(comptime Job: type, lease: anytype, jobs: []Job) !void {
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..]) |*job| try lease.spawnWg(&group, Job.run, .{job});
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |err| return err;
}
fn evaluate(raw: *const anyopaque, trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
    const component: *const P2 = @ptrCast(@alignCast(raw));
    const pool = Engine.work_pool.getGlobalPool() orelse return component.evaluateConstraintQuotientsOnDomain(trace, acc);
    const log = component.key.logs[3];
    const n = @as(usize, 1) << @intCast(log + 1);
    const workers = @min(pool.workerCount(), n / Lane.WIDTH);
    if (workers < 2 or try @import("../op_profile.zig").scalarDomainControl()) return component.evaluateConstraintQuotientsOnDomain(trace, acc);
    const a = acc.allocator;
    const slots = try acc.columns(a, &.{.{ .log_size = log + 1, .n_cols = Lane.ROOTS }});
    defer a.free(slots);
    const output = &slots[0];
    // Copies of this accumulator only write disjoint packed row intervals.
    output.next_fresh_index = null;
    const lane = Lane.Prepared.init(component.elements, component.claim.mulM31(try M.fromU64(component.key.rows[3]).inv()), output.random_coeff_powers);
    const domain = Core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
    var inverse: [2]M = undefined;
    for (&inverse, 0..) |*value, half| value.* = try Core.constraints.cosetVanishing(M, Core.poly.circle.canonic.CanonicCoset.new(log).coset(), domain.at(Core.utils.bitReverseIndex(half * n / 2, log + 1))).inv();
    var prepared = try Prepared.init(a, trace, log + 1);
    defer prepared.deinit();
    var lease = try pool.acquire(try Engine.work_pool.WorkerBudget.init(workers));
    defer lease.deinit();
    var expansion: [Engine.work_pool.MAX_WORKERS]Expand = undefined;
    for (expansion[0..workers]) |*job| job.* = .{ .prepared = &prepared };
    try runWave(Expand, &lease, expansion[0..workers]);
    var rows: [Engine.work_pool.MAX_WORKERS]Rows = undefined;
    const packs = n / Lane.WIDTH;
    for (rows[0..workers], 0..) |*job, i| job.* = .{ .columns = prepared.columns, .lane = &lane, .output = output.*, .inverse = inverse, .log = log, .first = packs * i / workers * Lane.WIDTH, .end = packs * (i + 1) / workers * Lane.WIDTH };
    try runWave(Rows, &lease, rows[0..workers]);
}
