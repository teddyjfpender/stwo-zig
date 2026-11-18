//! Concrete native-PCS OM31 component derived from the original circuit AIR.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const E = @import("program.zig");
const G = @import("geometry.zig");
const O = P.O;
const M = P.M;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O);
const ProverAir = prover.air.component_prover.ForField(O);
const Domain = prover.air.accumulation.ForField(O);
const Packed = @import("domain_pack.zig");
const Canonic = core.poly.circle.canonic.CanonicCoset;
pub const Component = struct {
    allocator: std.mem.Allocator,
    captured: *const C.composition_bundle.Component,
    preprocessed_logs: []const u32,
    z: O,
    alpha: O,
    claim: O,
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), ProverAir.ComponentProver, ProverAir.Trace, Domain.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) ProverAir.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Component) usize {
        return self.captured.n_constraints;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.captured.evaluation_log_size;
    }
    pub fn validate(self: *const Component) !void {
        if (self.captured.trace_log_size < 4 or self.captured.evaluation_log_size != self.captured.trace_log_size + 1) return error.UnsupportedOm31CircuitDegree;
        _ = try G.span(self.captured.*, 1);
        _ = try G.span(self.captured.*, 2);
        for (self.captured.parts) |part| try E.validateLens(self.allocator, part.program);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const fixed = try a.alloc(u32, self.captured.preprocessed_indices.len);
        errdefer a.free(fixed);
        for (fixed, self.captured.preprocessed_indices) |*v, index| {
            if (index >= self.preprocessed_logs.len) return error.InvalidOm31FixedIndex;
            v.* = self.preprocessed_logs[index];
        }
        const ms = try G.span(self.captured.*, 1);
        const is = try G.span(self.captured.*, 2);
        const main = try a.alloc(u32, ms.end - ms.start);
        errdefer a.free(main);
        @memset(main, self.captured.trace_log_size);
        const inter = try a.alloc(u32, is.end - is.start);
        errdefer a.free(inter);
        @memset(inter, self.captured.trace_log_size);
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.captured.preprocessed_indices.len);
        for (out, self.captured.preprocessed_indices) |*v, index| v.* = index;
        return out;
    }
    fn points(a: std.mem.Allocator, offsets: []const std.ArrayList(i32), p: Point, step: Point) ![][]Point {
        const out = try a.alloc([]Point, offsets.len);
        errdefer a.free(out);
        var made: usize = 0;
        errdefer for (out[0..made]) |column| a.free(column);
        for (out, offsets) |*column, list| {
            column.* = try a.alloc(Point, list.items.len);
            made += 1;
            for (column.*, list.items) |*v, offset| v.* = p.add(step.mulSigned(offset));
        }
        return out;
    }
    fn freePoints(a: std.mem.Allocator, tree: [][]Point) void {
        for (tree) |column| a.free(column);
        a.free(tree);
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, p: Point, global_log: u32) !Air.MaskPoints {
        if (global_log < self.captured.trace_log_size) return error.InvalidOm31MaskGeometry;
        const raw = Canonic.new(global_log).coset().step;
        const step = Point{ .x = O.fromBase(raw.x), .y = O.fromBase(raw.y) };
        const fixed = try a.alloc([]Point, self.captured.preprocessed_indices.len);
        errdefer a.free(fixed);
        for (fixed) |*v| v.* = &.{};
        const mo = try G.offsets(a, self.captured.*, 1);
        defer G.freeOffsets(a, mo);
        const io = try G.offsets(a, self.captured.*, 2);
        defer G.freeOffsets(a, io);
        const main = try points(a, mo, p, step);
        errdefer freePoints(a, main);
        const inter = try points(a, io, p, step);
        errdefer freePoints(a, inter);
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
    }
    pub fn extensionParameters(self: *const Component) ![]O {
        return E.parameters(self.allocator, self.captured, self.z, self.alpha, self.claim);
    }
    const PointRead = struct {
        component: *const Component,
        mask: *const Air.MaskValues,
        main_offsets: []const std.ArrayList(i32),
        inter_offsets: []const std.ArrayList(i32),
        fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
            const self: *const PointRead = @ptrCast(@alignCast(raw));
            if (tree >= self.mask.items.len) return error.MissingOm31Mask;
            if (tree == 0) {
                if (offset != 0 or column >= self.component.captured.preprocessed_indices.len) return error.MissingOm31Mask;
                const global = self.component.captured.preprocessed_indices[column];
                if (global >= self.mask.items[0].len or self.mask.items[0][global].len != 1) return error.MissingOm31Mask;
                return self.mask.items[0][global][0];
            }
            const span = try G.span(self.component.captured.*, tree);
            const offsets = if (tree == 1) self.main_offsets else self.inter_offsets;
            if (column >= offsets.len or span.start + column >= self.mask.items[tree].len) return error.MissingOm31Mask;
            const values = self.mask.items[tree][span.start + column];
            if (values.len != offsets[column].items.len) return error.MissingOm31Mask;
            const at = C.resident_geometry.offsetIndex(offsets[column].items, offset) orelse return error.MissingOm31Mask;
            return values[at];
        }
    };
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, global_log: u32) !void {
        if (global_log < self.captured.trace_log_size) return error.InvalidOm31MaskGeometry;
        const parameters = try self.extensionParameters();
        defer self.allocator.free(parameters);
        const mo = try G.offsets(self.allocator, self.captured.*, 1);
        defer G.freeOffsets(self.allocator, mo);
        const io = try G.offsets(self.allocator, self.captured.*, 2);
        defer G.freeOffsets(self.allocator, io);
        const read = PointRead{ .component = self, .mask = mask, .main_offsets = mo, .inter_offsets = io };
        const local = point.repeatedDouble(global_log - self.captured.trace_log_size);
        const inv = try core.constraints.cosetVanishing(O, Canonic.new(self.captured.trace_log_size).coset(), local).inv();
        for (self.captured.parts) |part| {
            const roots = try E.evaluate(self.allocator, part.program, .{ .context = &read, .get = PointRead.get }, parameters);
            defer self.allocator.free(roots);
            for (roots) |value| acc.accumulate(value.mul(inv));
        }
    }
    /// Materialize only this component's reads on their native 2n domains.
    /// Compact trees retain coefficients. Larger blowups retain evaluations on
    /// another coset. Both need the same evaluation before lifting.
    const Shadow = struct {
        values: [3][]?[]M,
        fn deinit(self: *Shadow, a: std.mem.Allocator) void {
            for (self.values) |tree| {
                for (tree) |entry| if (entry) |v| a.free(v);
                a.free(tree);
            }
        }
    };
    fn needsShadow(trace: *const ProverAir.Trace) bool {
        for (trace.polys.items) |tree| for (tree) |poly| {
            if (poly.device != null) continue;
            const coefficients = poly.coefficients orelse continue;
            if (poly.values.len == 0 or poly.log_size != coefficients.logSize() + 1) return true;
        };
        return false;
    }
    fn buildShadow(self: *const Component, a: std.mem.Allocator, trace: *const ProverAir.Trace) !Shadow {
        var shadow: Shadow = .{ .values = undefined };
        var made: usize = 0;
        errdefer {
            for (shadow.values[0..made]) |tree| {
                for (tree) |entry| if (entry) |v| a.free(v);
                a.free(tree);
            }
        }
        for (&shadow.values, 0..) |*tree, t| {
            const n = if (t < trace.polys.items.len) trace.polys.items[t].len else 0;
            tree.* = try a.alloc(?[]M, n);
            @memset(tree.*, null);
            made += 1;
        }
        var twiddles = prover.poly.twiddle_source.TwiddleSource.initOwned(a);
        defer twiddles.deinit(a);
        const Circle = prover.poly.circle;
        for (0..3) |t| {
            if (t >= trace.polys.items.len) continue;
            const globals: []const u32 = if (t == 0) self.captured.preprocessed_indices else &.{};
            const span = if (t == 0) G.Span{ .start = 0, .end = 0 } else try G.span(self.captured.*, @intCast(t));
            const count = if (t == 0) globals.len else span.end - span.start;
            for (0..count) |i| {
                const global: usize = if (t == 0) globals[i] else span.start + i;
                if (global >= trace.polys.items[t].len or shadow.values[t][global] != null) continue;
                const poly = trace.polys.items[t][global];
                const coefficients = poly.coefficients orelse return error.Om31CircuitRequiresHostLde;
                const log = coefficients.logSize() + 1;
                if (poly.values.len != 0 and poly.log_size == log) continue;
                const evaluation = try coefficients.evaluateWithTwiddles(a, Circle.CanonicCoset.new(log).circleDomain(), try twiddles.get(a, log));
                shadow.values[t][global] = @constCast(evaluation.values);
            }
        }
        return shadow;
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const ProverAir.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        return self.evaluateDomainWithPool(trace, acc, prover.work_pool.getGlobalPool());
    }
    /// The octic engine currently visits components in order. Split each large
    /// domain through the caller's bounded pool without changing that order or
    /// allocating an independent full composition plane per worker.
    pub fn evaluateDomainWithPool(self: *const Component, trace: *const ProverAir.Trace, acc: *Domain.DomainEvaluationAccumulator, pool: ?*prover.work_pool.WorkPool) !void {
        const a = acc.allocator;
        const requests = [_]Domain.ColumnRequest{.{ .log_size = self.captured.evaluation_log_size, .n_cols = self.captured.n_constraints }};
        const columns = try acc.columns(a, &requests);
        defer a.free(columns);
        const column = &columns[0];
        const params = try self.extensionParameters();
        defer self.allocator.free(params);
        const n = @as(usize, 1) << @intCast(self.captured.evaluation_log_size);
        var shadow_storage: ?Shadow = if (needsShadow(trace)) try self.buildShadow(a, trace) else null;
        defer if (shadow_storage) |*shadow| shadow.deinit(a);
        const shadow: ?*const Shadow = if (shadow_storage) |*value| value else null;
        const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const temp = arena.allocator();
        const plan = try Packed.Plan.init(temp, self.captured, trace, if (shadow) |v| v.values else null, params, column.random_coeff_powers);
        // Each worker owns registers and writes a disjoint range. Allocate on
        // this thread so callers can supply a single-threaded arena.
        if (workers > 1) column.next_fresh_index = null;
        var jobs: [prover.work_pool.MAX_WORKERS]Rows = undefined;
        for (jobs[0..workers], 0..) |*job, i| {
            job.* = .{ .plan = &plan, .registers = try plan.registers(temp), .column = column.*, .first = n * i / workers, .end = n * (i + 1) / workers };
        }
        if (workers == 1) return jobs[0].evaluate();
        var lease = try pool.?.acquire(try prover.work_pool.WorkerBudget.init(workers));
        defer lease.deinit();
        var group = std.Thread.WaitGroup{};
        var joined = false;
        defer {
            if (!joined) group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Rows.run, .{job});
        jobs[0].run();
        group.wait();
        joined = true;
        for (jobs[0..workers]) |job| if (job.failure) |err| return err;
    }
    const Rows = struct {
        plan: *const Packed.Plan,
        registers: Packed.Registers,
        column: Domain.ColumnAccumulator,
        first: usize,
        end: usize,
        failure: ?anyerror = null,
        fn run(self: *Rows) void {
            self.evaluate() catch |err| {
                self.failure = err;
            };
        }
        fn evaluate(self: *Rows) !void {
            var r = self.first;
            while (r < self.end) {
                const active = @min(self.end - r, core.fields.m31.PACK_WIDTH);
                const value = try self.plan.evaluate(self.registers, r, active);
                for (0..active) |lane| {
                    const inverse = self.plan.component.denominator_inverses[(r + lane) >> @intCast(self.plan.component.trace_log_size)];
                    self.column.accumulate(r + lane, core.fields.packed_om31.lane(value, lane).mulM31(M.fromCanonical(inverse)));
                }
                r += active;
            }
        }
    };
};
