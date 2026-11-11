//! Concrete native-PCS OM31 component derived from the original circuit AIR.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const E = @import("program.zig");
const PackedDomain = @import("domain_program.zig");
const Native = @import("native_program.zig");
const G = @import("geometry.zig");
const O = P.O;
const M = P.M;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O);
const ProverAir = prover.air.component_prover.ForField(O);
const Domain = prover.air.accumulation.ForField(O);
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
    /// Outer profiles with blowup > 2 (m3) commit LDEs larger than the 2n
    /// evaluation domain. Their reads are re-expressed exactly as the beta1
    /// route sees them: each read column's minimal polynomial evaluated on its
    /// own 2x canonic domain (coefficient log + 1), then lifted as before.
    const ShadowColumns = @import("shadow_columns.zig");
    const Shadow = ShadowColumns.Shadow;
    fn needsShadow(trace: *const ProverAir.Trace) bool {
        for (trace.polys.items) |tree| for (tree) |poly| {
            if (poly.device != null) continue;
            const coefficients = poly.coefficients orelse continue;
            if (poly.values.len == 0 or poly.log_size != coefficients.logSize() + 1) return true;
        };
        return false;
    }
    fn buildShadow(self: *const Component, a: std.mem.Allocator, trace: *const ProverAir.Trace, pool: ?*prover.work_pool.WorkPool) !Shadow {
        var requests: std.ArrayList(ShadowColumns.Request) = .empty;
        defer requests.deinit(a);
        for (0..3) |t| {
            if (t >= trace.polys.items.len) continue;
            if (t == 0) {
                for (self.captured.preprocessed_indices) |column| try requests.append(a, .{ .tree = 0, .column = column });
            } else {
                const span = try G.span(self.captured.*, @intCast(t));
                for (span.start..span.end) |column| try requests.append(a, .{ .tree = @intCast(t), .column = column });
            }
        }
        return ShadowColumns.prepare(a, trace, requests.items, pool);
    }
    const DomainRead = struct {
        component: *const Component,
        trace: *const ProverAir.Trace,
        row: usize,
        shadow: ?*const Shadow = null,
        fn resolve(raw: *const anyopaque, tree: u8, column: u32) !Native.Poly {
            const self: *const DomainRead = @ptrCast(@alignCast(raw));
            if (tree >= self.trace.polys.items.len) return error.MissingOm31Trace;
            const global = if (tree == 0) blk: {
                if (column >= self.component.captured.preprocessed_indices.len) return error.MissingOm31Trace;
                break :blk self.component.captured.preprocessed_indices[column];
            } else (try G.span(self.component.captured.*, tree)).start + column;
            if (global >= self.trace.polys.items[tree].len) return error.MissingOm31Trace;
            var poly = self.trace.polys.items[tree][global];
            if (self.shadow) |shadow| if (shadow.values[tree][global]) |values| {
                poly = .{ .log_size = std.math.log2_int(usize, values.len), .values = values };
            };
            return poly;
        }
        fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
            const self: *const DomainRead = @ptrCast(@alignCast(raw));
            const poly = try resolve(raw, tree, column);
            // The initial native beta1 proof retains its exact2n LDE; no
            // hidden scalar re-expansion or fabricated host device columns.
            if (poly.device != null or poly.values.len == 0) return error.Om31CircuitRequiresHostLde;
            const index = core.utils.offsetBitReversedCircleDomainIndex(self.row, self.component.captured.trace_log_size, self.component.captured.evaluation_log_size, offset);
            return O.fromBase(try poly.valueAtLiftingPosition(self.component.captured.evaluation_log_size, index));
        }
        fn getPacked(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !core.fields.m31.PackedM31 {
            const self: *const DomainRead = @ptrCast(@alignCast(raw));
            const poly = try resolve(raw, tree, column);
            if (poly.device != null or poly.values.len == 0) return error.Om31CircuitRequiresHostLde;
            if (offset == 0 and poly.log_size == self.component.captured.evaluation_log_size) {
                if (self.row > poly.values.len or PackedDomain.WIDTH > poly.values.len - self.row) return error.MissingOm31Trace;
                return core.fields.m31.loadPacked(poly.values[self.row..].ptr);
            }
            var out: core.fields.m31.PackedM31 = undefined;
            inline for (0..PackedDomain.WIDTH) |lane| {
                const index = core.utils.offsetBitReversedCircleDomainIndex(self.row + lane, self.component.captured.trace_log_size, self.component.captured.evaluation_log_size, offset);
                out[lane] = (try poly.valueAtLiftingPosition(self.component.captured.evaluation_log_size, index)).v;
            }
            return out;
        }
    };
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
        var shadow_storage: ?Shadow = if (needsShadow(trace)) try self.buildShadow(a, trace, pool) else null;
        defer if (shadow_storage) |*shadow| shadow.deinit(a);
        const shadow: ?*const Shadow = if (shadow_storage) |*value| value else null;
        const read = DomainRead{ .component = self, .trace = trace, .row = 0, .shadow = shadow };
        var native_storage = if (Native.enabled()) try Native.Prepared.init(a, self.captured, params, column.*, .{ .context = &read, .get = DomainRead.resolve }) else null;
        defer if (native_storage) |*value| value.deinit();
        const native: ?*const Native.Prepared = if (native_storage) |*value| value else null;
        const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        if (workers == 1) {
            var job = try Rows.init(a, self, trace, params, column.*, 0, n, native);
            job.shadow = shadow;
            defer job.deinit(a);
            return job.evaluate();
        }
        var lease = try pool.?.acquire(try prover.work_pool.WorkerBudget.init(workers));
        defer lease.deinit();
        // Every job writes a disjoint row range into the already zeroed bucket.
        // Disable the sequential fresh cursor before copying it to helpers.
        column.next_fresh_index = null;
        var jobs: [prover.work_pool.MAX_WORKERS]Rows = undefined;
        var prepared: usize = 0;
        defer for (jobs[0..prepared]) |*job| job.deinit(a);
        for (jobs[0..workers], 0..) |*job, i| {
            const packs = n / PackedDomain.WIDTH;
            job.* = try Rows.init(a, self, trace, params, column.*, packs * i / workers * PackedDomain.WIDTH, packs * (i + 1) / workers * PackedDomain.WIDTH, native);
            job.shadow = shadow;
            prepared += 1;
        }
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
        component: *const Component,
        trace: *const ProverAir.Trace,
        parameters: []PackedDomain.F,
        column: Domain.ColumnAccumulator,
        scratch: []PackedDomain.Scratch,
        roots: []PackedDomain.F,
        first: usize,
        end: usize,
        failure: ?anyerror = null,
        shadow: ?*const Shadow = null,
        native: ?*const Native.Prepared = null,
        fn init(a: std.mem.Allocator, component: *const Component, trace: *const ProverAir.Trace, parameters: []const O, column: Domain.ColumnAccumulator, first: usize, end: usize, native: ?*const Native.Prepared) !Rows {
            if (native != null) return .{ .component = component, .trace = trace, .parameters = &.{}, .column = column, .scratch = &.{}, .roots = &.{}, .first = first, .end = end, .native = native };
            const scratch = try a.alloc(PackedDomain.Scratch, component.captured.parts.len);
            errdefer a.free(scratch);
            var made: usize = 0;
            errdefer for (scratch[0..made]) |*item| item.deinit();
            var max_roots: usize = 0;
            for (scratch, component.captured.parts) |*item, part| {
                item.* = try PackedDomain.Scratch.init(a, part.program);
                made += 1;
                max_roots = @max(max_roots, part.program.constraint_roots.len);
            }
            const packed_parameters = try a.alloc(PackedDomain.F, parameters.len);
            errdefer a.free(packed_parameters);
            for (packed_parameters, parameters) |*out, value| out.* = PackedDomain.Packed.splat(value);
            return .{ .component = component, .trace = trace, .parameters = packed_parameters, .column = column, .scratch = scratch, .roots = try a.alloc(PackedDomain.F, max_roots), .first = first, .end = end };
        }
        fn deinit(self: *Rows, a: std.mem.Allocator) void {
            for (self.scratch) |*item| item.deinit();
            a.free(self.scratch);
            a.free(self.roots);
            a.free(self.parameters);
        }
        fn run(self: *Rows) void {
            self.evaluate() catch |err| {
                self.failure = err;
            };
        }
        fn evaluate(self: *Rows) !void {
            if (self.native) |native| return native.evaluateRange(self.first, self.end);
            const component = self.component;
            var read = DomainRead{ .component = component, .trace = self.trace, .row = self.first, .shadow = self.shadow };
            var r = self.first;
            while (r < self.end) : (r += PackedDomain.WIDTH) {
                read.row = r;
                var value = PackedDomain.Packed.splat(O.zero());
                for (self.scratch, component.captured.parts) |*item, part| {
                    const values = self.roots[0..part.program.constraint_roots.len];
                    try item.evaluateInto(part.program, .{ .context = &read, .get = DomainRead.getPacked }, self.parameters, values);
                    for (values, item.root_kinds, 0..) |root, kind, i| {
                        const coefficient = PackedDomain.Packed.splat(self.column.random_coeff_powers[component.captured.n_constraints - 1 - part.rc_base - i]);
                        value = value.add(switch (kind) {
                            .zero => continue,
                            .one => coefficient,
                            .base => coefficient.mulBase(root.c0.c0.a),
                            .secure => PackedDomain.Packed.mul(root, coefficient),
                        });
                    }
                }
                const inv = M.fromCanonical(component.captured.denominator_inverses[r >> @intCast(component.captured.trace_log_size)]);
                value = value.mulBase(core.fields.m31.splatPacked(inv));
                inline for (0..PackedDomain.WIDTH) |lane| self.column.accumulate(r + lane, PackedDomain.Packed.lane(value, lane));
            }
        }
    };
};
