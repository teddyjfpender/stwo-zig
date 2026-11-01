//! Joined2n domain evaluation: one bounded expansion of original MAIN and actual
//!16 binding columns; packed M31 original constraints and packed OM residuals.
//! Succinct Eq auxiliaries are derived from the checked GKR point, never PCS
//! witness columns, and owned only for this component's evaluation lifetime.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = E.PackedFields.BaseForField(O);
const S = E.PackedFields.SecureForField(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const B = @import("binding.zig");
const PreparedProjection = @import("prepared_projection.zig").For(F);
const Geo = @import("role_geometry.zig");
const Partition = A.full.coset_evaluation.Evaluation;
fn packedSecure(values: [][]const M, start: usize, row: usize) S {
    var coords: [8]F = undefined;
    for (&coords, 0..) |*v, c| v.* = F.load(values[start + c].ptr + row);
    return E.secureFromCoordinatesForField(O, F, coords);
}
pub const MAX_ROW_SCRATCH_BYTES: usize = 8 * 1024 * 1024;
pub const MIN_PACKED_BLOCKS_PER_SHARD: usize = 256;
fn ScratchFor(comptime Component: type) type {
    return struct { fixed: [Component.MAX_FIXED]F, main: [Component.MAX_MAIN]F, previous: [Component.MAX_MAIN]F, inter: [Geo.maxInter(Component)]F, previous_inter: [Geo.maxInter(Component)]F };
}
pub const RowScratchPlan = struct { jobs: usize, bytes_per_job: usize, total_bytes: usize };
pub fn rowScratchPlan(comptime Component: type, rows: usize, requested: usize) !RowScratchPlan {
    if (rows == 0 or rows % E.LANES != 0) return error.InvalidLocalGkrTrace;
    const bytes = @sizeOf(ScratchFor(Component));
    const fits = MAX_ROW_SCRATCH_BYTES / bytes;
    if (fits == 0) return error.LocalDomainScratchBudgetExceeded;
    const jobs: usize = @max(1, @min(fits, @min(engine.lookups.row_work.MAX_SHARDS, @min(requested, rows / (E.LANES * MIN_PACKED_BLOCKS_PER_SHARD)))));
    return .{ .jobs = jobs, .bytes_per_job = bytes, .total_bytes = try std.math.mul(usize, jobs, bytes) };
}
pub fn ScratchOwner(comptime Component: type) type {
    return struct {
        allocator: std.mem.Allocator,
        plan: RowScratchPlan,
        data: []ScratchFor(Component),
        pub fn init(a: std.mem.Allocator, rows: usize, workers: usize) !@This() {
            const plan = try rowScratchPlan(Component, rows, workers);
            return .{ .allocator = a, .plan = plan, .data = try a.alloc(ScratchFor(Component), plan.jobs) };
        }
        pub fn deinit(owner: *@This()) void {
            owner.allocator.free(owner.data);
            owner.* = undefined;
        }
    };
}
pub fn evaluate(self: anytype, trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    try self.validate();
    const Component = @typeInfo(@TypeOf(self)).pointer.child;
    const local_binding = comptime Geo.hasLocal(Component);
    const max_inter = comptime Geo.maxInter(Component);
    const aux_count = comptime if (local_binding) 10 else 0;
    const Scratch = ScratchFor(Component);
    const active_pool = pool orelse engine.work_pool.currentScopedPool();
    const profile = std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_OM_DOMAIN");
    var timer: ?std.time.Timer = if (profile) try std.time.Timer.start() else null;
    var fft_ns: u64 = 0;
    var row_ns: u64 = 0;
    const shape = self.mainShape();
    if (shape.fixed > Component.MAX_FIXED or shape.main > Component.MAX_MAIN) return error.InvalidLocalGkrTrace;
    const log = Geo.logSize(self);
    const inter_width = Geo.interWidth(self);
    if (inter_width > max_inter) return error.InvalidLocalGkrTrace;
    const offsets = self.columnOffsets();
    if (trace.polys.items.len < 3 or trace.polys.items[0].len < offsets[0] + shape.fixed or trace.polys.items[1].len < offsets[1] + shape.main or trace.polys.items[2].len < self.inter_offset + inter_width) return error.InvalidLocalGkrTrace;
    const a = acc.allocator;
    const rows: usize = @as(usize, 1) << @intCast(log);
    var aux: [aux_count]engine.poly.circle.CircleCoefficients = undefined;
    var done: usize = 0;
    defer for (aux[0..done]) |*v| v.deinit(a);
    if (comptime local_binding) {
        aux = try @import("public_aux.zig").init(a, &self.data.point, log, active_pool);
        done = aux_count;
    }
    const main_at = shape.fixed;
    const inter_at = main_at + shape.main;
    const aux_at = inter_at + inter_width;
    const total = aux_at + aux_count;
    var columns: [Component.MAX_FIXED + Component.MAX_MAIN + max_inter + aux_count]P.Poly = undefined;
    @memcpy(columns[0..shape.fixed], trace.polys.items[0][offsets[0]..][0..shape.fixed]);
    @memcpy(columns[main_at..inter_at], trace.polys.items[1][offsets[1]..][0..shape.main]);
    @memcpy(columns[inter_at..aux_at], trace.polys.items[2][self.inter_offset..][0..inter_width]);
    for (aux, 0..) |coefficient, c| columns[aux_at + c] = .{ .log_size = log, .values = &.{}, .coefficients = coefficient };
    var previous: [Component.MAX_FIXED + Component.MAX_MAIN + max_inter + aux_count]bool = @splat(false);
    for (0..shape.main) |c| previous[main_at + c] = self.previousMain(c);
    for (0..inter_width) |c| previous[inter_at + c] = Geo.previousInter(self, c);
    var evaluation = try Partition.initDegreeThree(a, columns[0..total], log, previous[0..total]);
    defer evaluation.deinit();
    var scratch_owner = try ScratchOwner(Component).init(a, rows, if (active_pool) |bound| bound.workerCount() else 1);
    defer scratch_owner.deinit();
    const scratch_plan = scratch_owner.plan;
    const scratches = scratch_owner.data;
    for (scratches) |*scratch| scratch.previous = @splat(F.zero());
    var prepared: ?PreparedProjection = null;
    defer if (prepared) |*owned| owned.deinit();
    if (comptime local_binding) prepared = try PreparedProjection.initComponent(a, self);
    const outputs = try acc.columns(a, &.{.{ .log_size = log + 1, .n_cols = self.nConstraints() }});
    defer a.free(outputs);
    var output = outputs[0];
    const Work = struct {
        component: @TypeOf(self),
        evaluation: *const Partition,
        output: @TypeOf(output),
        scratch: []Scratch,
        part: usize,
        rows: usize,
        log: u32,
        shape: @TypeOf(shape),
        main_at: usize,
        inter_at: usize,
        aux_at: usize,
        inter_width: usize,
        inverse: F,
        fresh: bool,
        prepared: ?*const PreparedProjection,
        errors: [engine.lookups.row_work.MAX_SHARDS]?anyerror = @splat(null),
        pub fn runRange(ctx: *@This(), index: usize, first: usize, end: usize) void {
            ctx.execute(index, first, end) catch |err| {
                ctx.errors[index] = err;
            };
        }
        fn execute(ctx: *@This(), index: usize, first: usize, end: usize) !void {
            const component = ctx.component;
            const view = ctx.evaluation;
            const destination = ctx.output;
            const scratch = &ctx.scratch[index];
            const coset = ctx.part;
            const row_count = ctx.rows;
            const trace_log = ctx.log;
            const column_shape = ctx.shape;
            const main_offset = ctx.main_at;
            const inter_offset = ctx.inter_at;
            const aux_offset = ctx.aux_at;
            const interaction_count = ctx.inter_width;
            const vanishing_inverse = ctx.inverse;
            var row: usize = first * E.LANES;
            while (row < end * E.LANES) : (row += E.LANES) {
                for (scratch.fixed[0..column_shape.fixed], 0..) |*v, c| v.* = F.load(view.current_values[c].ptr + row);
                for (scratch.main[0..column_shape.main], 0..) |*v, c| {
                    v.* = F.load(view.current_values[main_offset + c].ptr + row);
                    if (component.previousMain(c)) {
                        var prior: [E.LANES]M = undefined;
                        for (&prior, 0..) |*x, lane| x.* = view.previous_values[main_offset + c][view.previousRow(coset, row + lane)];
                        scratch.previous[c] = F.fromLanes(prior);
                    }
                }
                var weighted = E.WeightedAccumulatorFor(F){ .powers = destination.random_coeff_powers };
                var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
                try component.emitMainFor(F, scratch.fixed[0..column_shape.fixed], scratch.main[0..column_shape.main], scratch.previous[0..column_shape.main], &sink);
                for (scratch.inter[0..interaction_count], scratch.previous_inter[0..interaction_count], 0..) |*value, *prior, c| {
                    value.* = F.load(view.current_values[inter_offset + c].ptr + row);
                    prior.* = F.zero();
                    if (Geo.previousInter(component, c)) {
                        var previous_lanes: [E.LANES]M = undefined;
                        for (&previous_lanes, 0..) |*v, lane| v.* = view.previous_values[inter_offset + c][view.previousRow(coset, row + lane)];
                        prior.* = F.fromLanes(previous_lanes);
                    }
                }
                if (comptime local_binding) {
                    var projection = ctx.prepared.?.projection();
                    component.emitLocalFor(F, scratch.fixed[0..column_shape.fixed], scratch.main[0..column_shape.main], &projection);
                    try projection.finish();
                    var next_coords: [8]F = undefined;
                    var prior_coords: [8]F = undefined;
                    for (0..8) |c| {
                        var next: [E.LANES]M = undefined;
                        var prior: [E.LANES]M = undefined;
                        for (&next, &prior, 0..) |*n, *p, lane| {
                            const global = view.globalRow(coset, row + lane);
                            const shifted = core.utils.offsetBitReversedCircleDomainIndex(global, trace_log, trace_log + 1, 2);
                            if (shifted / row_count != coset) return error.InvalidLocalGkrNextMask;
                            n.* = view.current_values[inter_offset + c][shifted % row_count];
                            p.* = view.previous_values[inter_offset + 8 + c][view.previousRow(coset, row + lane)];
                        }
                        next_coords[c] = F.fromLanes(next);
                        prior_coords[c] = F.fromLanes(prior);
                    }
                    B.emitFor(F, .{ .eq = packedSecure(view.current_values, inter_offset, row), .eq_next2 = E.secureFromCoordinatesForField(O, F, next_coords), .prefix = packedSecure(view.current_values, inter_offset + 8, row), .prefix_previous = E.secureFromCoordinatesForField(O, F, prior_coords) }, .{ .first = S.fromBase(F.load(view.current_values[aux_offset + 8].ptr + row)), .second = S.fromBase(F.load(view.current_values[aux_offset + 9].ptr + row)), .carry = packedSecure(view.current_values, aux_offset, row), .eq0 = S.splat(component.data.point.eq0), .eq1 = S.splat(component.data.point.eq1) }, projection.combine(S.splat(component.data.eta)), S.splat(component.data.target_per_row), &sink);
                }
                if (comptime @hasDecl(Component, "emitGlobalFor")) try component.emitGlobalFor(F, scratch.fixed[0..column_shape.fixed], scratch.main[0..column_shape.main], scratch.inter[0..interaction_count], scratch.previous_inter[0..interaction_count], &sink);
                if (sink.count != component.nConstraints()) return error.LocalGkrProjectionShape;
                const result = weighted.accumulation.mulBase(vanishing_inverse).coordinates();
                const start = view.globalRow(coset, row);
                const fresh = ctx.fresh;
                for (destination.col.columns, result) |column, v| {
                    if (fresh) v.store(column.ptr + start) else F.load(column.ptr + start).add(v).store(column.ptr + start);
                }
            }
        }
    };
    const prep_ns = if (timer) |*clock| clock.lap() else 0;
    var actual_jobs: usize = 1;
    for (0..2) |part| {
        if (timer) |*clock| clock.reset();
        try evaluation.evaluatePartWithPool(part, active_pool);
        const inverse = F.fromBase(try evaluation.denominatorInverse(part));
        if (timer) |*clock| fft_ns += clock.lap();
        const start = evaluation.globalRow(part, 0);
        const fresh = if (output.next_fresh_index) |next| next == start else false;
        var work = Work{ .component = self, .evaluation = &evaluation, .output = output, .scratch = scratches, .part = part, .rows = rows, .log = log, .shape = shape, .main_at = main_at, .inter_at = inter_at, .aux_at = aux_at, .inter_width = inter_width, .inverse = inverse, .fresh = fresh, .prepared = if (prepared) |*owned| owned else null };
        const jobs = engine.lookups.row_work.forEachRange(rows / E.LANES, &work, .{ .max_shards = scratch_plan.jobs, .min_rows_per_shard = MIN_PACKED_BLOCKS_PER_SHARD });
        actual_jobs = @max(actual_jobs, jobs);
        for (work.errors[0..jobs]) |failure| if (failure) |err| {
            output.next_fresh_index = null;
            return err;
        };
        // One caller owns the freshness cursor. Callback writes are disjoint.
        output.next_fresh_index = if (fresh) start + rows else null;
        if (timer) |*clock| row_ns += clock.read();
    }
    if (profile) std.debug.print("OM_DOMAIN_STAGE log={d} main={d} inter={d} constraints={d} jobs={d} scratch_bytes={d} prepared_bytes={d} prep_ns={d} fft_ns={d} rows_ns={d}\n", .{ log, shape.main, inter_width, self.nConstraints(), actual_jobs, scratch_plan.total_bytes, if (prepared) |*owned| owned.bytes() else @as(usize, 0), prep_ns, fft_ns, row_ns });
}
