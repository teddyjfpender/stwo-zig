//! Bounded four-coset classic truth kernel, packed M31 arithmetic / OM31 weights.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = E.PackedFields.BaseForField(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Evaluation = A.full.coset_evaluation.Evaluation;
const Component = @import("truth_role.zig").Component;
const RowWork = engine.lookups.row_work;
pub const MAX_ROW_WORKSPACE_BYTES: usize = 32 << 20;
pub const MIN_BLOCKS_PER_TASK: usize = 64;
pub const RowWorkspace = Component.Workspace(F);
fn logSize(owner: anytype) u32 {
    const T = @typeInfo(@TypeOf(owner)).pointer.child;
    return if (@hasField(T, "original")) owner.original.log_size else owner.log_size;
}
pub const WorkspacePlan = struct {
    jobs: usize,
    bytes: usize,
    pub fn allocate(self: WorkspacePlan, allocator: std.mem.Allocator) ![]RowWorkspace {
        if (self.jobs == 0 or self.jobs > RowWork.MAX_SHARDS or self.bytes != try std.math.mul(usize, self.jobs, @sizeOf(RowWorkspace)) or self.bytes > MAX_ROW_WORKSPACE_BYTES) return error.WideTruthRowScratchBudgetExceeded;
        return allocator.alloc(RowWorkspace, self.jobs);
    }
    pub fn init(rows: usize, available_workers: usize) !WorkspacePlan {
        if (rows == 0 or rows % E.LANES != 0) return error.InvalidWideTruthTrace;
        const blocks = rows / E.LANES;
        const jobs = @max(1, @min(RowWork.MAX_SHARDS, @min(available_workers, blocks / MIN_BLOCKS_PER_TASK)));
        const bytes = try std.math.mul(usize, jobs, @sizeOf(RowWorkspace));
        if (bytes > MAX_ROW_WORKSPACE_BYTES) return error.WideTruthRowScratchBudgetExceeded;
        return .{ .jobs = jobs, .bytes = bytes };
    }
};
/// Per-block address metadata shared by all shifted columns. It owns no trace
/// values and is local to one joined row job, never shared between workers.
pub const ShiftMap = struct {
    pub const offsets = [_]i32{ -2, -1, 1, 2 };
    rows: [offsets.len][E.LANES]usize,
    previous: [offsets.len][E.LANES]bool,
    pub fn slot(shift: i32) ?usize {
        return switch (shift) {
            -2 => 0,
            -1 => 1,
            1 => 2,
            2 => 3,
            else => null,
        };
    }
    pub fn init(trace_log: u32, split: u32, part: usize, row: usize) !ShiftMap {
        if (trace_log < 5 or trace_log > 26 or split < 1 or split > 2) return error.InvalidWideTruthTrace;
        const size = @as(usize, 1) << @intCast(trace_log);
        if (part >= (@as(usize, 1) << @intCast(split)) or row % E.LANES != 0 or row > size - E.LANES) return error.InvalidWideTruthTrace;
        var result: ShiftMap = undefined;
        for (offsets, 0..) |shift, index| for (0..E.LANES) |lane| {
            const target = core.utils.offsetBitReversedCircleDomainIndex(part * size + row + lane, trace_log, trace_log + split, shift);
            const target_part = target / size;
            if (target_part != part and target_part != part ^ 1) return error.InvalidWideTruthShift;
            result.rows[index][lane] = target % size;
            result.previous[index][lane] = target_part != part;
        };
        return result;
    }
};
fn Samples(comptime Owner: type) type {
    return struct {
        owner: *const Owner,
        evaluation: *const Evaluation,
        part: usize,
        row: usize,
        shifts: *const ShiftMap,
        pub fn aux(s: @This()) !@import("binding.zig").AuxFor(E.SecureFor(F)) {
            const width = s.owner.widths();
            const at = width[0] + width[1] + width[2];
            var carry: [8]F = undefined;
            for (&carry, 0..) |*v, c| v.* = F.load(s.evaluation.current_values[at + c].ptr + s.row);
            const S = E.SecureFor(F);
            return .{ .first = S.fromBase(F.load(s.evaluation.current_values[at + 8].ptr + s.row)), .second = S.fromBase(F.load(s.evaluation.current_values[at + 9].ptr + s.row)), .carry = E.secureFromCoordinatesForField(O, F, carry), .eq0 = S.splat(s.owner.data.point.eq0), .eq1 = S.splat(s.owner.data.point.eq1) };
        }
        pub fn last(s: @This()) !F {
            return F.load(s.evaluation.current_values[s.evaluation.sources.len - 1].ptr + s.row);
        }
        pub fn get(s: @This(), tree: usize, column: usize, shift: i32) !F {
            const widths = s.owner.widths();
            const index = column + (if (tree == 0) @as(usize, 0) else if (tree == 1) widths[0] else widths[0] + widths[1]);
            if (shift == 0) return F.load(s.evaluation.current_values[index].ptr + s.row);
            var values: [E.LANES]M = undefined;
            if (ShiftMap.slot(shift)) |slot| {
                for (&values, s.shifts.rows[slot], s.shifts.previous[slot]) |*v, row, previous| {
                    v.* = if (!previous) s.evaluation.current_values[index][row] else if (s.evaluation.previous_values[index].len != 0) s.evaluation.previous_values[index][row] else return error.InvalidWideTruthShift;
                }
                return F.fromLanes(values);
            }
            // Preserve the checked original authority if a future mask adds an
            // offset outside the cache's explicitly supported four shifts.
            for (&values, 0..) |*v, lane| {
                const target = core.utils.offsetBitReversedCircleDomainIndex(s.evaluation.globalRow(s.part, s.row + lane), logSize(s.owner), logSize(s.owner) + s.owner.compositionLogSplit(), shift);
                const part = target / s.evaluation.size;
                const row = target % s.evaluation.size;
                v.* = if (part == s.part) s.evaluation.current_values[index][row] else if (part == s.part ^ 1 and s.evaluation.previous_values[index].len != 0) s.evaluation.previous_values[index][row] else return error.InvalidWideTruthShift;
            }
            return F.fromLanes(values);
        }
    };
}
pub fn evaluate(self: anytype, trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
    try self.validate();
    const Owner = @typeInfo(@TypeOf(self)).pointer.child;
    const aux_count: usize = if (@hasField(Owner, "data")) 10 else 0;
    const profile = std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_OM_DOMAIN");
    var timer: ?std.time.Timer = if (profile) try std.time.Timer.start() else null;
    var fft_ns: u64 = 0;
    var rows_ns: u64 = 0;
    const a = acc.allocator;
    const widths = self.widths();
    const native_total = widths[0] + widths[1] + widths[2];
    const total = native_total + aux_count + 1;
    var aux: [aux_count]engine.poly.circle.CircleCoefficients = undefined;
    if (comptime aux_count != 0) aux = try @import("public_aux.zig").init(acc.allocator, &self.data.point, logSize(self), engine.work_pool.currentScopedPool());
    defer for (&aux) |*coefficient| coefficient.deinit(acc.allocator);
    const columns = try a.alloc(P.Poly, total);
    defer a.free(columns);
    const previous = try a.alloc(bool, total);
    defer a.free(previous);
    if (trace.polys.items.len != 3) return error.InvalidWideTruthTrace;
    var at: usize = 0;
    for (widths, 0..) |width, t| {
        if (trace.polys.items[t].len < self.offsets[t] + width) return error.InvalidWideTruthTrace;
        @memcpy(columns[at..][0..width], trace.polys.items[t][self.offsets[t]..][0..width]);
        for (0..width) |c| previous[at + c] = self.shifts(t, c).len > 1;
        at += width;
    }
    const rows = @as(usize, 1) << @intCast(logSize(self));
    const values = try a.alloc(M, rows);
    defer a.free(values);
    @memset(values, M.zero());
    values[A.witness.physical(rows - 1, logSize(self))] = M.one();
    var last = try engine.poly.circle.poly.interpolateFromEvaluation(a, try engine.poly.circle.evaluation.CircleEvaluation.init(core.poly.circle.canonic.CanonicCoset.new(logSize(self)).circleDomain(), values));
    defer last.deinit(a);
    for (aux, 0..) |coefficient, i| columns[native_total + i] = .{ .log_size = logSize(self), .values = &.{}, .coefficients = coefficient };
    @memset(previous[native_total..], false);
    columns[total - 1] = .{ .log_size = logSize(self), .values = &.{}, .coefficients = last };
    previous[total - 1] = false;
    var evaluation = if (self.compositionLogSplit() == 1) try Evaluation.initDegreeThree(a, columns, logSize(self), previous) else try Evaluation.init(a, columns, logSize(self), previous);
    defer evaluation.deinit();
    const pool = engine.work_pool.currentScopedPool();
    const workers = if (pool) |p| if (engine.work_pool.cooperative.current() == null) p.availableWorkers() else 1 else 1;
    const plan = try WorkspacePlan.init(evaluation.size, workers);
    const workspaces = try plan.allocate(a);
    defer a.free(workspaces);
    const outputs = try acc.columns(a, &.{.{ .log_size = logSize(self) + self.compositionLogSplit(), .n_cols = self.nConstraints() }});
    defer a.free(outputs);
    var output = outputs[0];
    const prep_ns = if (timer) |*clock| clock.lap() else 0;
    for (0..@as(usize, 1) << @intCast(self.compositionLogSplit())) |part| {
        try evaluation.evaluatePartWithPool(part, pool);
        if (timer) |*clock| fft_ns += clock.lap();
        const inverse = F.fromBase(try evaluation.denominatorInverse(part));
        const first = evaluation.globalRow(part, 0);
        const fresh = if (output.next_fresh_index) |next| next == first else false;
        var failures: [RowWork.MAX_SHARDS]?anyerror = @splat(null);
        var context = Rows(Owner){ .owner = self, .evaluation = &evaluation, .output = &output, .workspaces = workspaces, .failures = &failures, .part = part, .inverse = inverse, .fresh = fresh };
        const active = RowWork.forEachRange(evaluation.size / E.LANES, &context, .{ .max_shards = plan.jobs, .min_rows_per_shard = MIN_BLOCKS_PER_TASK });
        // All helpers and their fixed pool submissions are joined. Select the
        // first ordinal error without dropping any still-running workspace.
        for (failures[0..active]) |failure| if (failure) |err| {
            output.next_fresh_index = null;
            return err;
        };
        output.next_fresh_index = if (fresh) first + evaluation.size else null;
        if (timer) |*clock| rows_ns += clock.lap();
    }
    if (profile) std.debug.print("OM_TRUTH_DOMAIN_STAGE kind={s} log={d} main={d} inter={d} constraints={d} jobs={d} prep_ns={d} fft_ns={d} rows_ns={d}\n", .{ @tagName(if (@hasField(Owner, "original")) self.original.kind else self.kind), logSize(self), widths[1], widths[2], self.nConstraints(), plan.jobs, prep_ns, fft_ns, rows_ns });
}
fn Rows(comptime Owner: type) type {
    return struct {
        owner: *const Owner,
        evaluation: *const Evaluation,
        output: *const D.ColumnAccumulator,
        workspaces: []RowWorkspace,
        failures: *[RowWork.MAX_SHARDS]?anyerror,
        part: usize,
        inverse: F,
        fresh: bool,
        pub fn runRange(self: *@This(), index: usize, first: usize, end: usize) void {
            self.evaluateRange(index, first, end) catch |err| {
                self.failures[index] = err;
            };
        }
        fn evaluateRange(self: *@This(), index: usize, first: usize, end: usize) !void {
            const workspace = &self.workspaces[index];
            for (first..end) |block| {
                const row = block * E.LANES;
                const shifts = try ShiftMap.init(logSize(self.owner), self.owner.compositionLogSplit(), self.part, row);
                var weighted = E.WeightedAccumulatorFor(F){ .powers = self.output.random_coeff_powers };
                var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
                try self.owner.emitForWithWorkspace(F, Samples(Owner){ .owner = self.owner, .evaluation = self.evaluation, .part = self.part, .row = row, .shifts = &shifts }, &sink, workspace);
                if (sink.count != self.owner.nConstraints()) return error.WideTruthConstraintCount;
                const result = weighted.accumulation.mulBase(self.inverse).coordinates();
                const start = self.evaluation.globalRow(self.part, row);
                for (self.output.col.columns, result) |column, value| {
                    if (self.fresh) value.store(column.ptr + start) else F.load(column.ptr + start).add(value).store(column.ptr + start);
                }
            }
        }
    };
}
