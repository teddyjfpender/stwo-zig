//! Generic-prover component for an authenticated captured Cairo AIR program.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("../../witness/composition_bundle.zig");
const verifier_runtime = @import("../../witness/resident_verifier.zig");
const native = @import("native_evaluator.zig");
const simd = @import("simd_evaluator.zig");
const trace_lease = @import("trace_lease.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const CoreComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const DomainAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;

pub const Component = struct {
    runtime: verifier_runtime.RuntimeComponent,
    native_executor: ?native.Executor = null,
    recorder: ?*prover.stage_profile.Recorder = null,

    const Adapter = core.air.derive.ComponentAdapter(
        @This(),
        ComponentProver,
        Trace,
        DomainAccumulator,
    );

    pub fn init(
        allocator: std.mem.Allocator,
        captured: *const composition.Component,
        preprocessed_logs: []const u32,
        lifting_log_size: u32,
        lookup_z: QM31,
        lookup_alpha: QM31,
        claimed_sum: QM31,
    ) Component {
        return .{ .runtime = .{
            .allocator = allocator,
            .captured = captured,
            .preprocessed_logs = preprocessed_logs,
            .lifting_log_size = lifting_log_size,
            .lookup_z = lookup_z,
            .lookup_alpha = lookup_alpha,
            .claimed_sum = claimed_sum,
        } };
    }

    pub fn asProverComponent(self: *const Component) ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.domain_parallel_evaluator = evaluateDomainParallelAdapter;
        // Multiple expensive Cairo AIRs need their own row split. Giving the
        // pool to each domain in turn avoids leaving a long one-core tail
        // after the default component-parallel scheduler drains its small jobs.
        component.pool_exclusive_domain = self.native_executor != null;
        return component;
    }

    pub fn asVerifierComponent(self: *const Component) CoreComponent {
        return self.runtime.asComponent();
    }

    pub fn nConstraints(self: *const Component) usize {
        return self.asVerifierComponent().nConstraints();
    }

    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.asVerifierComponent().maxConstraintLogDegreeBound();
    }

    pub fn traceLogDegreeBounds(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) !core.air.components.TraceLogDegreeBounds {
        return self.asVerifierComponent().traceLogDegreeBounds(allocator);
    }

    pub fn maskPoints(
        self: *const Component,
        allocator: std.mem.Allocator,
        point: Point,
        max_log_degree_bound: u32,
    ) !core.air.components.MaskPoints {
        return self.asVerifierComponent().maskPoints(
            allocator,
            point,
            max_log_degree_bound,
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return self.asVerifierComponent().preprocessedColumnIndices(allocator);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Component,
        point: Point,
        mask: *const core.air.components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        return self.asVerifierComponent().evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Component,
        trace: *const Trace,
        accumulator: *DomainAccumulator,
    ) !void {
        return self.evaluateConstraintQuotientsOnDomainImpl(
            trace,
            accumulator,
            null,
        );
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: *const Component,
        trace: *const Trace,
        accumulator: *DomainAccumulator,
        pool: *prover.work_pool.WorkPool,
    ) !void {
        return self.evaluateConstraintQuotientsOnDomainImpl(
            trace,
            accumulator,
            pool,
        );
    }

    fn evaluateConstraintQuotientsOnDomainImpl(
        self: *const Component,
        trace: *const Trace,
        accumulator: *DomainAccumulator,
        maybe_pool: ?*prover.work_pool.WorkPool,
    ) !void {
        var scope = try prover.stage_profile.StageScope.begin(self.recorder, "cpu_composition_component", stableProfileLabel(self.runtime.captured.label));
        defer scope.end();
        const captured = self.runtime.captured;
        const requests = [_]prover.air.accumulation.ColumnRequest{.{
            .log_size = captured.evaluation_log_size,
            .n_cols = captured.n_constraints,
        }};
        const columns = try accumulator.columns(accumulator.allocator, &requests);
        defer accumulator.allocator.free(columns);
        const column = &columns[0];

        const parameters = try self.runtime.extensionParameters();
        defer self.runtime.allocator.free(parameters);
        const coefficients = try orderedCoefficients(
            accumulator.allocator,
            column.random_coeff_powers,
        );
        defer accumulator.allocator.free(coefficients);
        // Interpreted components whose coefficient-backed columns would not
        // fit `tile_lease_budget` expand one row tile at a time; everything
        // else expands whole (or reads committed evaluations in place).
        var tiles: ?trace_lease.Tiles = if (self.native_executor == null)
            try trace_lease.Tiles.plan(accumulator.allocator, trace, captured, tile_lease_budget, tile_group_budget)
        else
            null;
        defer if (tiles) |*owned| owned.deinit();
        var lease = if (tiles == null)
            try trace_lease.Lease.init(accumulator.allocator, trace, captured)
        else
            trace_lease.Lease{ .allocator = accumulator.allocator, .source = trace };
        defer lease.deinit();
        prover.measurement.process_usage.reportStage("composition.lease_expanded");
        const context = TraceContext{
            .trace = lease.trace(),
            .captured = captured,
            .evaluation_log_size = captured.evaluation_log_size,
            .tiles = if (tiles) |*owned| owned else null,
        };
        var evaluation = EvaluationContext{
            .allocator = accumulator.allocator,
            .captured = captured,
            .trace = &context,
            .parameters = parameters,
            .coefficients = coefficients,
            .column = column,
        };
        const row_count = try checkedPow2(captured.evaluation_log_size);
        const prepared: ?[]?native.Prepared = if (self.native_executor != null)
            try accumulator.allocator.alloc(?native.Prepared, captured.parts.len)
        else
            null;
        if (prepared) |parts| @memset(parts, null);
        defer if (prepared) |parts| {
            for (parts) |*part| if (part.*) |*plan| plan.deinit(accumulator.allocator);
            accumulator.allocator.free(parts);
        };
        for (captured.parts, 0..) |part, index| {
            if (self.native_executor) |executor| {
                if (executor.resolve(native.identity(part.program))) |kernel|
                    prepared.?[index] = try native.Prepared.init(accumulator.allocator, kernel, part.program, evaluation.inputFor(part), column.col.columns);
            }
            const compiled = if (prepared) |parts| parts[index] != null else false;
            var marker = try prover.stage_profile.StageScope.begin(self.recorder, if (compiled) "cpu_native_air_part" else "cpu_ir_air_part", if (compiled) "Authenticated native AIR" else "SIMD AIR interpreter");
            marker.end();
        }
        evaluation.native_parts = prepared;
        // A composition column can be shared by several components. The first
        // writer stores directly and publishes `next_fresh_index`; every later
        // writer must accumulate. The serial path has to honour the same
        // protocol as the parallel one below, or a second component silently
        // clobbers the first.
        if (tiles) |*owned| {
            // Tiles are disjoint row runs: every tile stores (or accumulates)
            // under the same fresh-column decision the whole range would.
            const direct_store = column.next_fresh_index == 0;
            const tile_rows = owned.tileRows();
            for (0..owned.tileCount()) |tile| {
                try owned.load(tile);
                const first = tile * tile_rows;
                if (maybe_pool) |pool| if (pool.workerCount() > 1) {
                    try evaluateParallel(accumulator.allocator, &evaluation, pool, first, first + tile_rows, !direct_store, true);
                    continue;
                };
                try evaluation.evaluateRange(first, first + tile_rows, !direct_store);
            }
            column.next_fresh_index = if (direct_store) row_count else null;
            return;
        }
        const serial_pool = maybe_pool orelse
            return evaluateSerial(&evaluation, column, row_count);
        if (row_count < parallel_row_threshold or serial_pool.workerCount() <= 1) {
            return evaluateSerial(&evaluation, column, row_count);
        }
        const direct_store = column.next_fresh_index == 0;
        try evaluateParallel(accumulator.allocator, &evaluation, serial_pool, 0, row_count, !direct_store, self.native_executor != null);
        column.next_fresh_index = if (direct_store) row_count else null;
    }
};

/// Row-tile budget for coefficient-backed interpreted components
/// (`trace_lease.Tiles`), and the budget of their per-group prefolds.
const tile_lease_budget: usize = 256 << 20;
const tile_group_budget: usize = 256 << 20;

/// Evaluates rows `[row_start, row_end)` on `pool`: fixed contiguous splits,
/// or (`dynamic`) 8192-row chunks claimed from a shared cursor.
fn evaluateParallel(
    allocator: std.mem.Allocator,
    evaluation: *const EvaluationContext,
    pool: *prover.work_pool.WorkPool,
    row_start: usize,
    row_end: usize,
    additive: bool,
    dynamic: bool,
) !void {
    const row_count = row_end - row_start;
    const chunk_rows: usize = 8192;
    var cursor = std.atomic.Value(usize).init(row_start);
    const worker_count = @max(1, @min(pool.workerCount(), if (dynamic) std.math.divCeil(usize, row_count, chunk_rows) catch unreachable else row_count / simd.lane_count));
    const workers = try allocator.alloc(RangeWorker, worker_count);
    defer allocator.free(workers);
    const row_groups = row_count / simd.lane_count;
    for (workers, 0..) |*worker, index| {
        worker.* = .{
            .evaluation = evaluation.*,
            .row_start = if (dynamic) row_start else row_start + (row_groups * index / worker_count) * simd.lane_count,
            .row_end = if (dynamic) row_end else row_start + (row_groups * (index + 1) / worker_count) * simd.lane_count,
            .cursor = if (dynamic) &cursor else null,
            .chunk_rows = chunk_rows,
            .additive = additive,
        };
    }

    var wait_group = std.Thread.WaitGroup{};
    for (workers[1..]) |*worker| {
        pool.spawnWg(&wait_group, RangeWorker.run, .{worker});
    }
    RangeWorker.run(&workers[0]);
    wait_group.wait();
    for (workers) |worker| {
        if (worker.err) |err| return err;
    }
}

const parallel_row_threshold: usize = 4096;

/// Serial mirror of the parallel path's fresh-column protocol: derive
/// `additive` from whether the column already carries a written prefix, then
/// publish the same `next_fresh_index` the parallel path would have published.
fn evaluateSerial(
    evaluation: *const EvaluationContext,
    column: *prover.air.accumulation.ColumnAccumulator,
    row_count: usize,
) !void {
    const direct_store = column.next_fresh_index == 0;
    try evaluation.evaluateRange(0, row_count, !direct_store);
    column.next_fresh_index = if (direct_store) row_count else null;
}

fn evaluateDomainParallelAdapter(
    raw_context: *const anyopaque,
    trace: *const Trace,
    accumulator: *DomainAccumulator,
    pool: *prover.work_pool.WorkPool,
) anyerror!void {
    const self: *const Component = @ptrCast(@alignCast(raw_context));
    return self.evaluateConstraintQuotientsOnDomainParallel(
        trace,
        accumulator,
        pool,
    );
}

const EvaluationContext = struct {
    allocator: std.mem.Allocator,
    captured: *const composition.Component,
    trace: *const TraceContext,
    parameters: []const QM31,
    coefficients: []const QM31,
    column: *prover.air.accumulation.ColumnAccumulator,
    native_parts: ?[]const ?native.Prepared = null,

    fn inputFor(self: EvaluationContext, part: composition.Part) simd.Input {
        return .{
            .evaluation_log_size = self.captured.evaluation_log_size,
            .trace_log_size = self.captured.trace_log_size,
            .trace = .{
                .context = self.trace,
                .resolve = resolveTrace,
                .resolve_at = if (self.trace.tiles != null) resolveTraceAt else null,
            },
            .extension_parameters = self.parameters,
            .random_coefficients = self.coefficients,
            .constraint_base = part.rc_base,
            .denominator_inverses = self.captured.denominator_inverses,
        };
    }

    fn evaluateRange(
        self: EvaluationContext,
        row_start: usize,
        row_end: usize,
        additive: bool,
    ) !void {
        const output = RangeOutput{
            .column = self.column.col,
            .additive = additive,
        };
        for (self.captured.parts, 0..) |part, index| {
            if (self.native_parts) |parts| {
                if (parts[index]) |*prepared| {
                    try prepared.evaluateRange(row_start, row_end, additive);
                    continue;
                }
            }
            try simd.evaluatePartRange(self.allocator, part.program, self.inputFor(part), output, row_start, row_end);
        }
    }
};

const RangeOutput = struct {
    column: *prover.secure_column.SecureColumnByCoords,
    additive: bool,

    pub fn accumulate(self: RangeOutput, row: usize, value: QM31) void {
        if (self.additive) {
            self.column.set(row, self.column.at(row).add(value));
        } else {
            self.column.set(row, value);
        }
    }
};

const RangeWorker = struct {
    evaluation: EvaluationContext,
    row_start: usize,
    row_end: usize,
    additive: bool,
    err: ?anyerror = null,
    cursor: ?*std.atomic.Value(usize) = null,
    chunk_rows: usize = 8192,

    fn run(self: *RangeWorker) void {
        // Faster cores take more disjoint row tiles. Every tile keeps the full
        // constraint order, and all writers join before freshness is published.
        if (self.cursor) |cursor| {
            while (true) {
                const first = cursor.fetchAdd(self.chunk_rows, .monotonic);
                if (first >= self.row_end) return;
                self.evaluation.evaluateRange(first, @min(first + self.chunk_rows, self.row_end), self.additive) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
        self.evaluation.evaluateRange(
            self.row_start,
            self.row_end,
            self.additive,
        ) catch |err| {
            self.err = err;
        };
    }
};

/// The mask-resolution context the row loop reads through. Public because the
/// device composition stage (`device_stage.zig`) has to hand the *same*
/// resolver to the device path that the host path uses, or the two evaluators
/// would not be comparing the same columns.
pub const TraceContext = struct {
    trace: *const Trace,
    captured: *const composition.Component,
    evaluation_log_size: u32,
    /// Set while a component is evaluated tile by tile: expanded columns
    /// resolve to the loaded tile's block.
    tiles: ?*const trace_lease.Tiles = null,
};

/// Re-export of the resolver interface so callers outside this file can build a
/// reader without naming `simd_evaluator` themselves.
pub const TraceReader = simd.TraceReader;

/// Resolves one mask read site to its committed column and lifting shift.
/// Called once per read instruction per evaluated range; every check it
/// performs — tree arity, preprocessed index bounds, component span
/// arithmetic, column length against its log size, and the lifting shift
/// range — used to be repeated on every four-row group.
pub fn resolveTrace(
    raw_context: *const anyopaque,
    interaction: u8,
    local_column: u32,
) !simd.ResolvedColumn {
    const context: *const TraceContext = @ptrCast(@alignCast(raw_context));
    const key = try trace_lease.address(context.trace, context.captured, interaction, local_column);
    if (context.tiles) |tiles| if (tiles.view(key, 0)) |block| return tileRead(context, block);
    const column = context.trace.polys.items[key.tree][key.column];

    try column.validate();
    if (column.log_size > context.evaluation_log_size)
        return error.InvalidTraceShape;
    const shift = context.evaluation_log_size - column.log_size;
    if (shift + 1 >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    return .{
        .values = column.values,
        .shift_amt = @intCast(shift + 1),
    };
}

/// `resolveTrace` for a read at `mask_offset`: a tiled column's halo, read
/// by row, or the ordinary resolution.
pub fn resolveTraceAt(
    raw_context: *const anyopaque,
    interaction: u8,
    local_column: u32,
    mask_offset: i32,
) !simd.ResolvedColumn {
    const context: *const TraceContext = @ptrCast(@alignCast(raw_context));
    if (context.tiles) |tiles| {
        const key = try trace_lease.address(context.trace, context.captured, interaction, local_column);
        if (tiles.view(key, mask_offset)) |block| return tileRead(context, block);
    }
    return resolveTrace(raw_context, interaction, local_column);
}

fn tileRead(context: *const TraceContext, block: trace_lease.Tiles.View) !simd.ResolvedColumn {
    if (block.coset_log > context.evaluation_log_size) return error.InvalidTraceShape;
    return .{
        .values = block.values,
        .shift_amt = @intCast(context.evaluation_log_size - block.coset_log + 1),
        .base = block.base,
        .row_indexed = block.row_indexed,
    };
}

/// Reverses the accumulator's power vector into the orientation
/// `simd_evaluator` and the compiled kernels both index at `rc_base`.
pub fn orderedCoefficients(
    allocator: std.mem.Allocator,
    powers: []const QM31,
) ![]QM31 {
    const output = try allocator.alloc(QM31, powers.len);
    for (output, 0..) |*value, index| {
        value.* = powers[powers.len - 1 - index];
    }
    return output;
}

fn checkedPow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "Cairo coefficients preserve point-accumulator order" {
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const ordered = try orderedCoefficients(std.testing.allocator, &values);
    defer std.testing.allocator.free(ordered);
    try std.testing.expect(ordered[0].eql(values[2]));
    try std.testing.expect(ordered[1].eql(values[1]));
    try std.testing.expect(ordered[2].eql(values[0]));
}

/// Recorder labels outlive the owned captured bundle: borrow only canonical
/// static registry names, including a stable name for repeated memory slots.
fn stableProfileLabel(label: []const u8) []const u8 {
    const registry = @import("../../air/official_claim_registry.zig");
    for (registry.enable_slots) |entry| if (std.mem.eql(u8, entry.name, label)) return entry.name;
    for (registry.claim_fields) |entry| if (std.mem.startsWith(u8, label, entry.name)) return entry.name;
    return "Captured Cairo AIR";
}
