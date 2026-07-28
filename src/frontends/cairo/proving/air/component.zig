//! Generic-prover component for an authenticated captured Cairo AIR program.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("../../witness/composition_bundle.zig");
const geometry = @import("../../witness/resident_geometry.zig");
const verifier_runtime = @import("../../witness/resident_verifier.zig");
const simd = @import("simd_evaluator.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const CoreComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const DomainAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;

pub const Component = struct {
    runtime: verifier_runtime.RuntimeComponent,

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
        const context = TraceContext{
            .trace = trace,
            .captured = captured,
            .evaluation_log_size = captured.evaluation_log_size,
        };
        const evaluation = EvaluationContext{
            .allocator = accumulator.allocator,
            .captured = captured,
            .trace = &context,
            .parameters = parameters,
            .coefficients = coefficients,
            .column = column,
        };
        const row_count = try checkedPow2(captured.evaluation_log_size);
        const pool = maybe_pool orelse
            return evaluation.evaluateRange(0, row_count, false);
        if (row_count < parallel_row_threshold or pool.workerCount() <= 1) {
            return evaluation.evaluateRange(0, row_count, false);
        }

        const worker_count = @min(pool.workerCount(), row_count / simd.lane_count);
        const workers = try accumulator.allocator.alloc(RangeWorker, worker_count);
        defer accumulator.allocator.free(workers);
        const row_groups = row_count / simd.lane_count;
        const direct_store = column.next_fresh_index == 0;
        for (workers, 0..) |*worker, index| {
            worker.* = .{
                .evaluation = evaluation,
                .row_start = (row_groups * index / worker_count) * simd.lane_count,
                .row_end = (row_groups * (index + 1) / worker_count) * simd.lane_count,
                .additive = !direct_store,
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
        column.next_fresh_index = if (direct_store) row_count else null;
    }
};

const parallel_row_threshold: usize = 4096;

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
        for (self.captured.parts) |part| {
            try simd.evaluatePartRange(
                self.allocator,
                part.program,
                .{
                    .evaluation_log_size = self.captured.evaluation_log_size,
                    .trace_log_size = self.captured.trace_log_size,
                    .trace = .{ .context = self.trace, .read = readTrace },
                    .extension_parameters = self.parameters,
                    .random_coefficients = self.coefficients,
                    .constraint_base = part.rc_base,
                    .denominator_inverses = self.captured.denominator_inverses,
                },
                output,
                row_start,
                row_end,
            );
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

    fn run(self: *RangeWorker) void {
        self.evaluation.evaluateRange(
            self.row_start,
            self.row_end,
            self.additive,
        ) catch |err| {
            self.err = err;
        };
    }
};

const TraceContext = struct {
    trace: *const Trace,
    captured: *const composition.Component,
    evaluation_log_size: u32,
};

fn readTrace(
    raw_context: *const anyopaque,
    interaction: u8,
    local_column: u32,
    row: usize,
    offset: i32,
) !simd.PackedM31 {
    const context: *const TraceContext = @ptrCast(@alignCast(raw_context));
    if (context.trace.polys.items.len < 3) return error.InvalidTraceShape;
    const column = switch (interaction) {
        0 => blk: {
            if (local_column >= context.captured.preprocessed_indices.len)
                return error.InvalidTraceShape;
            const global = context.captured.preprocessed_indices[local_column];
            if (global >= context.trace.polys.items[0].len)
                return error.InvalidTraceShape;
            break :blk context.trace.polys.items[0][global];
        },
        1, 2 => blk: {
            const span = try geometry.componentSpan(
                context.captured.*,
                interaction,
            );
            const global = std.math.add(
                usize,
                span.start,
                local_column,
            ) catch return error.InvalidTraceShape;
            if (global >= span.end or global >= context.trace.polys.items[interaction].len)
                return error.InvalidTraceShape;
            break :blk context.trace.polys.items[interaction][global];
        },
        else => return error.InvalidTraceShape,
    };

    var values: simd.PackedM31 = undefined;
    inline for (0..simd.lane_count) |lane| {
        const position = row + lane;
        const shifted = if (offset == 0)
            position
        else
            core.utils.offsetBitReversedCircleDomainIndex(
                position,
                context.captured.trace_log_size,
                context.evaluation_log_size,
                offset,
            );
        const value: M31 = try column.valueAtLiftingPosition(
            context.evaluation_log_size,
            shifted,
        );
        values[lane] = value.toU32();
    }
    return values;
}

fn orderedCoefficients(
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
