//! Prepared-domain execution authority for the opcode lookup component.
//!
//! The public component owns protocol geometry and row semantics. This module
//! owns the cold evaluation preparation and the parallel row executor so the
//! hot loop has one focused implementation and no facade-level allocation or
//! dispatch overhead.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const qm31 = @import("stwo_core").fields.qm31;
const QM31 = qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const prepared_parallel = @import("../prepared_parallel.zig");
const prepared_evaluation = @import("../prepared_evaluation_owner.zig");
const trace = @import("../../runner/trace.zig");
const entry = @import("entry.zig");
const opcode_interaction = @import("opcode_interaction.zig");

pub const PARALLEL_DOMAIN_ROWS: usize = 2 * 4096;
pub const TelemetrySnapshot = prepared_parallel.TelemetrySnapshot;

var telemetry: prepared_parallel.Telemetry = .{};

pub fn telemetrySnapshot() TelemetrySnapshot {
    return telemetry.snapshot();
}

pub fn prepare(
    comptime Component: type,
    component: *const Component,
    allocator: std.mem.Allocator,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !prepared_domain.PreparedDomainEvaluation {
    if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
    const eval_log_size = std.math.add(u32, component.log_size, 1) catch
        return error.InvalidProofShape;
    if (component.log_size == 0 or
        eval_log_size > circle.M31_CIRCLE_LOG_ORDER - 1 or
        eval_log_size >= @bitSizeOf(usize))
    {
        return error.InvalidProofShape;
    }
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    try component.mask_binding.validate();
    const n_main: usize = component.mask_binding.borrowed_main_current_columns;
    const n_interaction = component.interactionColumnCount();
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const secure = trace_data.polys.items[2];
    const main_end = std.math.add(usize, component.main_col_offset, n_main) catch
        return error.InvalidProofShape;
    const interaction_end = std.math.add(
        usize,
        component.interaction_col_offset,
        n_interaction,
    ) catch return error.InvalidProofShape;
    if (preprocessed.len <= component.is_first_col_idx or
        main.len < main_end or secure.len < interaction_end)
        return error.InvalidProofShape;

    var n_sources = std.math.add(usize, 1, n_main) catch
        return error.InvalidProofShape;
    n_sources = std.math.add(usize, n_sources, n_interaction) catch
        return error.InvalidProofShape;
    const StateType = State(Component);
    if (n_sources > StateType.MAX_SOURCES) return error.InvalidProofShape;
    var owned_count: usize = 0;
    owned_count += @intFromBool(try prepared_evaluation.needsOwned(
        preprocessed[component.is_first_col_idx],
        component.log_size,
        eval_log_size,
    ));
    for (main[component.main_col_offset..main_end]) |poly| {
        owned_count += @intFromBool(try prepared_evaluation.needsOwned(
            poly,
            component.log_size,
            eval_log_size,
        ));
    }
    for (secure[component.interaction_col_offset..interaction_end]) |poly| {
        owned_count += @intFromBool(try prepared_evaluation.needsOwned(
            poly,
            component.log_size,
            eval_log_size,
        ));
    }
    var evaluation_owner = try prepared_evaluation.Owner.init(
        allocator,
        owned_count,
    );
    errdefer evaluation_owner.deinit();
    var evaluations = [_][]const M31{&.{}} ** StateType.MAX_SOURCES;
    var source: usize = 0;
    evaluations[source] = try evaluation_owner.value(
        preprocessed[component.is_first_col_idx],
        component.log_size,
        eval_log_size,
        eval_size,
    );
    source += 1;
    for (main[component.main_col_offset..main_end]) |poly| {
        evaluations[source] = try evaluation_owner.value(
            poly,
            component.log_size,
            eval_log_size,
            eval_size,
        );
        source += 1;
    }
    for (secure[component.interaction_col_offset..interaction_end]) |poly| {
        evaluations[source] = try evaluation_owner.value(
            poly,
            component.log_size,
            eval_log_size,
            eval_size,
        );
        source += 1;
    }

    std.debug.assert(source == n_sources);
    try evaluation_owner.finish(eval_domain);

    const denominator_inv = try quotientDenominators(
        component.log_size,
        eval_log_size,
        eval_domain,
    );
    const resources = try preparedDomainResources(Component, eval_size, owned_count);
    const state = try allocator.create(StateType);
    errdefer allocator.destroy(state);
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component.nConstraints() }},
    );
    state.* = .{
        .allocator = allocator,
        .component = component,
        .evaluations = evaluations,
        .evaluation_owner = evaluation_owner,
        .source_count = n_sources,
        .n_main = n_main,
        .interaction_start = 1 + n_main,
        .eval_log_size = eval_log_size,
        .eval_size = eval_size,
        .denominator_inv = denominator_inv,
        .accumulators = accumulators,
        .direct_store = accumulators[0].next_fresh_index == 0,
    };
    return .{
        .context = state,
        .vtable = &StateType.vtable,
        .task_class = if (eval_size >= PARALLEL_DOMAIN_ROWS)
            .pool_exclusive
        else
            .leaf,
        .resources = resources,
    };
}

pub fn runSerial(evaluation: *prepared_domain.PreparedDomainEvaluation) !void {
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = prover_task_graph.TaskContext{
        .user_context = evaluation.context,
        .cancellation = &cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
    try evaluation.run(&task_context);
}

pub fn State(comptime Component: type) type {
    return struct {
        const Self = @This();
        pub const CANCELLATION_POLL_ROWS: usize = 4096;
        pub const MAX_SOURCES: usize = 1 +
            trace.MAX_FAMILY_COLUMNS + opcode_interaction.MAX_COLUMNS;

        const RangeWorker = struct {
            state: *Self,
            parent_cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
            is_child: bool,
            completed: bool = false,
            failure: ?anyerror = null,

            fn run(self: *@This()) void {
                defer if (self.is_child) telemetry.recordChildCompletion();
                self.completed = self.state.evaluateRange(
                    self.parent_cancellation,
                    self.range_index,
                    self.row_start,
                    self.row_end,
                ) catch |failure| failed: {
                    self.failure = failure;
                    telemetry.recordRangeFailure();
                    if (self.state.failure_boundary.recordFailure(self.range_index)) {
                        telemetry.recordLocalCancellation();
                    }
                    break :failed false;
                };
            }
        };

        allocator: std.mem.Allocator,
        component: *const Component,
        evaluations: [MAX_SOURCES][]const M31,
        evaluation_owner: prepared_evaluation.Owner,
        source_count: usize,
        n_main: usize,
        interaction_start: usize,
        eval_log_size: u32,
        eval_size: usize,
        denominator_inv: [2]M31,
        accumulators: []prover_air_accumulation.ColumnAccumulator,
        direct_store: bool,
        failure_boundary: prepared_parallel.FailureBoundary = .{},
        range_workers: [work_pool.MAX_WORKERS]RangeWorker = undefined,

        pub const vtable = prepared_domain.VTable{
            .run = runErased,
            .deinit = deinitErased,
        };

        comptime {
            if (CANCELLATION_POLL_ROWS == 0 or
                CANCELLATION_POLL_ROWS > 4096 or
                !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
            {
                @compileError("opcode prepared-domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
            }
        }

        fn runErased(
            context: *anyopaque,
            task_context: *prover_task_graph.TaskContext,
        ) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.failure_boundary.reset();
            const tile_count = std.math.divCeil(
                usize,
                self.eval_size,
                CANCELLATION_POLL_ROWS,
            ) catch unreachable;
            const worker_count = @min(task_context.worker_budget.count, tile_count);
            if (worker_count == 1) {
                if (try self.evaluateRange(
                    task_context.cancellation,
                    0,
                    0,
                    self.eval_size,
                )) self.finishOutput();
                return;
            }

            std.debug.assert(task_context.task_class == .pool_exclusive);
            const tiles_per_worker = tile_count / worker_count;
            const workers_with_extra_tile = tile_count % worker_count;
            var next_tile: usize = 0;
            for (self.range_workers[0..worker_count], 0..) |*worker, index| {
                const assigned_tiles = tiles_per_worker +
                    @intFromBool(index < workers_with_extra_tile);
                const end_tile = next_tile + assigned_tiles;
                worker.* = .{
                    .state = self,
                    .parent_cancellation = task_context.cancellation,
                    .range_index = index,
                    .row_start = next_tile * CANCELLATION_POLL_ROWS,
                    .row_end = @min(
                        self.eval_size,
                        end_tile * CANCELLATION_POLL_ROWS,
                    ),
                    .is_child = index != 0,
                };
                next_tile = end_tile;
            }
            std.debug.assert(next_tile == tile_count);
            for (self.range_workers[1..worker_count]) |*worker| {
                try task_context.spawnChild(RangeWorker.run, .{worker});
                telemetry.recordChildSubmission();
            }
            self.range_workers[0].run();
            try task_context.waitForChildren();
            // Inspect in stable row order after the join so completion order
            // cannot select a different failure.
            for (self.range_workers[0..worker_count]) |worker| {
                if (worker.failure) |failure| return failure;
            }
            for (self.range_workers[0..worker_count]) |worker| {
                if (!worker.completed) return;
            }
            self.finishOutput();
        }

        fn evaluateRange(
            self: *Self,
            parent_cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
        ) !bool {
            const component = self.component;
            const batch_count = component.nConstraints();
            const column_accumulator = &self.accumulators[0];
            const powers = column_accumulator.random_coeff_powers;
            const evaluations = self.evaluations[0..self.source_count];
            const denominator_shift: std.math.Log2Int(usize) =
                @intCast(component.log_size);
            for (row_start..row_end) |row| {
                if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
                    (parent_cancellation.isCancelled() or
                        self.failure_boundary.shouldCancel(range_index)))
                {
                    return false;
                }
                const previous_row = utils.previousBitReversedCircleDomainIndex(
                    row,
                    component.log_size,
                    self.eval_log_size,
                );
                var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
                for (
                    sampled[0..self.n_main],
                    evaluations[1..][0..self.n_main],
                ) |*value, column| value.* = QM31.fromBase(column[row]);
                var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
                var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
                for (0..batch_count) |batch| {
                    current[batch] = secureAt(
                        evaluations[self.interaction_start + 4 * batch ..][0..4],
                        row,
                    );
                    previous[batch] = secureAt(
                        evaluations[self.interaction_start + 4 * batch ..][0..4],
                        previous_row,
                    );
                }
                const constraints = try component.evaluateRow(
                    sampled[0..self.n_main],
                    current[0..batch_count],
                    previous[0..batch_count],
                    QM31.fromBase(evaluations[0][row]),
                );
                var folded = QM31.zero();
                for (
                    constraints.values[0..constraints.len],
                    0..,
                ) |constraint, index| {
                    folded = folded.add(
                        powers[powers.len - 1 - index].mul(constraint),
                    );
                }
                const contribution = folded.mulM31(
                    self.denominator_inv[row >> denominator_shift],
                );
                const output = column_accumulator.col;
                if (self.direct_store) {
                    output.set(row, contribution);
                } else {
                    output.set(row, output.at(row).add(contribution));
                }
            }
            return true;
        }

        fn finishOutput(self: *Self) void {
            self.accumulators[0].next_fresh_index =
                if (self.direct_store) self.eval_size else null;
        }

        fn deinitErased(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            const allocator = self.allocator;
            allocator.free(self.accumulators);
            self.evaluation_owner.deinit();
            allocator.destroy(self);
        }
    };
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

fn quotientDenominators(
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![2]M31 {
    const expected_log_size = std.math.add(u32, log_size, 1) catch
        return error.InvalidProofShape;
    if (eval_log_size != expected_log_size) return error.InvalidProofShape;
    const extension_bits: u5 = 1;
    var result: [2]M31 = undefined;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (&result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

pub fn preparedDomainResources(
    comptime Component: type,
    eval_size: usize,
    owned_count: usize,
) !prover_task_graph.ResourceReservation {
    const secure_element_bytes = std.math.mul(
        usize,
        qm31.SECURE_EXTENSION_DEGREE,
        @sizeOf(M31),
    ) catch return error.ResourceReservationOverflow;
    const final_output_bytes = std.math.mul(
        usize,
        eval_size,
        secure_element_bytes,
    ) catch return error.ResourceReservationOverflow;
    var shared_resident_bytes = std.math.add(
        usize,
        @sizeOf(State(Component)),
        @sizeOf(prover_air_accumulation.ColumnAccumulator),
    ) catch return error.ResourceReservationOverflow;
    shared_resident_bytes = std.math.add(
        usize,
        shared_resident_bytes,
        try prepared_evaluation.residentBytes(owned_count, eval_size),
    ) catch return error.ResourceReservationOverflow;
    _ = std.math.add(
        usize,
        final_output_bytes,
        shared_resident_bytes,
    ) catch return error.ResourceReservationOverflow;
    return .{
        .final_output_bytes = final_output_bytes,
        .shared_resident_bytes = shared_resident_bytes,
        .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    };
}

const TestEvaluation = struct {
    values: [entry.MAX_BATCHES]QM31 = .{QM31.zero()} ** entry.MAX_BATCHES,
    len: usize = 1,
};

const TestComponent = struct {
    log_size: u32 = 1,

    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }

    pub fn evaluateRow(
        _: *const @This(),
        _: []const QM31,
        _: []const QM31,
        _: []const QM31,
        _: QM31,
    ) !TestEvaluation {
        return .{};
    }
};

test "opcode prepared domain resource geometry and cancellation cadence are bounded" {
    const secure_element_bytes = qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);
    const owned_count: usize = 3;
    const resources = try preparedDomainResources(TestComponent, 17, owned_count);
    try std.testing.expectEqual(
        17 * secure_element_bytes,
        resources.final_output_bytes,
    );
    try std.testing.expectEqual(
        @sizeOf(State(TestComponent)) +
            @sizeOf(prover_air_accumulation.ColumnAccumulator) +
            try prepared_evaluation.residentBytes(owned_count, 17),
        resources.shared_resident_bytes,
    );
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        resources.worker_stack_bytes,
    );
    try std.testing.expect(State(TestComponent).CANCELLATION_POLL_ROWS <= 4096);
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        preparedDomainResources(
            TestComponent,
            std.math.maxInt(usize) / secure_element_bytes,
            owned_count,
        ),
    );
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        preparedDomainResources(TestComponent, 17, std.math.maxInt(usize)),
    );
}
