//! Prover/verifier adapter for the exact Merkle-node and Poseidon2 AIRs.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
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
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const work_pool = @import("stwo_prover_engine").work_pool;
const prepared_parallel = @import("../prepared_parallel.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const merkle_node = @import("merkle_node.zig");
const prepared_support = @import("hash_component_prepared_support.zig");
const poseidon2_air = @import("poseidon2_air.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const N_POSEIDON_SHELL_CONSTRAINTS: usize = 3;
const N_POSEIDON_COMPONENT_CONSTRAINTS: usize =
    poseidon2_air.N_CONSTRAINTS + N_POSEIDON_SHELL_CONSTRAINTS + poseidon2_air.N_SUMS;

pub const Kind = enum { merkle, poseidon2 };
pub const PREPARED_DENOMINATOR_COUNT: usize = 2;
pub const PARALLEL_DOMAIN_LOG_SIZE: u32 = 12;

pub const PreparedParallelTelemetrySnapshot = prepared_parallel.TelemetrySnapshot;
var prepared_parallel_telemetry: prepared_parallel.Telemetry = .{};

pub fn preparedParallelTelemetrySnapshot() PreparedParallelTelemetrySnapshot {
    return prepared_parallel_telemetry.snapshot();
}

pub const HashComponent = struct {
    kind: Kind,
    log_size: u32,
    n_rows: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    merkle_claims: [merkle_node.N_SUMS]QM31 = .{QM31.zero()} ** merkle_node.N_SUMS,
    poseidon_claims: [poseidon2_air.N_SUMS]QM31 = .{QM31.zero()} ** poseidon2_air.N_SUMS,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        return component;
    }

    fn prepareDomainEvaluatorErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return self.prepareDomainEvaluator(allocator, trace_data, accumulator);
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return switch (self.kind) {
            .merkle => merkle_node.N_CONSTRAINTS,
            .poseidon2 => N_POSEIDON_COMPONENT_CONSTRAINTS,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + switch (self.kind) {
            .merkle => @as(u32, 1),
            .poseidon2 => @as(u32, 1),
        };
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &[_]u32{ self.log_size, self.log_size });
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, nMainColumns(self.kind));
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(u32, nInteractionColumns(self.kind));
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main, interaction }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try currentPointColumns(allocator, 2, point);
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, nMainColumns(self.kind), point);
        errdefer freePointColumns(allocator, main);
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const interaction = try currentAndPreviousPointColumns(
            allocator,
            nInteractionColumns(self.kind),
            point,
            previous_point,
        );
        errdefer freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{ self.is_first_col_idx, self.is_active_col_idx });
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main_mask = mask.items[1];
        const interaction_mask = mask.items[2];
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        if (preprocessed.len <= self.is_active_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
            main_mask.len < self.main_col_offset + n_main or
            interaction_mask.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        const is_first = preprocessed[self.is_first_col_idx][0];
        const is_active = preprocessed[self.is_active_col_idx][0];

        switch (self.kind) {
            .merkle => {
                const main = try sampleMain(
                    merkle_node.N_MAIN_COLUMNS,
                    main_mask,
                    self.main_col_offset,
                );
                var sums: [merkle_node.N_SUMS]QM31 = undefined;
                var previous: [merkle_node.N_SUMS]QM31 = undefined;
                try sampleInteraction(
                    merkle_node.N_SUMS,
                    interaction_mask,
                    self.interaction_col_offset,
                    &sums,
                    &previous,
                );
                const constraints = merkle_node.evaluate(
                    main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.merkle_claims,
                    self.relations,
                );
                for (constraints) |constraint| accumulator.accumulate(constraint.mul(denominator_inv));
            },
            .poseidon2 => {
                const main = try sampleMain(
                    poseidon2_air.N_MAIN_COLUMNS,
                    main_mask,
                    self.main_col_offset,
                );
                var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                try sampleInteraction(
                    poseidon2_air.N_SUMS,
                    interaction_mask,
                    self.interaction_col_offset,
                    &sums,
                    &previous,
                );
                const constraints = poseidonConstraints(
                    main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.poseidon_claims,
                    self.relations,
                );
                for (constraints) |constraint| {
                    accumulator.accumulate(constraint.mul(denominator_inv));
                }
            },
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try self.prepareDomainEvaluator(
            accumulator.allocator,
            trace_data,
            accumulator,
        );
        defer prepared.deinit();
        var cancellation = prover_task_graph.CancellationToken{};
        var task_context = serialTaskContext(prepared.context, &cancellation);
        try prepared.run(&task_context);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
        const eval_log_size = std.math.add(u32, self.log_size, 1) catch
            return error.InvalidProofShape;
        if (self.log_size == 0 or eval_log_size >= circle.M31_CIRCLE_LOG_ORDER) {
            return error.InvalidProofShape;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const trace_size = @as(usize, 1) << @intCast(self.log_size);
        if (@as(usize, self.n_rows) > trace_size) return error.InvalidProofShape;
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        const main_end = std.math.add(usize, self.main_col_offset, n_main) catch
            return error.InvalidProofShape;
        const interaction_end = std.math.add(
            usize,
            self.interaction_col_offset,
            n_interaction,
        ) catch return error.InvalidProofShape;
        const source_count = std.math.add(
            usize,
            std.math.add(usize, 2, n_main) catch
                return error.ResourceReservationOverflow,
            n_interaction,
        ) catch return error.ResourceReservationOverflow;
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const interaction = trace_data.polys.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            main.len < main_end or interaction.len < interaction_end)
        {
            return error.InvalidProofShape;
        }

        var owned_count: usize = 0;
        const sources = .{
            preprocessed[self.is_first_col_idx],
            preprocessed[self.is_active_col_idx],
        };
        inline for (sources) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, self.log_size, eval_log_size)) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }
        for (main[self.main_col_offset..main_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, self.log_size, eval_log_size)) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }
        for (interaction[self.interaction_col_offset..interaction_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, self.log_size, eval_log_size)) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }

        const evaluations = try allocator.alloc([]const M31, source_count);
        errdefer allocator.free(evaluations);
        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var owned_initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..owned_initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        var source: usize = 0;
        inline for (sources) |poly| {
            evaluations[source] = try prepared_support.evaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
            source += 1;
        }
        for (main[self.main_col_offset..main_end]) |poly| {
            evaluations[source] = try prepared_support.evaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
            source += 1;
        }
        for (interaction[self.interaction_col_offset..interaction_end]) |poly| {
            evaluations[source] = try prepared_support.evaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
            source += 1;
        }
        std.debug.assert(source == source_count);
        std.debug.assert(owned_initialized == owned_count);
        if (owned_buffers.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                owned_buffers,
                eval_domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const denominator_inv = try prepared_support.quotientDenominators(
            PREPARED_DENOMINATOR_COUNT,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resources(
            eval_size,
            source_count,
            owned_count,
            @sizeOf(PreparedDomainState),
        );
        const state = try allocator.create(PreparedDomainState);
        errdefer allocator.destroy(state);
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }},
        );
        defer allocator.free(accumulators);
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .owned_buffers = owned_buffers,
            .denominator_inv = denominator_inv,
            .column_accumulator = accumulators[0],
            .direct_store = accumulators[0].next_fresh_index == 0,
            .main_start = 2,
            .interaction_start = 2 + n_main,
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
        };
        return .{
            .context = state,
            .vtable = &PreparedDomainState.vtable,
            .task_class = if (self.log_size >= PARALLEL_DOMAIN_LOG_SIZE)
                .pool_exclusive
            else
                .leaf,
            .resources = resources,
        };
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;

    comptime {
        if (PREPARED_DENOMINATOR_COUNT != 2) {
            @compileError("hash composition domains own exactly two quotient denominators");
        }
        if (CANCELLATION_POLL_ROWS == 0 or
            CANCELLATION_POLL_ROWS > 4096 or
            !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
        {
            @compileError("prepared domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
        }
    }

    allocator: std.mem.Allocator,
    component: *const HashComponent,
    evaluations: [][]const M31,
    owned_buffers: [][]M31,
    denominator_inv: [PREPARED_DENOMINATOR_COUNT]M31,
    column_accumulator: prover_air_accumulation.ColumnAccumulator,
    direct_store: bool,
    main_start: usize,
    interaction_start: usize,
    eval_log_size: u32,
    eval_size: usize,
    failure_boundary: prepared_parallel.FailureBoundary = .{},
    range_workers: [work_pool.MAX_WORKERS]PreparedRangeWorker = undefined,

    const vtable = prepared_domain.VTable{
        .run = runErased,
        .deinit = deinitErased,
    };

    fn runErased(
        context: *anyopaque,
        task_context: *prover_task_graph.TaskContext,
    ) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.failure_boundary.reset();
        const tile_count = std.math.divCeil(
            usize,
            self.eval_size,
            CANCELLATION_POLL_ROWS,
        ) catch unreachable;
        const worker_count = @min(task_context.worker_budget.count, tile_count);
        if (worker_count == 1) {
            if (try self.evaluateRange(task_context.cancellation, 0, 0, self.eval_size)) {
                self.finishOutput();
            }
            return;
        }

        std.debug.assert(task_context.task_class == .pool_exclusive);
        const tiles_per_worker = tile_count / worker_count;
        const workers_with_extra_tile = tile_count % worker_count;
        var next_tile: usize = 0;
        for (self.range_workers[0..worker_count], 0..) |*worker, index| {
            const assigned_tiles = tiles_per_worker + @intFromBool(index < workers_with_extra_tile);
            const end_tile = next_tile + assigned_tiles;
            worker.* = .{
                .state = self,
                .parent_cancellation = task_context.cancellation,
                .range_index = index,
                .row_start = next_tile * CANCELLATION_POLL_ROWS,
                .row_end = @min(self.eval_size, end_tile * CANCELLATION_POLL_ROWS),
                .is_child = index != 0,
            };
            next_tile = end_tile;
        }
        std.debug.assert(next_tile == tile_count);
        for (self.range_workers[1..worker_count]) |*worker| {
            try task_context.spawnChild(PreparedRangeWorker.run, .{worker});
            prepared_parallel_telemetry.recordChildSubmission();
        }
        self.range_workers[0].run();
        try task_context.waitForChildren();
        // Ranges are stored in ascending row order. Inspecting failures only
        // after the join makes the selected error independent of completion
        // order while local cancellation remains only a work-saving signal.
        for (self.range_workers[0..worker_count]) |worker| {
            if (worker.failure) |failure| return failure;
        }
        for (self.range_workers[0..worker_count]) |worker| {
            if (!worker.completed) return;
        }
        self.finishOutput();
    }

    fn deinitErased(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        for (self.owned_buffers) |values| allocator.free(values);
        allocator.free(self.owned_buffers);
        allocator.free(self.evaluations);
        allocator.destroy(self);
    }

    fn evaluateRange(
        self: *@This(),
        parent_cancellation: *const prover_task_graph.CancellationToken,
        range_index: usize,
        row_start: usize,
        row_end: usize,
    ) anyerror!bool {
        const component = self.component;
        for (row_start..row_end) |row| {
            if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
                (parent_cancellation.isCancelled() or
                    self.failure_boundary.shouldCancel(range_index))) return false;
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                component.log_size,
                self.eval_log_size,
            );
            const is_first = QM31.fromBase(self.evaluations[0][row]);
            const is_active = QM31.fromBase(self.evaluations[1][row]);
            var row_evaluation = QM31.zero();
            switch (component.kind) {
                .merkle => {
                    const main = readMain(
                        merkle_node.N_MAIN_COLUMNS,
                        self.evaluations[self.main_start..][0..merkle_node.N_MAIN_COLUMNS],
                        row,
                    );
                    var sums: [merkle_node.N_SUMS]QM31 = undefined;
                    var previous: [merkle_node.N_SUMS]QM31 = undefined;
                    readInteraction(
                        merkle_node.N_SUMS,
                        self.evaluations,
                        self.interaction_start,
                        row,
                        previous_row,
                        &sums,
                        &previous,
                    );
                    const constraints = merkle_node.evaluate(
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        component.merkle_claims,
                        component.relations,
                    );
                    row_evaluation = combineConstraints(
                        self.column_accumulator.random_coeff_powers,
                        &constraints,
                    );
                },
                .poseidon2 => {
                    const main = readMain(
                        poseidon2_air.N_MAIN_COLUMNS,
                        self.evaluations[self.main_start..][0..poseidon2_air.N_MAIN_COLUMNS],
                        row,
                    );
                    var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                    var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                    readInteraction(
                        poseidon2_air.N_SUMS,
                        self.evaluations,
                        self.interaction_start,
                        row,
                        previous_row,
                        &sums,
                        &previous,
                    );
                    const constraints = poseidonConstraints(
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        component.poseidon_claims,
                        component.relations,
                    );
                    row_evaluation = combineConstraints(
                        self.column_accumulator.random_coeff_powers,
                        &constraints,
                    );
                },
            }
            const contribution = row_evaluation.mulM31(
                self.denominator_inv[row >> @intCast(component.log_size)],
            );
            const output = self.column_accumulator.col;
            if (self.direct_store) {
                output.set(row, contribution);
            } else {
                output.set(row, output.at(row).add(contribution));
            }
        }
        return true;
    }

    fn finishOutput(self: *@This()) void {
        self.column_accumulator.next_fresh_index = if (self.direct_store) self.eval_size else null;
    }
};

const PreparedRangeWorker = struct {
    state: *PreparedDomainState,
    parent_cancellation: *const prover_task_graph.CancellationToken,
    range_index: usize,
    row_start: usize,
    row_end: usize,
    is_child: bool,
    completed: bool = false,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        defer if (self.is_child) {
            prepared_parallel_telemetry.recordChildCompletion();
        };
        self.completed = self.state.evaluateRange(
            self.parent_cancellation,
            self.range_index,
            self.row_start,
            self.row_end,
        ) catch |failure| failed: {
            self.failure = failure;
            prepared_parallel_telemetry.recordRangeFailure();
            if (self.state.failure_boundary.recordFailure(self.range_index)) {
                prepared_parallel_telemetry.recordLocalCancellation();
            }
            break :failed false;
        };
    }
};

fn serialTaskContext(
    user_context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = user_context,
        .cancellation = cancellation,
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
}

pub fn nMainColumns(kind: Kind) usize {
    return switch (kind) {
        .merkle => merkle_node.N_MAIN_COLUMNS,
        .poseidon2 => poseidon2_air.N_MAIN_COLUMNS,
    };
}

pub fn nInteractionColumns(kind: Kind) usize {
    return switch (kind) {
        .merkle => merkle_node.N_INTERACTION_COLUMNS,
        .poseidon2 => poseidon2_air.N_INTERACTION_COLUMNS,
    };
}

pub fn poseidonConstraints(
    main: [poseidon2_air.N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [poseidon2_air.N_SUMS]QM31,
    previous: [poseidon2_air.N_SUMS]QM31,
    claims: [poseidon2_air.N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_POSEIDON_COMPONENT_CONSTRAINTS]QM31 {
    const air_constraints = poseidon2_air.evaluate(main);
    const interaction_constraints = poseidon2_air.interactionConstraints(
        main,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
    var constraints: [N_POSEIDON_COMPONENT_CONSTRAINTS]QM31 = undefined;
    @memcpy(constraints[0..poseidon2_air.N_CONSTRAINTS], &air_constraints);
    constraints[poseidon2_air.N_CONSTRAINTS] = main[0].sub(is_active);
    const narrow_mode = poseidon2_air.narrowModeConstraints(main);
    @memcpy(
        constraints[poseidon2_air.N_CONSTRAINTS + 1 ..][0..narrow_mode.len],
        &narrow_mode,
    );
    @memcpy(
        constraints[poseidon2_air.N_CONSTRAINTS + N_POSEIDON_SHELL_CONSTRAINTS ..],
        &interaction_constraints,
    );
    return constraints;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}

fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn sampleMain(
    comptime n: usize,
    columns: [][]QM31,
    offset: usize,
) ![n]QM31 {
    if (columns.len < offset + n) return error.InvalidProofShape;
    var result: [n]QM31 = undefined;
    for (&result, columns[offset..][0..n]) |*value, column| {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
    return result;
}

fn sampleInteraction(
    comptime n: usize,
    columns: [][]QM31,
    offset: usize,
    sums: *[n]QM31,
    previous: *[n]QM31,
) !void {
    for (0..n) |index| {
        sums[index] = try sampledSecure(columns, offset + 4 * index, 0);
        previous[index] = try sampledSecure(columns, offset + 4 * index, 1);
    }
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn readMain(comptime n: usize, columns: []const []const M31, row: usize) [n]QM31 {
    var result: [n]QM31 = undefined;
    for (&result, columns) |*value, column| value.* = QM31.fromBase(column[row]);
    return result;
}

fn readInteraction(
    comptime n: usize,
    evaluations: []const []const M31,
    interaction_start: usize,
    row: usize,
    previous_row: usize,
    sums: *[n]QM31,
    previous: *[n]QM31,
) void {
    for (0..n) |index| {
        sums[index] = secureAt(evaluations[interaction_start + 4 * index ..][0..4], row);
        previous[index] = secureAt(
            evaluations[interaction_start + 4 * index ..][0..4],
            previous_row,
        );
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn combineConstraints(powers: []const QM31, constraints: []const QM31) QM31 {
    var result = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        result = result.add(powers[powers.len - 1 - index].mul(constraint));
    }
    return result;
}
