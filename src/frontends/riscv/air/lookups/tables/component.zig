//! Generic prover/verifier AIR adapter for exact preprocessed lookup tables.

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
const work_pool = @import("stwo_prover_engine").work_pool;
const prepared_parallel = @import("../../prepared_parallel.zig");
const logup = @import("../../logup.zig");
const relations_mod = @import("../../relation_challenges.zig");
const interaction = @import("interaction.zig");
const schema = @import("schema.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const PARALLEL_DOMAIN_ROWS: usize = 2 * 4096;

pub const PreparedParallelTelemetrySnapshot = prepared_parallel.TelemetrySnapshot;
var prepared_parallel_telemetry: prepared_parallel.Telemetry = .{};

pub fn preparedParallelTelemetrySnapshot() PreparedParallelTelemetrySnapshot {
    return prepared_parallel_telemetry.snapshot();
}

pub const ConstructionMetadata = struct {
    kind: schema.Kind,
    log_size: u32,
    tuple_columns: usize,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    previous_masks: usize,
    constraints: usize,

    pub fn forKind(kind: schema.Kind) ConstructionMetadata {
        return .{
            .kind = kind,
            .log_size = schema.logSize(kind),
            .tuple_columns = schema.arity(kind),
            .preprocessed_columns = 1 + schema.arity(kind),
            .main_columns = 1,
            .interaction_columns = interaction.N_COLUMNS,
            .previous_masks = interaction.N_COLUMNS,
            .constraints = 1,
        };
    }
};

pub const LookupTableComponent = struct {
    kind: schema.Kind,
    is_first_col_idx: usize,
    tuple_col_indices: [schema.MAX_ARITY]usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claim: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !LookupTableComponent {
        return init(
            kind,
            is_first_col_idx,
            tuple_col_indices,
            main_col_offset,
            interaction_col_offset,
            relations,
            claim,
        );
    }

    pub fn initProver(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !LookupTableComponent {
        return init(
            kind,
            is_first_col_idx,
            tuple_col_indices,
            main_col_offset,
            interaction_col_offset,
            relations,
            claim,
        );
    }

    fn init(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !LookupTableComponent {
        if (tuple_col_indices.len != schema.arity(kind)) return error.InvalidTraceShape;
        var stored_indices = [_]usize{0} ** schema.MAX_ARITY;
        for (tuple_col_indices, 0..) |column, index| {
            if (column == is_first_col_idx) return error.InvalidTraceShape;
            for (tuple_col_indices[0..index]) |prior| {
                if (column == prior) return error.InvalidTraceShape;
            }
            stored_indices[index] = column;
        }
        return .{
            .kind = kind,
            .is_first_col_idx = is_first_col_idx,
            .tuple_col_indices = stored_indices,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claim = claim,
        };
    }

    pub fn metadata(self: *const @This()) ConstructionMetadata {
        return ConstructionMetadata.forKind(self.kind);
    }

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

    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return schema.logSize(self.kind) + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const log_size = schema.logSize(self.kind);
        const n_preprocessed = 1 + schema.arity(self.kind);
        const preprocessed = try allocator.alloc(u32, n_preprocessed);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, log_size);
        const main = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(main);
        const secure = try allocator.alloc(u32, interaction.N_COLUMNS);
        errdefer allocator.free(secure);
        @memset(secure, log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, secure }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < schema.logSize(self.kind)) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(
            allocator,
            1 + schema.arity(self.kind),
            point,
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, 1, point);
        errdefer freePointColumns(allocator, main);
        // The PCS folds a log-(k+1) commitment at a point derived from the
        // maximal composition domain. Shifting the request by that maximal
        // step becomes exactly one trace-row shift after folding.
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const secure = try allocator.alloc([]CirclePointQM31, interaction.N_COLUMNS);
        var initialized_secure: usize = 0;
        errdefer {
            for (secure[0..initialized_secure]) |column| allocator.free(column);
            allocator.free(secure);
        }
        for (secure) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous_point });
            initialized_secure += 1;
        }
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const result = try allocator.alloc(usize, 1 + schema.arity(self.kind));
        result[0] = self.is_first_col_idx;
        @memcpy(result[1..], self.tuple_col_indices[0..schema.arity(self.kind)]);
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        const log_size = schema.logSize(self.kind);
        if (max_log_degree_bound < log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            main.len <= self.main_col_offset or
            main[self.main_col_offset].len < 1 or
            secure.len < self.interaction_col_offset + interaction.N_COLUMNS)
            return error.InvalidProofShape;

        var tuple: [schema.MAX_ARITY]QM31 = undefined;
        for (self.tuple_col_indices[0..schema.arity(self.kind)], tuple[0..schema.arity(self.kind)]) |column_index, *value| {
            if (preprocessed.len <= column_index or preprocessed[column_index].len < 1)
                return error.InvalidProofShape;
            value.* = preprocessed[column_index][0];
        }
        if (preprocessed[self.is_first_col_idx].len < 1) return error.InvalidProofShape;
        const current = try sampledSecure(secure, self.interaction_col_offset, 0);
        const previous = try sampledSecure(secure, self.interaction_col_offset, 1);
        const constraint = try self.evaluateRow(
            tuple[0..schema.arity(self.kind)],
            main[self.main_col_offset][0],
            current,
            previous,
            preprocessed[self.is_first_col_idx][0],
        );
        const fold = max_log_degree_bound - log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        accumulator.accumulate(constraint.mul(denominator_inv));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try self.prepareDomainEvaluator(
            accumulator.allocator,
            trace,
            accumulator,
        );
        defer prepared.deinit();

        var cancellation = prover_task_graph.CancellationToken{};
        var task_context = serialTaskContext(prepared.context, &cancellation);
        try prepared.run(&task_context);
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) !void {
        _ = pool;
        return self.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const log_size = schema.logSize(self.kind);
        const eval_log_size = std.math.add(u32, log_size, 1) catch
            return error.InvalidProofShape;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_tuple = schema.arity(self.kind);
        const n_sources = 1 + n_tuple + 1 + interaction.N_COLUMNS;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const secure = trace.polys.items[2];
        const interaction_end = std.math.add(
            usize,
            self.interaction_col_offset,
            interaction.N_COLUMNS,
        ) catch return error.InvalidProofShape;
        if (preprocessed.len <= self.is_first_col_idx or
            main.len <= self.main_col_offset or
            secure.len < interaction_end)
            return error.InvalidProofShape;

        if (n_sources > PreparedDomainState.MAX_SOURCES) return error.InvalidProofShape;
        var evaluations = [_][]const M31{&.{}} ** PreparedDomainState.MAX_SOURCES;
        var source: usize = 0;
        evaluations[source] = try committedValues(
            preprocessed[self.is_first_col_idx],
            eval_log_size,
        );
        source += 1;
        for (self.tuple_col_indices[0..n_tuple]) |column_index| {
            if (preprocessed.len <= column_index) return error.InvalidProofShape;
            evaluations[source] = try committedValues(
                preprocessed[column_index],
                eval_log_size,
            );
            source += 1;
        }
        evaluations[source] = try committedValues(main[self.main_col_offset], eval_log_size);
        source += 1;
        for (0..interaction.N_COLUMNS) |coordinate| {
            evaluations[source] = try committedValues(
                secure[self.interaction_col_offset + coordinate],
                eval_log_size,
            );
            source += 1;
        }
        std.debug.assert(source == n_sources);

        const denominator_inv = try quotientDenominators(
            log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try preparedDomainResources(eval_size);
        const state = try allocator.create(PreparedDomainState);
        errdefer allocator.destroy(state);
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .source_count = n_sources,
            .n_tuple = n_tuple,
            .main_index = 1 + n_tuple,
            .interaction_start = 2 + n_tuple,
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
            .denominator_inv = denominator_inv,
            .accumulators = accumulators,
            .direct_store = accumulators[0].next_fresh_index == 0,
        };
        return .{
            .context = state,
            .vtable = &PreparedDomainState.vtable,
            .task_class = if (eval_size >= PARALLEL_DOMAIN_ROWS)
                .pool_exclusive
            else
                .leaf,
            .resources = resources,
        };
    }

    pub fn evaluateRow(
        self: *const @This(),
        tuple: []const QM31,
        signed_multiplicity: QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
    ) !QM31 {
        return interaction.evaluate(
            self.kind,
            tuple,
            signed_multiplicity,
            current,
            previous,
            is_first,
            self.claim,
            self.relations,
        );
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;
    const MAX_SOURCES: usize = 2 + schema.MAX_ARITY + interaction.N_COLUMNS;

    allocator: std.mem.Allocator,
    component: *const LookupTableComponent,
    evaluations: [MAX_SOURCES][]const M31,
    source_count: usize,
    n_tuple: usize,
    main_index: usize,
    interaction_start: usize,
    eval_log_size: u32,
    eval_size: usize,
    denominator_inv: [2]M31,
    accumulators: []prover_air_accumulation.ColumnAccumulator,
    direct_store: bool,
    failure_boundary: prepared_parallel.FailureBoundary = .{},
    range_workers: [work_pool.MAX_WORKERS]PreparedRangeWorker = undefined,

    const vtable = prepared_domain.VTable{
        .run = runErased,
        .deinit = deinitErased,
    };

    comptime {
        if (CANCELLATION_POLL_ROWS == 0 or
            CANCELLATION_POLL_ROWS > 4096 or
            !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
        {
            @compileError("table prepared-domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
        }
    }

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

    fn evaluateRange(
        self: *@This(),
        parent_cancellation: *const prover_task_graph.CancellationToken,
        range_index: usize,
        row_start: usize,
        row_end: usize,
    ) !bool {
        const component = self.component;
        const log_size = schema.logSize(component.kind);
        const evaluations = self.evaluations[0..self.source_count];
        const column_accumulator = &self.accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(log_size);
        for (row_start..row_end) |row| {
            if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
                (parent_cancellation.isCancelled() or
                    self.failure_boundary.shouldCancel(range_index)))
            {
                // Cancellation is not a competing failure cause. The task
                // graph retains the sibling error that requested it.
                return false;
            }
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                log_size,
                self.eval_log_size,
            );
            var tuple: [schema.MAX_ARITY]QM31 = undefined;
            for (tuple[0..self.n_tuple], evaluations[1..][0..self.n_tuple]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            const constraint = try component.evaluateRow(
                tuple[0..self.n_tuple],
                QM31.fromBase(evaluations[self.main_index][row]),
                secureAt(
                    evaluations[self.interaction_start..][0..interaction.N_COLUMNS],
                    row,
                ),
                secureAt(
                    evaluations[self.interaction_start..][0..interaction.N_COLUMNS],
                    previous_row,
                ),
                QM31.fromBase(evaluations[0][row]),
            );
            const contribution = column_accumulator.random_coeff_powers[0]
                .mul(constraint)
                .mulM31(self.denominator_inv[row >> denominator_shift]);
            const output = column_accumulator.col;
            if (self.direct_store) {
                output.set(row, contribution);
            } else {
                output.set(row, output.at(row).add(contribution));
            }
        }
        return true;
    }

    fn finishOutput(self: *@This()) void {
        self.accumulators[0].next_fresh_index = if (self.direct_store) self.eval_size else null;
    }

    fn deinitErased(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        allocator.free(self.accumulators);
        allocator.destroy(self);
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

fn committedValues(poly: prover_component.Poly, expected_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != expected_log_size) return error.InvalidProofShape;
    return poly.values;
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

fn preparedDomainResources(eval_size: usize) !prover_task_graph.ResourceReservation {
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
    const shared_resident_bytes = std.math.add(
        usize,
        @sizeOf(PreparedDomainState),
        @sizeOf(prover_air_accumulation.ColumnAccumulator),
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

fn currentPointColumns(
    allocator: std.mem.Allocator,
    n_columns: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, n_columns);
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

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [interaction.N_COLUMNS]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns.len <= offset + index or columns[offset + index].len <= point)
            return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

test "lookup table prepared domain: resource geometry and cancellation cadence are bounded" {
    const secure_element_bytes = qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);
    const resources = try preparedDomainResources(17);
    try std.testing.expectEqual(17 * secure_element_bytes, resources.final_output_bytes);
    try std.testing.expectEqual(
        @sizeOf(PreparedDomainState) + @sizeOf(prover_air_accumulation.ColumnAccumulator),
        resources.shared_resident_bytes,
    );
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        resources.worker_stack_bytes,
    );
    try std.testing.expect(PreparedDomainState.CANCELLATION_POLL_ROWS <= 4096);
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        preparedDomainResources(std.math.maxInt(usize) / secure_element_bytes),
    );
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        preparedDomainResources(std.math.maxInt(usize)),
    );
}
