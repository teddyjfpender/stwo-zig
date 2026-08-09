//! Prover/verifier AIR adapter for exact opcode-family lookup placement.
//!
//! Direct instruction constraints and the main-column declaration remain owned
//! by the semantic component. This adapter borrows those already-opened columns
//! by global offset and owns only its interaction columns. Declaring the main
//! columns here too would duplicate the main tree because core AIR orchestration
//! only aliases preprocessed columns. Every declaration-order relation batch is
//! reconstructed through `opcode_entries.fromMain`.

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
const prepared_parallel = @import("../prepared_parallel.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");
const runtime_program = @import("../extract/runtime_program.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const PARALLEL_DOMAIN_ROWS: usize = 2 * 4096;

pub const PreparedParallelTelemetrySnapshot = prepared_parallel.TelemetrySnapshot;
var prepared_parallel_telemetry: prepared_parallel.Telemetry = .{};

pub fn preparedParallelTelemetrySnapshot() PreparedParallelTelemetrySnapshot {
    return prepared_parallel_telemetry.snapshot();
}

pub const Evaluation = struct {
    values: [entry.MAX_BATCHES]QM31 = .{QM31.zero()} ** entry.MAX_BATCHES,
    len: usize = 0,

    pub fn allZero(self: Evaluation) bool {
        for (self.values[0..self.len]) |value| {
            if (!value.isZero()) return false;
        }
        return true;
    }
};

pub const OpcodeLookupComponent = struct {
    family: trace.OpcodeFamily,
    log_size: u32,
    is_first_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [entry.MAX_BATCHES]QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    pub fn initProver(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    fn init(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        const n_batches = opcode_entries.batchCount(family);
        if (claims.len != n_batches) return error.InvalidTraceShape;
        var stored_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        @memcpy(stored_claims[0..n_batches], claims);
        return .{
            .family = family,
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = stored_claims,
        };
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.backend_composition_capability = .{
            .lookup_polynomial_v1 = .{
                .program_id = (@as(u64, 2) << 32) | @intFromEnum(self.family),
                .trace_log_size = self.log_size,
                .selector_tree_index = 0,
                .selector_column = self.is_first_col_idx,
                .main_tree_index = 1,
                .first_main_column = self.main_col_offset,
                .main_column_count = trace.nColumnsForFamily(self.family),
                .interaction_tree_index = 2,
                .first_interaction_column = self.interaction_col_offset,
                .interaction_column_count = opcode_entries.interactionColumnCount(self.family),
                .export_program = exportRuntimeProgram,
                .export_parameters = exportRuntimeParameters,
            },
        };
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

    fn exportRuntimeProgram(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !prover_component.OwnedLookupPolynomialProgram {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        return runtime_program.buildLookups(allocator, self.family);
    }

    fn exportRuntimeParameters(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]QM31 {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        var sampled = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
        const lookups = try opcode_entries.fromMain(
            self.family,
            sampled[0..trace.nColumnsForFamily(self.family)],
        );
        var parameters = std.ArrayList(QM31).empty;
        errdefer parameters.deinit(allocator);
        for (lookups.entries[0..lookups.len]) |lookup|
            try appendRelationParameters(
                &parameters,
                allocator,
                self.relations,
                lookup.domain,
            );
        try parameters.appendSlice(allocator, self.claims[0..self.nConstraints()]);
        return parameters.toOwnedSlice(allocator);
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return opcode_entries.batchCount(self.family);
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{self.log_size});
        errdefer allocator.free(preprocessed);
        // The semantic component owns these shared main columns. Main-tree
        // bounds are concatenated by core orchestration, so aliases must not be
        // declared a second time.
        const main = try allocator.alloc(u32, 0);
        errdefer allocator.free(main);
        const secure = try allocator.alloc(u32, opcode_entries.interactionColumnCount(self.family));
        errdefer allocator.free(secure);
        @memset(secure, self.log_size);
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
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(allocator, 1, point);
        errdefer freePointColumns(allocator, preprocessed);
        // The semantic owner already requests the shared main columns at the
        // current point. Returning them here would append duplicate masks.
        const main = try currentPointColumns(allocator, 0, point);
        errdefer freePointColumns(allocator, main);
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const secure = try currentAndPreviousPointColumns(
            allocator,
            opcode_entries.interactionColumnCount(self.family),
            point,
            previous_point,
        );
        errdefer freePointColumns(allocator, secure);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{self.is_first_col_idx});
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
        const main = mask.items[1];
        const secure = mask.items[2];
        const n_main = trace.nColumnsForFamily(self.family);
        const n_interaction = opcode_entries.interactionColumnCount(self.family);
        if (preprocessed.len <= self.is_first_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            main.len < self.main_col_offset + n_main or
            secure.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;

        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], main[self.main_col_offset..][0..n_main]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        for (0..self.nConstraints()) |batch| {
            current[batch] = try sampledSecure(secure, self.interaction_col_offset + 4 * batch, 0);
            previous[batch] = try sampledSecure(secure, self.interaction_col_offset + 4 * batch, 1);
        }
        const evaluation = try self.evaluateRow(
            sampled[0..n_main],
            current[0..self.nConstraints()],
            previous[0..self.nConstraints()],
            preprocessed[self.is_first_col_idx][0],
        );
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        for (evaluation.values[0..evaluation.len]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
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

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) !void {
        _ = pool;
        return self.evaluateConstraintQuotientsOnDomain(trace_data, accumulator);
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
        if (self.log_size == 0 or
            eval_log_size > circle.M31_CIRCLE_LOG_ORDER - 1 or
            eval_log_size >= @bitSizeOf(usize))
        {
            return error.InvalidProofShape;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_main = trace.nColumnsForFamily(self.family);
        const n_interaction = opcode_entries.interactionColumnCount(self.family);
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const secure = trace_data.polys.items[2];
        const main_end = std.math.add(usize, self.main_col_offset, n_main) catch
            return error.InvalidProofShape;
        const interaction_end = std.math.add(
            usize,
            self.interaction_col_offset,
            n_interaction,
        ) catch return error.InvalidProofShape;
        if (preprocessed.len <= self.is_first_col_idx or
            main.len < main_end or secure.len < interaction_end)
            return error.InvalidProofShape;

        var n_sources = std.math.add(usize, 1, n_main) catch
            return error.InvalidProofShape;
        n_sources = std.math.add(usize, n_sources, n_interaction) catch
            return error.InvalidProofShape;
        if (n_sources > PreparedDomainState.MAX_SOURCES) return error.InvalidProofShape;
        var evaluations = [_][]const M31{&.{}} ** PreparedDomainState.MAX_SOURCES;
        var source: usize = 0;
        evaluations[source] = try committedValues(preprocessed[self.is_first_col_idx], eval_log_size);
        source += 1;
        for (main[self.main_col_offset..main_end]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }
        for (secure[self.interaction_col_offset..interaction_end]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }

        std.debug.assert(source == n_sources);

        const denominator_inv = try quotientDenominators(
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try preparedDomainResources(eval_size);
        const state = try allocator.create(PreparedDomainState);
        errdefer allocator.destroy(state);
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }},
        );
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
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
        main: []const QM31,
        current: []const QM31,
        previous: []const QM31,
        is_first: QM31,
    ) !Evaluation {
        const n_batches = self.nConstraints();
        if (main.len != trace.nColumnsForFamily(self.family) or
            current.len != n_batches or previous.len != n_batches)
            return error.InvalidTraceShape;
        const entries = try opcode_entries.fromMain(self.family, main);
        if (entries.batchCount() != n_batches) return error.InvalidBatchCount;
        var result = Evaluation{ .len = n_batches };
        for (0..n_batches) |batch| {
            result.values[batch] = logup.pairConstraint(
                current[batch],
                previous[batch],
                is_first,
                self.claims[batch],
                try entries.pair(batch, self.relations),
            );
        }
        return result;
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;
    const MAX_SOURCES: usize = 1 + trace.MAX_FAMILY_COLUMNS + opcode_interaction.MAX_COLUMNS;

    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
    evaluations: [MAX_SOURCES][]const M31,
    source_count: usize,
    n_main: usize,
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
            @compileError("opcode prepared-domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
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
        const batch_count = component.nConstraints();
        const column_accumulator = &self.accumulators[0];
        const powers = column_accumulator.random_coeff_powers;
        const evaluations = self.evaluations[0..self.source_count];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(component.log_size);
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
                component.log_size,
                self.eval_log_size,
            );
            var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
            for (sampled[0..self.n_main], evaluations[1..][0..self.n_main]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
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
            for (constraints.values[0..constraints.len], 0..) |constraint, index| {
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
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

fn appendRelationParameters(
    parameters: *std.ArrayList(QM31),
    allocator: std.mem.Allocator,
    relations: *const relations_mod.Relations,
    domain: entry.Domain,
) !void {
    switch (domain) {
        .registers_state => try appendRelation(parameters, allocator, relations.registers_state),
        .memory_access => try appendRelation(parameters, allocator, relations.memory_access),
        .program_access => try appendRelation(parameters, allocator, relations.program_access),
        .merkle => try appendRelation(parameters, allocator, relations.merkle),
        .poseidon2 => try appendRelation(parameters, allocator, relations.poseidon2),
        .poseidon2_io => try appendRelation(parameters, allocator, relations.poseidon2_io),
        .bitwise => try appendRelation(parameters, allocator, relations.bitwise),
        .range_check_20 => try appendRelation(parameters, allocator, relations.range_check_20),
        .range_check_8_11 => try appendRelation(parameters, allocator, relations.range_check_8_11),
        .range_check_8_8_4 => try appendRelation(parameters, allocator, relations.range_check_8_8_4),
        .range_check_8_8 => try appendRelation(parameters, allocator, relations.range_check_8_8),
        .range_check_m31 => try appendRelation(parameters, allocator, relations.range_check_m31),
    }
}

fn appendRelation(
    parameters: *std.ArrayList(QM31),
    allocator: std.mem.Allocator,
    relation: anytype,
) !void {
    try parameters.append(allocator, relation.z);
    try parameters.appendSlice(allocator, &relation.alpha_powers);
}

fn committedValues(poly: prover_component.Poly, expected_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != expected_log_size) return error.InvalidProofShape;
    return poly.values;
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidProofShape;
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
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

test "opcode prepared domain: resource geometry and cancellation cadence are bounded" {
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
