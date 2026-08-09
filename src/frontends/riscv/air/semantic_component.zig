//! Semantic-only AIR owner for one committed opcode-family trace.
//!
//! This component owns the family's raw main columns, aliases the global
//! `IsActive` selector, and declares no interaction columns. Relation placement
//! belongs to the lookup adapters; keeping it out of this component prevents
//! semantic and LogUp ownership from becoming coupled again.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const runtime_program = @import("extract/runtime_program.zig");
const semantic_eval = @import("semantic_eval.zig");
const trace = @import("../runner/trace.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const SemanticComponent = struct {
    family: trace.OpcodeFamily,
    log_size: u32,
    is_active_col_idx: usize,
    main_col_offset: usize,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn init(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_active_col_idx: usize,
        main_col_offset: usize,
    ) !SemanticComponent {
        if (!semantic_eval.isTraceCompatible(family)) {
            return error.IncompatibleCommittedTrace;
        }
        return .{
            .family = family,
            .log_size = log_size,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        component.backend_composition_capability = .{
            .base_polynomial_v1 = .{
                .program_id = (@as(u64, 1) << 32) | @intFromEnum(self.family),
                .trace_log_size = self.log_size,
                .selector_tree_index = 0,
                .selector_column = self.is_active_col_idx,
                .main_tree_index = 1,
                .first_main_column = self.main_col_offset,
                .main_column_count = self.mainColumnCount(),
                .export_program = exportRuntimeProgram,
            },
        };
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
    ) !prover_component.OwnedBasePolynomialProgram {
        const self: *const SemanticComponent = @ptrCast(@alignCast(ctx));
        return runtime_program.build(allocator, self.family);
    }

    pub fn mainColumnCount(self: *const @This()) usize {
        return semantic_eval.mainColumnCount(self.family);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return semantic_eval.constraintCount(self.family);
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return semantic_eval.constraintLogDegreeBound(self.family, self.log_size);
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{self.log_size});
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, self.mainColumnCount());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(u32, 0);
        errdefer allocator.free(interaction);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
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
        const main = try currentPointColumns(allocator, self.mainColumnCount(), point);
        errdefer freePointColumns(allocator, main);
        const interaction = try currentPointColumns(allocator, 0, point);
        errdefer freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{self.is_active_col_idx});
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3) {
            return error.InvalidProofShape;
        }
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const n_main = self.mainColumnCount();
        if (preprocessed.len <= self.is_active_col_idx or
            preprocessed[self.is_active_col_idx].len < 1 or
            main.len < self.main_col_offset + n_main)
        {
            return error.InvalidProofShape;
        }

        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], main[self.main_col_offset..][0..n_main]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        const evaluation = try self.evaluateRow(
            sampled[0..n_main],
            preprocessed[self.is_active_col_idx][0],
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
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
        var task_context = prover_task_graph.TaskContext{
            .user_context = prepared.context,
            .cancellation = &cancellation,
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = 0,
                .shard_or_chunk_index = 0,
            },
            .worker_budget = prover_work_pool.WorkerBudget.serial(),
            .task_class = .leaf,
            .exclusive_lease = null,
            .child_wait_group = null,
        };
        try prepared.run(&task_context);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const n_main = self.mainColumnCount();
        const main_end = std.math.add(usize, self.main_col_offset, n_main) catch
            return error.InvalidProofShape;
        if (preprocessed.len <= self.is_active_col_idx or main.len < main_end) {
            return error.InvalidProofShape;
        }

        const eval_log_size = try quotientEvaluationLogSize(self.log_size);
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const source_count = std.math.add(usize, 1, n_main) catch
            return error.ResourceReservationOverflow;
        const evaluations = try allocator.alloc([]const M31, source_count);
        errdefer allocator.free(evaluations);

        var owned_count: usize = 0;
        try validateEvaluationSource(
            preprocessed[self.is_active_col_idx],
            self.log_size,
            eval_log_size,
        );
        if (preprocessed[self.is_active_col_idx].log_size != eval_log_size) {
            owned_count = std.math.add(usize, owned_count, 1) catch
                return error.ResourceReservationOverflow;
        }
        for (main[self.main_col_offset..main_end]) |poly| {
            try validateEvaluationSource(poly, self.log_size, eval_log_size);
            if (poly.log_size != eval_log_size) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }

        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var owned_initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..owned_initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        evaluations[0] = try prepareEvaluationValues(
            allocator,
            preprocessed[self.is_active_col_idx],
            eval_log_size,
            eval_size,
            owned_buffers,
            &owned_initialized,
        );
        for (main[self.main_col_offset..main_end], evaluations[1..]) |poly, *values| {
            values.* = try prepareEvaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
        }
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

        const denominator_inv = try quotientDenominators(
            allocator,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        errdefer allocator.free(denominator_inv);
        const resources = try preparedDomainResources(
            eval_size,
            source_count,
            owned_count,
            denominator_inv.len,
        );
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
            .owned_buffers = owned_buffers,
            .denominator_inv = denominator_inv,
            .accumulators = accumulators,
            .eval_size = eval_size,
        };
        return .{
            .context = state,
            .vtable = &PreparedDomainState.vtable,
            .task_class = .leaf,
            .resources = resources,
        };
    }

    fn runPreparedDomain(
        self: *const @This(),
        state: *PreparedDomainState,
        task_context: *prover_task_graph.TaskContext,
    ) !void {
        const n_main = self.mainColumnCount();
        const evaluations = state.evaluations;
        const column_accumulator = &state.accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const powers = column_accumulator.random_coeff_powers;
        for (0..state.eval_size) |row| {
            if ((row & (PreparedDomainState.CANCELLATION_POLL_ROWS - 1)) == 0 and
                task_context.isCancelled())
            {
                // Cancellation is not a competing failure cause. The graph
                // discards partial component output with the failed stage.
                return;
            }
            var sampled: [trace.MAX_FAMILY_COLUMNS]semantic_eval.BaseScalar = undefined;
            for (sampled[0..n_main], evaluations[1..]) |*value, column| {
                value.* = semantic_eval.BaseScalar.fromBase(column[row]);
            }
            const evaluation = try semantic_eval.BaseEval.evaluate(
                self.family,
                sampled[0..n_main],
                semantic_eval.BaseScalar.fromBase(evaluations[0][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values[0..evaluation.len], 0..) |constraint, index| {
                folded = folded.add(
                    powers[powers.len - 1 - index].mulM31(constraint.value),
                );
            }
            column_accumulator.accumulate(
                row,
                folded.mulM31(state.denominator_inv[row >> denominator_shift]),
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        main: []const QM31,
        is_active: QM31,
    ) !semantic_eval.Evaluation {
        if (!semantic_eval.isTraceCompatible(self.family)) {
            return error.IncompatibleCommittedTrace;
        }
        return semantic_eval.evaluate(self.family, main, is_active);
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;
    comptime {
        if (CANCELLATION_POLL_ROWS == 0 or
            CANCELLATION_POLL_ROWS > 4096 or
            (CANCELLATION_POLL_ROWS & (CANCELLATION_POLL_ROWS - 1)) != 0)
        {
            @compileError("semantic cancellation polling must be power-of-two and at most 4096 rows");
        }
    }

    allocator: std.mem.Allocator,
    component: *const SemanticComponent,
    evaluations: [][]const M31,
    owned_buffers: [][]M31,
    denominator_inv: []M31,
    accumulators: []prover_air_accumulation.ColumnAccumulator,
    eval_size: usize,

    const vtable = prepared_domain.VTable{
        .run = runErased,
        .deinit = deinitErased,
    };

    fn runErased(
        context: *anyopaque,
        task_context: *prover_task_graph.TaskContext,
    ) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context));
        try self.component.runPreparedDomain(self, task_context);
    }

    fn deinitErased(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        allocator.free(self.accumulators);
        allocator.free(self.denominator_inv);
        for (self.owned_buffers) |values| allocator.free(values);
        allocator.free(self.owned_buffers);
        allocator.free(self.evaluations);
        allocator.destroy(self);
    }
};

fn quotientEvaluationLogSize(log_size: u32) !u32 {
    if (log_size == 0) return error.InvalidProofShape;
    const eval_log_size = std.math.add(u32, log_size, 1) catch
        return error.InvalidProofShape;
    if (eval_log_size >= circle.M31_CIRCLE_LOG_ORDER) {
        return error.InvalidProofShape;
    }
    return eval_log_size;
}

fn preparedDomainResources(
    eval_size: usize,
    source_count: usize,
    owned_count: usize,
    denominator_count: usize,
) !prover_task_graph.ResourceReservation {
    const final_output_bytes = std.math.mul(
        usize,
        eval_size,
        @sizeOf(QM31),
    ) catch return error.ResourceReservationOverflow;
    const source_bytes = std.math.mul(
        usize,
        source_count,
        @sizeOf([]const M31),
    ) catch return error.ResourceReservationOverflow;
    const owned_view_bytes = std.math.mul(
        usize,
        owned_count,
        @sizeOf([]M31),
    ) catch return error.ResourceReservationOverflow;
    const owned_value_count = std.math.mul(
        usize,
        owned_count,
        eval_size,
    ) catch return error.ResourceReservationOverflow;
    const owned_value_bytes = std.math.mul(
        usize,
        owned_value_count,
        @sizeOf(M31),
    ) catch return error.ResourceReservationOverflow;
    const denominator_bytes = std.math.mul(
        usize,
        denominator_count,
        @sizeOf(M31),
    ) catch return error.ResourceReservationOverflow;
    var resident_bytes = std.math.add(
        usize,
        @sizeOf(PreparedDomainState),
        source_bytes,
    ) catch return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(usize, resident_bytes, owned_view_bytes) catch
        return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(usize, resident_bytes, owned_value_bytes) catch
        return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(usize, resident_bytes, denominator_bytes) catch
        return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(
        usize,
        resident_bytes,
        @sizeOf(prover_air_accumulation.ColumnAccumulator),
    ) catch return error.ResourceReservationOverflow;
    return .{
        .final_output_bytes = final_output_bytes,
        .shared_resident_bytes = resident_bytes,
        .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    };
}

fn validateEvaluationSource(
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
) !void {
    try poly.validate();
    if (poly.log_size == eval_log_size) return;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
}

fn prepareEvaluationValues(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    eval_log_size: u32,
    eval_size: usize,
    owned_buffers: [][]M31,
    owned_initialized: *usize,
) ![]const M31 {
    if (poly.log_size == eval_log_size) return poly.values;
    const coefficients = poly.coefficients.?;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    owned_buffers[owned_initialized.*] = values;
    owned_initialized.* += 1;
    return values;
}

fn quotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![]M31 {
    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    const result = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
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

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
