//! Prover/verifier AIR adapter for the canonical unified clock-gap component.

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
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const composition_work_support = @import("composition_work_support.zig");
const interaction = @import("clock_update_interaction.zig");
const logup = @import("logup.zig");
const prepared_evaluation = @import("prepared_evaluation_owner.zig");
const relations_mod = @import("relation_challenges.zig");
const state_chain = @import("../runner/state_chain.zig");

const CirclePointQM31 = circle.CirclePointQM31;

/// Exact number of constraints emitted by the clock-gap component.  Exported
/// so recursive composition derives its instruction schedule from the same
/// production authority as the native verifier.
pub const N_CONSTRAINTS: usize = interaction.N_SUMS + 3;

pub const Evaluation = struct {
    values: [interaction.N_SUMS + 3]QM31,

    pub fn allZero(self: Evaluation) bool {
        for (self.values) |value| if (!value.isZero()) return false;
        return true;
    }
};

pub fn evaluateGeneric(
    comptime S: type,
    main: []const S,
    current: [interaction.N_SUMS]S,
    previous: [interaction.N_SUMS]S,
    is_first: S,
    is_active: S,
    claims: [interaction.N_SUMS]S,
    relations: anytype,
) ![N_CONSTRAINTS]S {
    const row = try interaction.RowFor(S).fromMain(main);
    const pairs = try interaction.pairsGeneric(S, row, relations);
    var result: [N_CONSTRAINTS]S = undefined;
    for (0..interaction.N_SUMS) |index| {
        result[index] = logup.pairConstraintGeneric(
            S,
            current[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    result[interaction.N_SUMS] = row.enabler.mul(S.one().sub(row.enabler));
    result[interaction.N_SUMS + 1] = row.enabler.sub(is_active);
    result[interaction.N_SUMS + 2] = row.enabler.mul(
        row.clock_prev.sub(
            row.clock_prev_low20.add(
                row.clock_prev_high6.mul(S.fromBase(M31.fromU64(
                    @as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS,
                ))),
            ),
        ),
    );
    return result;
}

pub const ClockUpdateComponent = struct {
    log_size: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [interaction.N_SUMS]QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
    ) ClockUpdateComponent {
        return init(
            log_size,
            is_first_col_idx,
            is_active_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    pub fn initProver(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
    ) !ClockUpdateComponent {
        return init(
            log_size,
            is_first_col_idx,
            is_active_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    fn init(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
    ) ClockUpdateComponent {
        return .{
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = claims,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        component.composition_work_profile = compositionWorkProfileErased;
        component.oods_work_profile = oodsWorkProfileErased;
        return component;
    }

    fn oodsWorkProfileErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
        source: *const composition_work_support.ComponentProfile,
    ) anyerror!composition_work_support.OodsComponentProfile {
        _ = allocator;
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return composition_work_support.oodsProfile(
            source,
            self.log_size,
            max_log_degree_bound,
            2 * interaction.N_SUMS,
            true,
        );
    }

    fn compositionWorkProfileErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work_support.ComponentProfile {
        _ = allocator;
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        const Scalar = composition_work_support.Scalar;
        const relations = composition_work_support.Relations.init();
        const main = composition_work_support.values(interaction.N_MAIN_COLUMNS, 0);
        const current = composition_work_support.values(interaction.N_SUMS, 20);
        const previous = composition_work_support.values(interaction.N_SUMS, 40);
        const claims = composition_work_support.values(interaction.N_SUMS, 60);
        const is_first = composition_work_support.values(1, 100)[0];
        const is_active = composition_work_support.values(1, 101)[0];
        var expression: composition_work_support.FieldOperations = undefined;
        try composition_work_support.begin(&expression);
        defer composition_work_support.end();
        _ = try evaluateGeneric(
            Scalar,
            &main,
            current,
            previous,
            is_first,
            is_active,
            claims,
            &relations,
        );
        return composition_work_support.profile(
            .clock_update,
            "riscv-clock-update-evaluate-generic-v1",
            self.maxConstraintLogDegreeBound(),
            self.nConstraints(),
            expression,
            .{},
            &.{
                @as(u64, self.log_size),
                @as(u64, interaction.N_MAIN_COLUMNS),
                @as(u64, interaction.N_SUMS),
            },
        );
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

    pub fn nConstraints(_: *const @This()) usize {
        return N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{ self.log_size, self.log_size });
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, interaction.N_MAIN_COLUMNS);
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const secure = try allocator.alloc(u32, interaction.N_INTERACTION_COLUMNS);
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
        const preprocessed = try currentPointColumns(allocator, 2, point);
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, interaction.N_MAIN_COLUMNS, point);
        errdefer freePointColumns(allocator, main);
        const secure = try currentAndPreviousPointColumns(
            allocator,
            interaction.N_INTERACTION_COLUMNS,
            point,
            logup.prevRowPoint(max_log_degree_bound, point),
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
        return allocator.dupe(usize, &.{ self.is_first_col_idx, self.is_active_col_idx });
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
        const secure = mask.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
            main.len < self.main_col_offset + interaction.N_MAIN_COLUMNS or
            secure.len < self.interaction_col_offset + interaction.N_INTERACTION_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
        for (&sampled, main[self.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current: [interaction.N_SUMS]QM31 = undefined;
        var previous: [interaction.N_SUMS]QM31 = undefined;
        for (0..interaction.N_SUMS) |index| {
            const offset = self.interaction_col_offset + index * 4;
            current[index] = try sampledSecure(secure, offset, 0);
            previous[index] = try sampledSecure(secure, offset, 1);
        }
        const evaluation = try self.evaluateRow(
            &sampled,
            current,
            previous,
            preprocessed[self.is_first_col_idx][0],
            preprocessed[self.is_active_col_idx][0],
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values) |constraint| {
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
        const secure = trace_data.polys.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            main.len < self.main_col_offset + interaction.N_MAIN_COLUMNS or
            secure.len < self.interaction_col_offset + interaction.N_INTERACTION_COLUMNS)
        {
            return error.InvalidProofShape;
        }

        const eval_log_size = std.math.add(u32, self.log_size, 1) catch
            return error.InvalidProofShape;
        if (self.log_size == 0 or eval_log_size >= circle.M31_CIRCLE_LOG_ORDER) {
            return error.InvalidProofShape;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        var owned_count: usize = 0;
        const selector_sources = .{
            preprocessed[self.is_first_col_idx],
            preprocessed[self.is_active_col_idx],
        };
        inline for (selector_sources) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                self.log_size,
                eval_log_size,
            ));
        }
        for (main[self.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                self.log_size,
                eval_log_size,
            ));
        }
        for (secure[self.interaction_col_offset..][0..interaction.N_INTERACTION_COLUMNS]) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                self.log_size,
                eval_log_size,
            ));
        }
        var evaluation_owner = try prepared_evaluation.Owner.init(
            allocator,
            owned_count,
        );
        errdefer evaluation_owner.deinit();
        var evaluations: [PreparedDomainState.SOURCE_COUNT][]const M31 = undefined;
        var source: usize = 0;
        evaluations[source] = try evaluation_owner.value(
            preprocessed[self.is_first_col_idx],
            self.log_size,
            eval_log_size,
            eval_size,
        );
        source += 1;
        evaluations[source] = try evaluation_owner.value(
            preprocessed[self.is_active_col_idx],
            self.log_size,
            eval_log_size,
            eval_size,
        );
        source += 1;
        for (main[self.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |poly| {
            evaluations[source] = try evaluation_owner.value(
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
            );
            source += 1;
        }
        for (secure[self.interaction_col_offset..][0..interaction.N_INTERACTION_COLUMNS]) |poly| {
            evaluations[source] = try evaluation_owner.value(
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
            );
            source += 1;
        }

        std.debug.assert(source == evaluations.len);
        try evaluation_owner.finish(eval_domain);

        const denominator_inv = try quotientDenominators(
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try preparedDomainResources(eval_size, owned_count);

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
            .evaluation_owner = evaluation_owner,
            .denominator_inv = denominator_inv,
            .column_accumulator = accumulators[0],
            .eval_log_size = eval_log_size,
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
        const evaluations = &state.evaluations;
        const column_accumulator = &state.column_accumulator;
        const main_start: usize = 2;
        const secure_start = main_start + interaction.N_MAIN_COLUMNS;
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..state.eval_size) |row| {
            if ((row & (PreparedDomainState.CANCELLATION_POLL_ROWS - 1)) == 0 and
                task_context.isCancelled())
            {
                // Cancellation is not a competing failure cause. The graph
                // discards this task's partially written accumulator after it
                // reports the original sibling failure.
                return;
            }
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                state.eval_log_size,
            );
            var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
            for (&sampled, evaluations[main_start..][0..interaction.N_MAIN_COLUMNS]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            var current: [interaction.N_SUMS]QM31 = undefined;
            var previous: [interaction.N_SUMS]QM31 = undefined;
            for (0..interaction.N_SUMS) |index| {
                const offset = secure_start + index * 4;
                current[index] = secureAt(evaluations[offset..][0..4], row);
                previous[index] = secureAt(evaluations[offset..][0..4], previous_row);
            }
            const evaluation = try self.evaluateRow(
                &sampled,
                current,
                previous,
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = column_accumulator.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
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
        current: [interaction.N_SUMS]QM31,
        previous: [interaction.N_SUMS]QM31,
        is_first: QM31,
        is_active: QM31,
    ) !Evaluation {
        return .{ .values = try evaluateGeneric(
            QM31,
            main,
            current,
            previous,
            is_first,
            is_active,
            self.claims,
            self.relations,
        ) };
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;
    const SOURCE_COUNT: usize =
        2 + interaction.N_MAIN_COLUMNS + interaction.N_INTERACTION_COLUMNS;
    const DENOMINATOR_COUNT: usize = 2;

    comptime {
        if (CANCELLATION_POLL_ROWS == 0 or
            CANCELLATION_POLL_ROWS > 4096 or
            !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
        {
            @compileError("prepared domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
        }
    }

    allocator: std.mem.Allocator,
    component: *const ClockUpdateComponent,
    evaluations: [SOURCE_COUNT][]const M31,
    evaluation_owner: prepared_evaluation.Owner,
    denominator_inv: [DENOMINATOR_COUNT]M31,
    column_accumulator: prover_air_accumulation.ColumnAccumulator,
    eval_log_size: u32,
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
        self.evaluation_owner.deinit();
        allocator.destroy(self);
    }
};

fn preparedDomainResources(
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
    var resident_bytes = std.math.add(
        usize,
        @sizeOf(PreparedDomainState),
        try prepared_evaluation.residentBytes(owned_count, eval_size),
    ) catch return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(
        usize,
        resident_bytes,
        @sizeOf(prover_air_accumulation.ColumnAccumulator),
    ) catch return error.ResourceReservationOverflow;
    return .{
        .final_output_bytes = final_output_bytes,
        // Preparation records remain live until the complete graph drains, so
        // they are resident rather than wave-reusable exclusive scratch.
        .shared_resident_bytes = resident_bytes,
        .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    };
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
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
) ![PreparedDomainState.DENOMINATOR_COUNT]M31 {
    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    if (extension_bits != 1) return error.InvalidProofShape;
    var result: [PreparedDomainState.DENOMINATOR_COUNT]M31 = undefined;
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
