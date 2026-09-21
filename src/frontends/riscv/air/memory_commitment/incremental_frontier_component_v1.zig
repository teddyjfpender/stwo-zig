//! Stwo prover/verifier adapter for the shared incremental-memory frontier.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_task_graph = prover_engine.task_graph;
const prover_poly = prover_engine.poly.circle.poly;
const prover_twiddles = prover_engine.poly.twiddles;
const frontier = @import("incremental_frontier_v1.zig");
const logup = @import("../logup.zig");
const prepared_support = @import("hash_component_prepared_support.zig");
const relations_mod = @import("../relation_challenges.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const prepared_source_count = 2 + frontier.N_MAIN_COLUMNS +
    frontier.N_INTERACTION_COLUMNS;

pub const Placement = struct {
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,

    pub fn validate(self: Placement) !void {
        if (self.is_first_col_idx == self.is_active_col_idx)
            return error.InvalidIncrementalFrontierPlacement;
        _ = std.math.add(
            usize,
            self.main_col_offset,
            frontier.N_MAIN_COLUMNS,
        ) catch return error.InvalidIncrementalFrontierPlacement;
        _ = std.math.add(
            usize,
            self.interaction_col_offset,
            frontier.N_INTERACTION_COLUMNS,
        ) catch return error.InvalidIncrementalFrontierPlacement;
    }
};

pub const IncrementalFrontierComponentV1 = struct {
    log_size: u32,
    n_rows: u32,
    entry_root: u32,
    exit_root: u32,
    placement: Placement,
    relations: *const relations_mod.Relations,
    claim: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn init(
        log_size: u32,
        n_rows: u32,
        entry_root: u32,
        exit_root: u32,
        placement: Placement,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !@This() {
        try placement.validate();
        if (log_size < 4 or n_rows == 0 or
            n_rows > (@as(u32, 1) << @intCast(log_size)) or
            entry_root >= m31.Modulus or exit_root >= m31.Modulus)
        {
            return error.InvalidIncrementalFrontierClaim;
        }
        return .{
            .log_size = log_size,
            .n_rows = n_rows,
            .entry_root = entry_root,
            .exit_root = exit_root,
            .placement = placement,
            .relations = relations,
            .claim = claim,
        };
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        return result;
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return frontier.N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index != 0) return error.InvalidProofShape;
        return 3;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(allocator, 2, self.log_size);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(
            allocator,
            frontier.N_MAIN_COLUMNS,
            self.log_size,
        );
        errdefer allocator.free(main);
        const interaction = try filledLogs(
            allocator,
            frontier.N_INTERACTION_COLUMNS,
            self.log_size,
        );
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
        if (max_log_degree_bound < self.log_size)
            return error.InvalidMaskDegreeBound;
        const preprocessed = try pointColumns(allocator, 2, &.{point});
        errdefer freePointColumns(allocator, preprocessed);
        const main = try pointColumns(
            allocator,
            frontier.N_MAIN_COLUMNS,
            &.{point},
        );
        errdefer freePointColumns(allocator, main);
        const interaction = try pointColumns(
            allocator,
            frontier.N_INTERACTION_COLUMNS,
            &.{ point, logup.prevRowPoint(max_log_degree_bound, point) },
        );
        errdefer freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        });
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or max_log_degree_bound < self.log_size)
            return error.InvalidPointMaskShape;
        const pp = mask.items[0];
        const main = mask.items[1];
        const interaction = mask.items[2];
        if (pp.len <= @max(
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        ) or main.len < self.placement.main_col_offset + frontier.N_MAIN_COLUMNS or
            interaction.len < self.placement.interaction_col_offset +
                frontier.N_INTERACTION_COLUMNS)
        {
            return error.InvalidSampledMaskShape;
        }
        const constraint = frontier.evaluate(
            try sampledMain(main, self.placement.main_col_offset),
            try pointAt(pp[self.placement.is_active_col_idx], 0),
            try pointAt(pp[self.placement.is_first_col_idx], 0),
            try sampledSecure(interaction, self.placement.interaction_col_offset, 0),
            try sampledSecure(interaction, self.placement.interaction_col_offset, 1),
            self.claim,
            base(self.entry_root),
            base(self.exit_root),
            self.relations,
        )[0];
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        accumulator.accumulate(constraint.mul(denominator_inv));
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
        var context = serialTaskContext(prepared.context, &cancellation);
        try prepared.run(&context);
    }

    fn prepareDomainEvaluatorErased(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const @This() = @ptrCast(@alignCast(context));
        return self.prepareDomainEvaluator(allocator, trace_data, accumulator);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace_data.polys.items.len != 3) return error.InvalidTraceTreeCount;
        const trees = trace_data.polys.items;
        if (trees[0].len <= @max(
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        ) or trees[1].len < self.placement.main_col_offset +
            frontier.N_MAIN_COLUMNS or
            trees[2].len < self.placement.interaction_col_offset +
                frontier.N_INTERACTION_COLUMNS)
        {
            return error.InvalidTraceColumnCount;
        }
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const polys = [prepared_source_count]prover_component.Poly{
            trees[0][self.placement.is_first_col_idx],
            trees[0][self.placement.is_active_col_idx],
            trees[1][self.placement.main_col_offset],
            trees[1][self.placement.main_col_offset + 1],
            trees[1][self.placement.main_col_offset + 2],
            trees[2][self.placement.interaction_col_offset],
            trees[2][self.placement.interaction_col_offset + 1],
            trees[2][self.placement.interaction_col_offset + 2],
            trees[2][self.placement.interaction_col_offset + 3],
        };
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(
            try prepared_support.sourceNeedsExtension(
                poly,
                self.log_size,
                eval_log_size,
            ),
        );
        var evaluations: [prepared_source_count][]const M31 = undefined;
        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        for (polys, &evaluations) |poly, *values| values.* =
            try prepared_support.evaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &initialized,
            );
        if (owned_buffers.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                eval_domain.half_coset,
            );
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
            2,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resourcesWithStack(
            eval_size,
            0,
            owned_count,
            @sizeOf(PreparedState),
            128 * 1024,
        );
        const columns = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer allocator.free(columns);
        const state = try allocator.create(PreparedState);
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .owned_buffers = owned_buffers,
            .denominator_inv = denominator_inv,
            .accumulator = columns[0],
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
        };
        return .{
            .context = state,
            .vtable = &PreparedState.vtable,
            .task_class = .pool_exclusive,
            .resources = resources,
        };
    }
};

const PreparedState = struct {
    allocator: std.mem.Allocator,
    component: *const IncrementalFrontierComponentV1,
    evaluations: [prepared_source_count][]const M31,
    owned_buffers: [][]M31,
    denominator_inv: [2]M31,
    accumulator: prover_air_accumulation.ColumnAccumulator,
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
        try self.run(task_context);
    }

    fn deinitErased(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        for (self.owned_buffers) |values| allocator.free(values);
        allocator.free(self.owned_buffers);
        allocator.destroy(self);
    }

    fn run(
        self: *@This(),
        task_context: *prover_task_graph.TaskContext,
    ) !void {
        const shift: std.math.Log2Int(usize) =
            @intCast(self.component.log_size);
        for (0..self.eval_size) |row| {
            if ((row & 4095) == 0 and task_context.isCancelled()) return;
            const previous = utils.previousBitReversedCircleDomainIndex(
                row,
                self.component.log_size,
                self.eval_log_size,
            );
            const main = [frontier.N_MAIN_COLUMNS]QM31{
                QM31.fromBase(self.evaluations[2][row]),
                QM31.fromBase(self.evaluations[3][row]),
                QM31.fromBase(self.evaluations[4][row]),
            };
            const constraint = frontier.evaluate(
                main,
                QM31.fromBase(self.evaluations[1][row]),
                QM31.fromBase(self.evaluations[0][row]),
                secureAt(&self.evaluations, 5, row),
                secureAt(&self.evaluations, 5, previous),
                self.component.claim,
                base(self.component.entry_root),
                base(self.component.exit_root),
                self.component.relations,
            )[0];
            self.accumulator.accumulate(
                row,
                self.accumulator.random_coeff_powers[0]
                    .mul(constraint)
                    .mulM31(self.denominator_inv[row >> shift]),
            );
        }
    }
};

fn sampledMain(
    columns: [][]QM31,
    offset: usize,
) ![frontier.N_MAIN_COLUMNS]QM31 {
    var result: [frontier.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, 0..) |*value, index| {
        value.* = try pointAt(columns[offset + index], 0);
    }
    return result;
}

fn filledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

fn pointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    points: []const CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}

fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn pointAt(values: []const QM31, index: usize) !QM31 {
    if (values.len <= index) return error.MissingMaskPoint;
    return values[index];
}

fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point: usize,
) !QM31 {
    if (columns.len < offset + 4) return error.InvalidSecureMaskShape;
    return QM31.fromPartialEvals(.{
        try pointAt(columns[offset], point),
        try pointAt(columns[offset + 1], point),
        try pointAt(columns[offset + 2], point),
        try pointAt(columns[offset + 3], point),
    });
}

fn secureAt(
    columns: []const []const M31,
    offset: usize,
    row: usize,
) QM31 {
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn serialTaskContext(
    context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_engine.work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

test "incremental frontier component pins geometry and public roots" {
    const relations = relations_mod.Relations.dummy();
    const placement = Placement{
        .is_first_col_idx = 3,
        .is_active_col_idx = 4,
        .main_col_offset = 7,
        .interaction_col_offset = 11,
    };
    const component = try IncrementalFrontierComponentV1.init(
        5,
        17,
        123,
        456,
        placement,
        &relations,
        QM31.zero(),
    );
    try std.testing.expectEqual(@as(usize, 1), component.nConstraints());
    try std.testing.expectEqual(@as(u32, 6), component.maxConstraintLogDegreeBound());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectError(
        error.InvalidIncrementalFrontierClaim,
        IncrementalFrontierComponentV1.init(
            5,
            0,
            123,
            456,
            placement,
            &relations,
            QM31.zero(),
        ),
    );
}

comptime {
    if (prepared_source_count != 9 or frontier.N_MAIN_COLUMNS != 3 or
        frontier.N_INTERACTION_COLUMNS != 4 or frontier.N_CONSTRAINTS != 1)
    {
        @compileError("incremental frontier component geometry drifted");
    }
}
