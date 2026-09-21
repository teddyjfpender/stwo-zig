//! Prover/verifier AIR adapter for the changed-only incremental-memory bridge.

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
const bridge = @import("incremental_bridge_v2.zig");
const logup = @import("../logup.zig");
const prepared_support = @import("hash_component_prepared_support.zig");
const relations_mod = @import("../relation_challenges.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const prepared_source_count = 2 + bridge.N_MAIN_COLUMNS +
    bridge.N_INTERACTION_COLUMNS;
const main_source_offset: usize = 2;
const interaction_source_offset = main_source_offset + bridge.N_MAIN_COLUMNS;

pub const Placement = struct {
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,

    pub fn validate(self: Placement) !void {
        if (self.is_first_col_idx == self.is_active_col_idx)
            return error.InvalidIncrementalBridgePlacement;
        _ = std.math.add(
            usize,
            self.main_col_offset,
            bridge.N_MAIN_COLUMNS,
        ) catch return error.InvalidIncrementalBridgePlacement;
        _ = std.math.add(
            usize,
            self.interaction_col_offset,
            bridge.N_INTERACTION_COLUMNS,
        ) catch return error.InvalidIncrementalBridgePlacement;
    }
};

pub const IncrementalBridgeComponentV2 = struct {
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
            return error.InvalidIncrementalBridgeClaim;
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
        return bridge.N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        return switch (index) {
            0 => 3,
            1...bridge.N_MODES => 2,
            bridge.N_CONSTRAINTS - 1 => 1,
            else => error.InvalidConstraintIndex,
        };
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(allocator, 2, self.log_size);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(
            allocator,
            bridge.N_MAIN_COLUMNS,
            self.log_size,
        );
        errdefer allocator.free(main);
        const interaction = try filledLogs(
            allocator,
            bridge.N_INTERACTION_COLUMNS,
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
            bridge.N_MAIN_COLUMNS,
            &.{point},
        );
        errdefer freePointColumns(allocator, main);
        const interaction = try pointColumns(
            allocator,
            bridge.N_INTERACTION_COLUMNS,
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
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const interaction = mask.items[2];
        if (preprocessed.len <= @max(
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        ) or main.len < self.placement.main_col_offset + bridge.N_MAIN_COLUMNS or
            interaction.len < self.placement.interaction_col_offset +
                bridge.N_INTERACTION_COLUMNS)
        {
            return error.InvalidSampledMaskShape;
        }
        const constraints = bridge.evaluateGeneric(
            QM31,
            try sampledMain(main, self.placement.main_col_offset),
            try pointAt(preprocessed[self.placement.is_active_col_idx], 0),
            try pointAt(preprocessed[self.placement.is_first_col_idx], 0),
            try sampledSecure(interaction, self.placement.interaction_col_offset, 0),
            try sampledSecure(interaction, self.placement.interaction_col_offset, 1),
            self.claim,
            base(self.entry_root),
            base(self.exit_root),
            self.relations,
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints) |constraint| {
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
            bridge.N_MAIN_COLUMNS or
            trees[2].len < self.placement.interaction_col_offset +
                bridge.N_INTERACTION_COLUMNS)
        {
            return error.InvalidTraceColumnCount;
        }
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        var polys: [prepared_source_count]prover_component.Poly = undefined;
        polys[0] = trees[0][self.placement.is_first_col_idx];
        polys[1] = trees[0][self.placement.is_active_col_idx];
        for (0..bridge.N_MAIN_COLUMNS) |index| {
            polys[main_source_offset + index] =
                trees[1][self.placement.main_col_offset + index];
        }
        for (0..bridge.N_INTERACTION_COLUMNS) |index| {
            polys[interaction_source_offset + index] =
                trees[2][self.placement.interaction_col_offset + index];
        }
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
            &.{.{
                .log_size = eval_log_size,
                .n_cols = bridge.N_CONSTRAINTS,
            }},
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
    component: *const IncrementalBridgeComponentV2,
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
            var main: [bridge.N_MAIN_COLUMNS]QM31 = undefined;
            for (&main, self.evaluations[main_source_offset..][0..bridge.N_MAIN_COLUMNS]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            const constraints = bridge.evaluateGeneric(
                QM31,
                main,
                QM31.fromBase(self.evaluations[1][row]),
                QM31.fromBase(self.evaluations[0][row]),
                secureAt(&self.evaluations, interaction_source_offset, row),
                secureAt(&self.evaluations, interaction_source_offset, previous),
                self.component.claim,
                base(self.component.entry_root),
                base(self.component.exit_root),
                self.component.relations,
            );
            var folded = QM31.zero();
            const powers = self.accumulator.random_coeff_powers;
            for (constraints, 0..) |constraint, index| {
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            self.accumulator.accumulate(
                row,
                folded.mulM31(self.denominator_inv[row >> shift]),
            );
        }
    }
};

fn sampledMain(
    columns: [][]QM31,
    offset: usize,
) ![bridge.N_MAIN_COLUMNS]QM31 {
    var result: [bridge.N_MAIN_COLUMNS]QM31 = undefined;
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

fn testPlacement() Placement {
    return .{
        .is_first_col_idx = 3,
        .is_active_col_idx = 4,
        .main_col_offset = 7,
        .interaction_col_offset = 17,
    };
}

test "incremental bridge v2 component pins claim geometry roots masks and degrees" {
    const relations = relations_mod.Relations.dummy();
    const component = try IncrementalBridgeComponentV2.init(
        5,
        17,
        123,
        456,
        testPlacement(),
        &relations,
        QM31.fromU32Unchecked(1, 2, 3, 4),
    );
    try std.testing.expectEqual(@as(u32, 5), component.log_size);
    try std.testing.expectEqual(@as(u32, 17), component.n_rows);
    try std.testing.expectEqual(@as(u32, 123), component.entry_root);
    try std.testing.expectEqual(@as(u32, 456), component.exit_root);
    try std.testing.expectEqual(@as(usize, 6), component.nConstraints());
    try std.testing.expectEqual(@as(u32, 6), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u8, 3), try component.constraintDegreeBound(0));
    for (1..1 + bridge.N_MODES) |index| {
        try std.testing.expectEqual(@as(u8, 2), try component.constraintDegreeBound(index));
    }
    try std.testing.expectEqual(@as(u8, 1), try component.constraintDegreeBound(5));
    try std.testing.expectError(
        error.InvalidConstraintIndex,
        component.constraintDegreeBound(bridge.N_CONSTRAINTS),
    );

    const verifier = component.asVerifierComponent();
    const prover = component.asProverComponent();
    try std.testing.expectEqual(bridge.N_CONSTRAINTS, verifier.nConstraints());
    try std.testing.expectEqual(bridge.N_CONSTRAINTS, prover.nConstraints());
    try std.testing.expect(prover.prepare_domain_evaluator != null);

    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 2), bounds.items[0].len);
    try std.testing.expectEqual(bridge.N_MAIN_COLUMNS, bounds.items[1].len);
    try std.testing.expectEqual(bridge.N_INTERACTION_COLUMNS, bounds.items[2].len);
    for (bounds.items) |tree| for (tree) |log_size| {
        try std.testing.expectEqual(@as(u32, 5), log_size);
    };

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var masks = try component.maskPoints(std.testing.allocator, point, 6);
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), masks.items.len);
    try std.testing.expectEqual(@as(usize, 2), masks.items[0].len);
    try std.testing.expectEqual(bridge.N_MAIN_COLUMNS, masks.items[1].len);
    try std.testing.expectEqual(bridge.N_INTERACTION_COLUMNS, masks.items[2].len);
    for (masks.items[0]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
    }
    for (masks.items[1]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
    }
    const previous = logup.prevRowPoint(6, point);
    for (masks.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
        try std.testing.expect(std.meta.eql(previous, column[1]));
    }
    const indices = try component.preprocessedColumnIndices(std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 3, 4 }, indices);
}

test "incremental bridge v2 component rejects invalid public authority" {
    const relations = relations_mod.Relations.dummy();
    const placement = testPlacement();
    try std.testing.expectError(
        error.InvalidIncrementalBridgeClaim,
        IncrementalBridgeComponentV2.init(
            5,
            0,
            123,
            456,
            placement,
            &relations,
            QM31.zero(),
        ),
    );
    try std.testing.expectError(
        error.InvalidIncrementalBridgeClaim,
        IncrementalBridgeComponentV2.init(
            5,
            17,
            m31.Modulus,
            456,
            placement,
            &relations,
            QM31.zero(),
        ),
    );
    var invalid = placement;
    invalid.is_active_col_idx = invalid.is_first_col_idx;
    try std.testing.expectError(
        error.InvalidIncrementalBridgePlacement,
        IncrementalBridgeComponentV2.init(
            5,
            17,
            123,
            456,
            invalid,
            &relations,
            QM31.zero(),
        ),
    );
}

test "incremental bridge v2 component binds exact one-hot selectors" {
    const relations = relations_mod.Relations.dummy();
    var main = [_]QM31{QM31.zero()} ** bridge.N_MAIN_COLUMNS;
    main[0] = base(7);
    main[1] = base(30);
    main[2] = base(99);
    main[3] = QM31.one();
    const honest = bridge.evaluateGeneric(
        QM31,
        main,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        base(123),
        base(456),
        &relations,
    );
    for (honest[1..]) |constraint| try std.testing.expect(constraint.isZero());

    main[4] = QM31.one();
    const two_hot = bridge.evaluateGeneric(
        QM31,
        main,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        base(123),
        base(456),
        &relations,
    );
    try std.testing.expect(!two_hot[bridge.N_CONSTRAINTS - 1].isZero());

    main[4] = QM31.zero();
    main[3] = base(2);
    const non_boolean = bridge.evaluateGeneric(
        QM31,
        main,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        base(123),
        base(456),
        &relations,
    );
    try std.testing.expect(!non_boolean[1].isZero());
}

comptime {
    if (prepared_source_count != 13 or bridge.N_MODES != 4 or
        bridge.N_MAIN_COLUMNS != 7 or bridge.N_INTERACTION_COLUMNS != 4 or
        bridge.N_CONSTRAINTS != 6)
    {
        @compileError("incremental bridge v2 component geometry drifted");
    }
}
