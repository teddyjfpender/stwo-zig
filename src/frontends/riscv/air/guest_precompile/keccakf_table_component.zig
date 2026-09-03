//! Generic Stwo adapter for a Keccak χ or xor5 multiplicity table.

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
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_task_graph = prover_engine.task_graph;
const prover_poly = prover_engine.poly.circle.poly;
const prover_twiddles = prover_engine.poly.twiddles;
const logup = @import("../logup.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");
const relations_mod = @import("keccakf_relations.zig");
const tables = @import("keccakf_tables.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const preprocessed_column_count: usize = 1 + tables.arity;
pub const main_column_count: usize = 1;
pub const interaction_column_count: usize = 4;
pub const constraint_count: usize = 1;
const prepared_source_count: usize = preprocessed_column_count +
    main_column_count + interaction_column_count;

pub const Placement = struct {
    is_first_col_idx: usize,
    tuple_col_indices: [tables.arity]usize,
    main_col_offset: usize,
    interaction_col_offset: usize,

    pub fn validate(self: Placement) !void {
        for (self.tuple_col_indices, 0..) |column, index| {
            if (column == self.is_first_col_idx) return error.InvalidPlacement;
            for (self.tuple_col_indices[0..index]) |prior|
                if (column == prior) return error.InvalidPlacement;
        }
        _ = std.math.add(usize, self.main_col_offset, 1) catch
            return error.InvalidPlacement;
        _ = std.math.add(usize, self.interaction_col_offset, 4) catch
            return error.InvalidPlacement;
    }
};

pub const KeccakTableComponent = struct {
    kind: tables.Kind,
    placement: Placement,
    relations: *const relations_mod.Relations,
    claim: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initProver(
        kind: tables.Kind,
        placement: Placement,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !KeccakTableComponent {
        try placement.validate();
        return .{ .kind = kind, .placement = placement, .relations = relations, .claim = claim };
    }

    pub fn initVerifier(
        kind: tables.Kind,
        placement: Placement,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !KeccakTableComponent {
        return initProver(kind, placement, relations, claim);
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
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return tables.logSize(self.kind) + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index != 0) return error.InvalidProofShape;
        return 3;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const log_size = tables.logSize(self.kind);
        const preprocessed = try allocator.alloc(u32, preprocessed_column_count);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, log_size);
        const main = try allocator.alloc(u32, main_column_count);
        errdefer allocator.free(main);
        @memset(main, log_size);
        const secure = try allocator.alloc(u32, interaction_column_count);
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
        if (max_log_degree_bound < tables.logSize(self.kind))
            return error.InvalidMaskDegreeBound;
        const preprocessed = try pointColumns(
            allocator,
            preprocessed_column_count,
            &.{point},
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try pointColumns(
            allocator,
            main_column_count,
            &.{point},
        );
        errdefer freePointColumns(allocator, main);
        const interaction = try pointColumns(
            allocator,
            interaction_column_count,
            &.{ point, logup.prevRowPoint(max_log_degree_bound, point) },
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
        const result = try allocator.alloc(usize, preprocessed_column_count);
        result[0] = self.placement.is_first_col_idx;
        @memcpy(result[1..], &self.placement.tuple_col_indices);
        return result;
    }

    pub fn evaluateRow(
        self: *const @This(),
        tuple: []const QM31,
        multiplicity: QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
    ) !QM31 {
        return evaluateRowGeneric(
            QM31,
            self.kind,
            tuple,
            multiplicity,
            current,
            previous,
            is_first,
            self.claim,
            self.relations,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or
            max_log_degree_bound < tables.logSize(self.kind))
        {
            return error.InvalidPointMaskShape;
        }
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        if (preprocessed.len <= maxTupleIndex(self.placement) or
            preprocessed.len <= self.placement.is_first_col_idx or
            main.len <= self.placement.main_col_offset or
            secure.len < self.placement.interaction_col_offset + 4)
        {
            return error.InvalidSampledMaskShape;
        }
        var tuple: [tables.arity]QM31 = undefined;
        for (&tuple, self.placement.tuple_col_indices) |*value, column|
            value.* = try pointAt(preprocessed[column], 0);
        const constraint = try self.evaluateRow(
            &tuple,
            try pointAt(main[self.placement.main_col_offset], 0),
            try sampledSecure(secure, self.placement.interaction_col_offset, 0),
            try sampledSecure(secure, self.placement.interaction_col_offset, 1),
            try pointAt(preprocessed[self.placement.is_first_col_idx], 0),
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(tables.logSize(self.kind)).coset(),
            point.repeatedDouble(max_log_degree_bound - tables.logSize(self.kind)),
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
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return self.prepareDomainEvaluator(allocator, trace_data, accumulator);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace_data.polys.items.len != 3) return error.InvalidTraceTreeCount;
        const log_size = tables.logSize(self.kind);
        const eval_log_size = log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const trees = trace_data.polys.items;
        if (trees[0].len <= maxTupleIndex(self.placement) or
            trees[0].len <= self.placement.is_first_col_idx or
            trees[1].len <= self.placement.main_col_offset or
            trees[2].len < self.placement.interaction_col_offset + 4)
        {
            return error.InvalidTraceColumnCount;
        }
        const polys = [prepared_source_count]prover_component.Poly{
            trees[0][self.placement.is_first_col_idx],
            trees[0][self.placement.tuple_col_indices[0]],
            trees[0][self.placement.tuple_col_indices[1]],
            trees[0][self.placement.tuple_col_indices[2]],
            trees[0][self.placement.tuple_col_indices[3]],
            trees[0][self.placement.tuple_col_indices[4]],
            trees[0][self.placement.tuple_col_indices[5]],
            trees[1][self.placement.main_col_offset],
            trees[2][self.placement.interaction_col_offset],
            trees[2][self.placement.interaction_col_offset + 1],
            trees[2][self.placement.interaction_col_offset + 2],
            trees[2][self.placement.interaction_col_offset + 3],
        };
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(
            try prepared_support.sourceNeedsExtension(poly, log_size, eval_log_size),
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
            log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resourcesWithStack(
            eval_size,
            0,
            owned_count,
            @sizeOf(PreparedDomainState),
            128 * 1024,
        );
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer allocator.free(accumulators);
        const state = try allocator.create(PreparedDomainState);
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .owned_buffers = owned_buffers,
            .denominator_inv = denominator_inv,
            .column_accumulator = accumulators[0],
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
        };
        return .{
            .context = state,
            .vtable = &PreparedDomainState.vtable,
            .task_class = .pool_exclusive,
            .resources = resources,
        };
    }
};

/// Single-source table constraint used by native verification and by the
/// recursive verifier-program compiler.
pub fn evaluateRowGeneric(
    comptime S: type,
    kind: tables.Kind,
    tuple: []const S,
    multiplicity: S,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    relations: anytype,
) !S {
    if (tuple.len != tables.arity) return error.InvalidProofShape;
    const relation = switch (kind) {
        .chi => relations.chi,
        .xor5 => relations.xor5,
    };
    const denominator = if (comptime S == QM31)
        relation.combineSecure(tuple[0..tables.arity].*)
    else if (comptime S == M31)
        relation.combineBase(tuple[0..tables.arity].*)
    else
        relation.combine(tuple[0..tables.arity].*);
    return logup.pairConstraintGeneric(
        S,
        current,
        previous,
        is_first,
        claim,
        logup.RowPairFor(S).single(multiplicity, denominator),
    );
}

const PreparedDomainState = struct {
    allocator: std.mem.Allocator,
    component: *const KeccakTableComponent,
    evaluations: [prepared_source_count][]const M31,
    owned_buffers: [][]M31,
    denominator_inv: [2]M31,
    column_accumulator: prover_air_accumulation.ColumnAccumulator,
    eval_log_size: u32,
    eval_size: usize,

    const vtable = prepared_domain.VTable{ .run = runErased, .deinit = deinitErased };

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

    fn run(self: *@This(), task_context: *prover_task_graph.TaskContext) !void {
        const log_size = tables.logSize(self.component.kind);
        const shift: std.math.Log2Int(usize) = @intCast(log_size);
        for (0..self.eval_size) |row| {
            if ((row & 4095) == 0 and task_context.isCancelled()) return;
            const previous = utils.previousBitReversedCircleDomainIndex(
                row,
                log_size,
                self.eval_log_size,
            );
            var tuple: [tables.arity]QM31 = undefined;
            for (&tuple, 0..) |*value, field| value.* =
                QM31.fromBase(self.evaluations[1 + field][row]);
            const constraint = try self.component.evaluateRow(
                &tuple,
                QM31.fromBase(self.evaluations[7][row]),
                secureAt(&self.evaluations, 8, row),
                secureAt(&self.evaluations, 8, previous),
                QM31.fromBase(self.evaluations[0][row]),
            );
            self.column_accumulator.accumulate(
                row,
                self.column_accumulator.random_coeff_powers[0]
                    .mul(constraint)
                    .mulM31(self.denominator_inv[row >> shift]),
            );
        }
    }
};

fn maxTupleIndex(placement: Placement) usize {
    var result = placement.is_first_col_idx;
    for (placement.tuple_col_indices) |column| result = @max(result, column);
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

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn pointAt(values: []const QM31, index: usize) !QM31 {
    if (values.len <= index) return error.MissingMaskPoint;
    return values[index];
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidSecureMaskShape;
    return QM31.fromPartialEvals(.{
        try pointAt(columns[offset], point),
        try pointAt(columns[offset + 1], point),
        try pointAt(columns[offset + 2], point),
        try pointAt(columns[offset + 3], point),
    });
}

fn secureAt(columns: []const []const M31, offset: usize, row: usize) QM31 {
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
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

comptime {
    if (prepared_source_count != 12 or preprocessed_column_count != 7)
        @compileError("Keccak table component geometry drifted");
}
