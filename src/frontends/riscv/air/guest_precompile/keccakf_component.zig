//! Stwo prover/verifier adapter for one bounded paired Keccak-f shard.

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
const direct = @import("keccakf_direct.zig");
const interaction = @import("keccakf_interaction_plan.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace_mod = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");
const logup = @import("../logup.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const preprocessed_column_count = trace_mod.Layout.preprocessed_columns;
pub const main_column_count = trace_mod.Layout.main_columns;
pub const interaction_column_count = interaction.interaction_column_count;
pub const direct_constraint_count = direct.constraint_count;
pub const interaction_constraint_count = interaction.batch_count;
pub const constraint_count = direct_constraint_count + interaction_constraint_count;
pub const prepared_row_stack_bytes: usize = 512 * 1024;
const prepared_source_count = preprocessed_column_count + main_column_count +
    interaction_column_count;

pub const Claim = struct {
    log_size: u32,
    n_rows: u32,
    first_call_index: u32,
    call_count: u32,
    batch_sums: [interaction.batch_count]QM31,
    component_sum: QM31,

    pub fn canonical(
        trace: *const trace_mod.Shard,
        batch_sums: [interaction.batch_count]QM31,
    ) InitError!Claim {
        const result = Claim{
            .log_size = trace.log_size,
            .n_rows = trace.n_rows,
            .first_call_index = trace.first_call_index,
            .call_count = trace.call_count,
            .batch_sums = batch_sums,
            .component_sum = sumClaims(batch_sums),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: Claim) InitError!void {
        if (self.call_count == 0 or
            self.call_count > trace_mod.maximum_calls_per_shard)
        {
            return error.InvalidClaim;
        }
        const end = std.math.add(u32, self.first_call_index, self.call_count) catch
            return error.InvalidClaim;
        if (end > @import("keccakf_authority.zig").geometry.maximum_calls)
            return error.InvalidClaim;
        const slots = std.math.divCeil(u32, self.call_count, 2) catch unreachable;
        const rows = std.math.mul(u32, slots, witness.row_count) catch
            return error.InvalidClaim;
        const expected_log: u32 = @max(
            trace_mod.minimum_log_size,
            std.math.log2_int_ceil(u32, rows),
        );
        if (self.n_rows != rows or self.log_size != expected_log or
            self.log_size > trace_mod.maximum_log_size or
            !sumClaims(self.batch_sums).eql(self.component_sum))
        {
            return error.InvalidClaim;
        }
    }
};

pub const Placement = struct {
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,

    pub fn validate(self: Placement) InitError!void {
        _ = checkedEnd(self.preprocessed_offset, preprocessed_column_count) catch
            return error.InvalidPlacement;
        _ = checkedEnd(self.main_offset, main_column_count) catch
            return error.InvalidPlacement;
        _ = checkedEnd(self.interaction_offset, interaction_column_count) catch
            return error.InvalidPlacement;
    }
};

pub const InitError = error{
    InvalidClaim,
    InvalidPlacement,
    InvalidProofShape,
    ResourceReservationOverflow,
};

pub const KeccakShardComponent = struct {
    claim: Claim,
    placement: Placement,
    relations: *const relations_mod.Relations,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initProver(
        claim: Claim,
        placement: Placement,
        relations: *const relations_mod.Relations,
    ) InitError!KeccakShardComponent {
        return init(claim, placement, relations);
    }

    pub fn initVerifier(
        claim: Claim,
        placement: Placement,
        relations: *const relations_mod.Relations,
    ) InitError!KeccakShardComponent {
        return init(claim, placement, relations);
    }

    fn init(
        claim: Claim,
        placement: Placement,
        relations: *const relations_mod.Relations,
    ) InitError!KeccakShardComponent {
        try claim.validate();
        try placement.validate();
        return .{ .claim = claim, .placement = placement, .relations = relations };
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
        return constraint_count;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.claim.log_size + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index >= constraint_count) return error.InvalidProofShape;
        return 3;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const log_size = self.claim.log_size;
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
        if (max_log_degree_bound < self.claim.log_size)
            return error.InvalidMaskDegreeBound;
        const preprocessed = try pointColumns(
            allocator,
            preprocessed_column_count,
            &.{point},
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try allocator.alloc([]CirclePointQM31, main_column_count);
        var main_initialized: usize = 0;
        errdefer {
            for (main[0..main_initialized]) |column| allocator.free(column);
            allocator.free(main);
        }
        for (main, 0..) |*column, local| {
            const points = if (local >= trace_mod.Layout.io_a and
                local < trace_mod.Layout.state)
                &.{ point, shiftedPoint(max_log_degree_bound, point, -1) }
            else if (local >= trace_mod.Layout.state and
                local < trace_mod.Layout.parity)
                &.{
                    point,
                    shiftedPoint(max_log_degree_bound, point, -2),
                    shiftedPoint(max_log_degree_bound, point, -1),
                    shiftedPoint(max_log_degree_bound, point, 1),
                    shiftedPoint(max_log_degree_bound, point, 2),
                }
            else
                &.{point};
            column.* = try allocator.dupe(CirclePointQM31, points);
            main_initialized += 1;
        }
        const secure = try pointColumns(
            allocator,
            interaction_column_count,
            &.{ point, shiftedPoint(max_log_degree_bound, point, -1) },
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
        const result = try allocator.alloc(usize, preprocessed_column_count);
        for (result, 0..) |*value, index| value.* =
            self.placement.preprocessed_offset + index;
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or
            max_log_degree_bound < self.claim.log_size)
        {
            return error.InvalidPointMaskShape;
        }
        const sampled = try samplePoint(self, mask);
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.claim.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.claim.log_size),
        ).inv();
        var sink = PointSink{
            .accumulator = accumulator,
            .denominator_inv = denominator_inv,
        };
        try direct.evaluateGeneric(
            QM31,
            &sampled.main,
            &sampled.previous_io,
            &sampled.state_minus_two,
            &sampled.state_minus_one,
            &sampled.state_plus_one,
            &sampled.state_plus_two,
            &sampled.selectors,
            sampled.second_active,
            &sink,
        );
        const pairs = try interaction.rowPairs(
            &sampled.main,
            &sampled.state_plus_one,
            &sampled.selectors,
            self.relations,
        );
        for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
            sampled.current_sums[batch],
            sampled.previous_sums[batch],
            sampled.is_first,
            self.claim.batch_sums[batch],
            pair,
        ), 3);
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
        const eval_log_size = self.claim.log_size + 1;
        if (eval_log_size >= circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidEvaluationLogSize;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const trees = trace_data.polys.items;
        const preprocessed_end = try checkedEnd(
            self.placement.preprocessed_offset,
            preprocessed_column_count,
        );
        const main_end = try checkedEnd(self.placement.main_offset, main_column_count);
        const interaction_end = try checkedEnd(
            self.placement.interaction_offset,
            interaction_column_count,
        );
        if (trees[0].len < preprocessed_end or trees[1].len < main_end or
            trees[2].len < interaction_end)
        {
            return error.InvalidTraceColumnCount;
        }

        var owned_count: usize = 0;
        const slices = .{
            trees[0][self.placement.preprocessed_offset..preprocessed_end],
            trees[1][self.placement.main_offset..main_end],
            trees[2][self.placement.interaction_offset..interaction_end],
        };
        inline for (slices) |polys| for (polys) |poly| if (try prepared_support.sourceNeedsExtension(
            poly,
            self.claim.log_size,
            eval_log_size,
        )) {
            owned_count = try checkedAdd(owned_count, 1);
        };

        var evaluations: [prepared_source_count][]const M31 = undefined;
        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var owned_initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..owned_initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        var source: usize = 0;
        inline for (slices) |polys| for (polys) |poly| {
            evaluations[source] = try prepared_support.evaluationValues(
                allocator,
                poly,
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
            source += 1;
        };
        std.debug.assert(source == evaluations.len);
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
            self.claim.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resourcesWithStack(
            eval_size,
            0,
            owned_count,
            @sizeOf(PreparedDomainState),
            prepared_row_stack_bytes,
        );
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = constraint_count }},
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
            .task_class = .leaf,
            .resources = resources,
        };
    }
};

const PointSample = struct {
    is_first: QM31,
    selectors: [witness.row_count]QM31,
    second_active: QM31,
    main: [main_column_count]QM31,
    previous_io: [2 * relations_mod.io_arity]QM31,
    state_minus_two: [witness.state_cell_count]QM31,
    state_minus_one: [witness.state_cell_count]QM31,
    state_plus_one: [witness.state_cell_count]QM31,
    state_plus_two: [witness.state_cell_count]QM31,
    current_sums: [interaction.batch_count]QM31,
    previous_sums: [interaction.batch_count]QM31,
};

fn samplePoint(
    component: *const KeccakShardComponent,
    mask: *const core_air_components.MaskValues,
) !PointSample {
    const preprocessed = mask.items[0];
    const main_mask = mask.items[1];
    const secure = mask.items[2];
    const p = component.placement;
    const preprocessed_end = try checkedEnd(p.preprocessed_offset, preprocessed_column_count);
    const main_end = try checkedEnd(p.main_offset, main_column_count);
    const interaction_end = try checkedEnd(p.interaction_offset, interaction_column_count);
    if (preprocessed.len < preprocessed_end or main_mask.len < main_end or
        secure.len < interaction_end)
    {
        return error.InvalidSampledMaskShape;
    }
    var result: PointSample = undefined;
    result.is_first = try pointAt(preprocessed[p.preprocessed_offset], 0);
    for (&result.selectors, 0..) |*value, group| value.* = try pointAt(
        preprocessed[p.preprocessed_offset + trace_mod.Layout.row_group + group],
        0,
    );
    result.second_active = try pointAt(
        preprocessed[p.preprocessed_offset + trace_mod.Layout.second_active],
        0,
    );
    for (&result.main, 0..) |*value, column| value.* =
        try pointAt(main_mask[p.main_offset + column], 0);
    for (&result.previous_io, 0..) |*value, field| value.* =
        try pointAt(main_mask[p.main_offset + trace_mod.Layout.io_a + field], 1);
    for (0..witness.state_cell_count) |cell| {
        const points = main_mask[p.main_offset + trace_mod.Layout.state + cell];
        result.state_minus_two[cell] = try pointAt(points, 1);
        result.state_minus_one[cell] = try pointAt(points, 2);
        result.state_plus_one[cell] = try pointAt(points, 3);
        result.state_plus_two[cell] = try pointAt(points, 4);
    }
    for (0..interaction.batch_count) |batch| {
        result.current_sums[batch] = try sampledSecure(
            secure,
            p.interaction_offset + 4 * batch,
            0,
        );
        result.previous_sums[batch] = try sampledSecure(
            secure,
            p.interaction_offset + 4 * batch,
            1,
        );
    }
    return result;
}

const PointSink = struct {
    accumulator: *core_air_accumulation.PointEvaluationAccumulator,
    denominator_inv: QM31,

    pub fn add(self: *PointSink, value: QM31, degree: u8) void {
        _ = degree;
        self.accumulator.accumulate(value.mul(self.denominator_inv));
    }
};

const PreparedDomainState = struct {
    allocator: std.mem.Allocator,
    component: *const KeccakShardComponent,
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
        const main_start = preprocessed_column_count;
        const interaction_start = main_start + main_column_count;
        const powers = self.column_accumulator.random_coeff_powers;
        const shift: std.math.Log2Int(usize) = @intCast(self.component.claim.log_size);
        for (0..self.eval_size) |row| {
            if ((row & 4095) == 0 and task_context.isCancelled()) return;
            const previous_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.component.claim.log_size,
                self.eval_log_size,
                -1,
            );
            const minus_two_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.component.claim.log_size,
                self.eval_log_size,
                -2,
            );
            const plus_one_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.component.claim.log_size,
                self.eval_log_size,
                1,
            );
            const plus_two_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.component.claim.log_size,
                self.eval_log_size,
                2,
            );
            var main: [main_column_count]M31 = undefined;
            for (&main, 0..) |*value, column| value.* =
                self.evaluations[main_start + column][row];
            var previous_io: [2 * relations_mod.io_arity]M31 = undefined;
            for (&previous_io, 0..) |*value, field| value.* = self.evaluations[
                main_start + trace_mod.Layout.io_a + field
            ][previous_row];
            var minus_two: [witness.state_cell_count]M31 = undefined;
            var minus_one: [witness.state_cell_count]M31 = undefined;
            var plus_one: [witness.state_cell_count]M31 = undefined;
            var plus_two: [witness.state_cell_count]M31 = undefined;
            for (0..witness.state_cell_count) |cell| {
                const values = self.evaluations[
                    main_start + trace_mod.Layout.state + cell
                ];
                minus_two[cell] = values[minus_two_row];
                minus_one[cell] = values[previous_row];
                plus_one[cell] = values[plus_one_row];
                plus_two[cell] = values[plus_two_row];
            }
            var selectors: [witness.row_count]M31 = undefined;
            for (&selectors, 0..) |*value, group| value.* = self.evaluations[
                trace_mod.Layout.row_group + group
            ][row];
            const second_active = self.evaluations[trace_mod.Layout.second_active][row];
            var sink = FoldSink{ .powers = powers };
            try direct.evaluateGeneric(
                M31,
                &main,
                &previous_io,
                &minus_two,
                &minus_one,
                &plus_one,
                &plus_two,
                &selectors,
                second_active,
                &sink,
            );
            const pairs = try interaction.rowPairsBase(
                &main,
                &plus_one,
                &selectors,
                self.component.relations,
            );
            const is_first = QM31.fromBase(self.evaluations[trace_mod.Layout.is_first][row]);
            for (pairs, 0..) |pair, batch| {
                const offset = interaction_start + 4 * batch;
                sink.add(logup.pairConstraint(
                    secureAt(&self.evaluations, offset, row),
                    secureAt(&self.evaluations, offset, previous_row),
                    is_first,
                    self.component.claim.batch_sums[batch],
                    pair,
                ), 3);
            }
            std.debug.assert(sink.index == constraint_count);
            self.column_accumulator.accumulate(
                row,
                sink.folded.mulM31(self.denominator_inv[row >> shift]),
            );
        }
    }
};

const FoldSink = struct {
    powers: []const QM31,
    index: usize = 0,
    folded: QM31 = QM31.zero(),

    pub fn add(self: *FoldSink, value: anytype, degree: u8) void {
        _ = degree;
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.folded = self.folded.add(
            self.powers[self.powers.len - 1 - self.index].mul(lifted),
        );
        self.index += 1;
    }
};

fn shiftedPoint(log_size: u32, point: CirclePointQM31, offset: isize) CirclePointQM31 {
    const step = logup.liftPoint(canonic.CanonicCoset.new(log_size).coset_value.step);
    return point.add(step.mulSigned(offset));
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
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| value.* =
        try pointAt(columns[offset + index], point);
    return QM31.fromPartialEvals(coordinates);
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

fn sumClaims(claims: [interaction.batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (claims) |claim| result = result.add(claim);
    return result;
}

fn checkedEnd(offset: usize, count: usize) !usize {
    return std.math.add(usize, offset, count) catch error.InvalidPlacement;
}

fn checkedAdd(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch error.ResourceReservationOverflow;
}

comptime {
    if (constraint_count != 7004 or prepared_source_count != 6015)
        @compileError("Keccak-f component geometry drifted");
}
