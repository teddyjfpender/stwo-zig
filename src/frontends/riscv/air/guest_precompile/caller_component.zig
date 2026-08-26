//! Stwo proof-component adapter for the authenticated guest Poseidon2 caller.
//!
//! The adapter owns one canonical component descriptor and all 77 terminal
//! LogUp sums by value.  Its row evaluator is the single composition seam:
//! the 417 direct constraints retain C-009's pinned order, followed by the 77
//! authenticated interaction batches in ordinal order.  Cold setup may
//! allocate mask and domain metadata; row evaluation performs no allocation.

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
const prover_poly = prover_engine.poly.circle.poly;
const prover_twiddles = prover_engine.poly.twiddles;
const prover_work_pool = prover_engine.work_pool;
const composition_work_support = @import("../composition_work_support.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");
const component_interaction = @import("caller_component_interaction.zig");
const component_mask = @import("caller_component_mask.zig");
const components = @import("component_registry.zig");
const direct_constraints = @import("direct_constraints.zig");
const interaction = @import("interaction.zig");
const interaction_plan = @import("interaction_plan.zig");
const logup = @import("../logup.zig");
const relation_challenges = @import("relation_challenges.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const Relations = relation_challenges.Poseidon2V1Relations;

pub const preprocessed_column_count: usize = components.preprocessed_columns;
pub const main_column_count: usize = direct_constraints.caller_main_column_count;
pub const interaction_column_count: usize = interaction.caller_column_count;
pub const direct_constraint_count: usize = direct_constraints.caller_constraint_count;
pub const interaction_constraint_count: usize = interaction.caller_batch_count;
pub const constraint_count: usize = direct_constraint_count + interaction_constraint_count;
pub const event_count: usize = interaction.caller_event_count;
pub const batch_count: usize = interaction.caller_batch_count;
pub const maximum_constraint_degree: u8 = direct_constraints.maximum_constraint_degree;
pub const row_evaluation_allocation_count: usize = 0;

pub const InitError = components.Error || error{
    ClaimDescriptorMismatch,
    ComponentClaimMismatch,
    InvalidColumnPlacement,
    InvalidTraceLogSize,
    NonZeroEmptyClaim,
};

pub const Error = InitError || interaction.Error || error{
    InvalidConstraintIndex,
    InvalidProofShape,
    ResourceReservationOverflow,
};

/// Global tree placement for the caller's component-local columns.
pub const Placement = struct {
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,

    pub fn validate(self: Placement) InitError!void {
        const expected_active = std.math.add(
            usize,
            self.is_first_col_idx,
            1,
        ) catch return error.InvalidColumnPlacement;
        if (self.is_active_col_idx != expected_active)
            return error.InvalidColumnPlacement;
        _ = std.math.add(usize, self.main_col_offset, main_column_count) catch
            return error.InvalidColumnPlacement;
        _ = std.math.add(
            usize,
            self.interaction_col_offset,
            interaction_column_count,
        ) catch return error.InvalidColumnPlacement;
    }
};

pub const ColumnPlacement = Placement;

/// Detailed recurrence claims plus their transcript-visible component sum.
///
/// The batch claims are proof metadata needed by each independent cumulative
/// column. `component_sum` is the one value mixed in extension slot 28.  Both
/// values are owned here so verifier construction never borrows prover state.
pub const Claim = struct {
    descriptor: components.Descriptor,
    batch_sums: [batch_count]QM31,
    component_sum: QM31,

    pub fn canonical(
        authority: components.CallerConstruction,
        batch_sums: [batch_count]QM31,
    ) InitError!Claim {
        const result = Claim{
            .descriptor = authority.descriptor,
            .batch_sums = batch_sums,
            .component_sum = sumBatchClaims(&batch_sums),
        };
        try result.validate(authority);
        return result;
    }

    pub fn init(
        authority: components.CallerConstruction,
        batch_sums: [batch_count]QM31,
        component_sum: QM31,
    ) InitError!Claim {
        const result = Claim{
            .descriptor = authority.descriptor,
            .batch_sums = batch_sums,
            .component_sum = component_sum,
        };
        try result.validate(authority);
        return result;
    }

    pub fn validate(
        self: Claim,
        authority: components.CallerConstruction,
    ) InitError!void {
        try self.descriptor.validate();
        if (!std.meta.eql(self.descriptor, authority.descriptor)) {
            return error.ClaimDescriptorMismatch;
        }
        if (!sumBatchClaims(&self.batch_sums).eql(self.component_sum)) {
            return error.ComponentClaimMismatch;
        }
        if (self.descriptor.n_rows == 0) {
            for (self.batch_sums) |sum| {
                if (!sum.isZero()) return error.NonZeroEmptyClaim;
            }
        }
    }

    pub fn total(self: Claim) QM31 {
        return self.component_sum;
    }
};

/// Public constraint positions consumed by random-coefficient composition.
pub const ConstraintOrder = struct {
    pub const direct_start: usize = 0;
    pub const interaction_start: usize = direct_start + direct_constraint_count;
    pub const end: usize = interaction_start + interaction_constraint_count;

    pub fn interactionBatch(batch: usize) usize {
        std.debug.assert(batch < batch_count);
        return interaction_start + batch;
    }
};

pub const Evaluation = struct {
    values: [constraint_count]QM31,

    pub fn allZero(self: *const Evaluation) bool {
        for (self.values) |value| if (!value.isZero()) return false;
        return true;
    }
};

pub const CallerComponent = struct {
    authority: components.CallerConstruction,
    placement: Placement,
    relations: *const Relations,
    claim: Claim,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        authority: components.CallerConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!CallerComponent {
        return init(authority, claim, placement, relations);
    }

    pub fn initProver(
        authority: components.CallerConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!CallerComponent {
        return init(authority, claim, placement, relations);
    }

    fn init(
        authority: components.CallerConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!CallerComponent {
        try authority.validate();
        try claim.validate(authority);
        try placement.validate();
        try validateLogSize(authority.descriptor.log_size);
        return .{
            .authority = authority,
            .placement = placement,
            .relations = relations,
            .claim = claim,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.profile_identity = .riscv_guest_poseidon2_caller_v1;
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        component.composition_work_profile = compositionWorkProfileErased;
        component.oods_work_profile = oodsWorkProfileErased;
        return component;
    }

    fn oodsWorkProfileErased(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
        source: *const composition_work_support.ComponentProfile,
    ) anyerror!composition_work_support.OodsComponentProfile {
        _ = allocator;
        const self: *const @This() = @ptrCast(@alignCast(context));
        return composition_work_support.oodsProfile(
            source,
            self.claim.descriptor.log_size,
            max_log_degree_bound,
            2 * batch_count,
            true,
        );
    }

    fn compositionWorkProfileErased(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work_support.ComponentProfile {
        _ = allocator;
        const self: *const @This() = @ptrCast(@alignCast(context));
        const Scalar = composition_work_support.Scalar;
        const relations = composition_work_support.GuestRelations.init();
        const main = composition_work_support.values(main_column_count, 0);
        const current = composition_work_support.values(batch_count, 400);
        const previous = composition_work_support.values(batch_count, 500);
        const claims = composition_work_support.values(batch_count, 600);
        const selectors = composition_work_support.values(2, 900);
        var expression: composition_work_support.FieldOperations = undefined;
        try composition_work_support.begin(&expression);
        defer composition_work_support.end();
        _ = direct_constraints.evaluateCallerGeneric(
            Scalar,
            main,
            selectors[1],
        );
        const pairs = try interaction_plan.callerRowPairsGeneric(
            Scalar,
            &main,
            &relations,
        );
        for (pairs, current, previous, claims) |pair, sum, prior, claim| {
            _ = logup.pairConstraintGeneric(
                Scalar,
                sum,
                prior,
                selectors[0],
                claim,
                pair,
            );
        }
        return composition_work_support.profile(
            .guest_caller,
            "riscv-guest-poseidon2-caller-row-v1",
            self.maxConstraintLogDegreeBound(),
            self.nConstraints(),
            expression,
            // The prepared caller folds direct and interaction groups
            // independently, then adds the two group folds once.
            .{ .additions = 1 },
            &.{
                @as(u64, self.claim.descriptor.log_size),
                @as(u64, main_column_count),
                @as(u64, event_count),
                @as(u64, batch_count),
            },
        );
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

    pub fn nConstraints(_: *const @This()) usize {
        return constraint_count;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.claim.descriptor.log_size + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) Error!u8 {
        if (index < direct_constraint_count) {
            return direct_constraints.callerConstraintDegreeBound(index);
        }
        if (index < constraint_count) return maximum_constraint_degree;
        return error.InvalidConstraintIndex;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, preprocessed_column_count);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.claim.descriptor.log_size);

        const main = try allocator.alloc(u32, main_column_count);
        errdefer allocator.free(main);
        @memset(main, self.claim.descriptor.log_size);

        const interaction_columns = try allocator.alloc(u32, interaction_column_count);
        errdefer allocator.free(interaction_columns);
        @memset(interaction_columns, self.claim.descriptor.log_size);

        const trees = try allocator.dupe([]u32, &.{
            preprocessed,
            main,
            interaction_columns,
        });
        return core_air_components.TraceLogDegreeBounds.initOwned(trees);
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.maxConstraintLogDegreeBound()) {
            return error.InvalidProofShape;
        }
        const preprocessed = try component_mask.currentPointColumns(
            allocator,
            preprocessed_column_count,
            point,
        );
        errdefer component_mask.freePointColumns(allocator, preprocessed);
        const main = try component_mask.currentPointColumns(allocator, main_column_count, point);
        errdefer component_mask.freePointColumns(allocator, main);
        const interaction_columns = try component_mask.currentAndPreviousPointColumns(
            allocator,
            interaction_column_count,
            point,
            logup.prevRowPoint(max_log_degree_bound, point),
        );
        errdefer component_mask.freePointColumns(allocator, interaction_columns);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction_columns,
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
        if (max_log_degree_bound < self.maxConstraintLogDegreeBound() or
            mask.items.len < 3)
        {
            return error.InvalidProofShape;
        }
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const interaction_columns = mask.items[2];
        const main_end = self.mainEnd();
        const interaction_end = self.interactionEnd();
        if (preprocessed.len <= @max(
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        ) or main.len < main_end or interaction_columns.len < interaction_end) {
            return error.InvalidProofShape;
        }
        const is_first_column = preprocessed[self.placement.is_first_col_idx];
        const is_active_column = preprocessed[self.placement.is_active_col_idx];
        if (is_first_column.len < 1 or is_active_column.len < 1) {
            return error.InvalidProofShape;
        }

        var sampled_main: [main_column_count]QM31 = undefined;
        for (
            &sampled_main,
            main[self.placement.main_col_offset..main_end],
        ) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current: [batch_count]QM31 = undefined;
        var previous: [batch_count]QM31 = undefined;
        for (0..batch_count) |batch| {
            const offset = self.placement.interaction_col_offset + 4 * batch;
            current[batch] = try component_mask.sampledSecure(interaction_columns, offset, 0);
            previous[batch] = try component_mask.sampledSecure(interaction_columns, offset, 1);
        }

        const evaluation = try self.evaluateRow(
            sampled_main,
            current,
            previous,
            is_first_column[0],
            is_active_column[0],
        );
        const folded_point = point.repeatedDouble(
            max_log_degree_bound - self.claim.descriptor.log_size,
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.claim.descriptor.log_size).coset(),
            folded_point,
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
        if (trace_data.polys.items.len != 3) return error.InvalidProofShape;
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const interaction_columns = trace_data.polys.items[2];
        const main_end = self.mainEnd();
        const interaction_end = self.interactionEnd();
        if (preprocessed.len <= @max(
            self.placement.is_first_col_idx,
            self.placement.is_active_col_idx,
        ) or main.len < main_end or interaction_columns.len < interaction_end) {
            return error.InvalidProofShape;
        }

        const eval_log_size = self.maxConstraintLogDegreeBound();
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const selector_polys = .{
            preprocessed[self.placement.is_first_col_idx],
            preprocessed[self.placement.is_active_col_idx],
        };
        var owned_count: usize = 0;
        inline for (selector_polys) |poly| {
            if (try prepared_support.sourceNeedsExtension(
                poly,
                self.claim.descriptor.log_size,
                eval_log_size,
            )) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }
        for (main[self.placement.main_col_offset..main_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(
                poly,
                self.claim.descriptor.log_size,
                eval_log_size,
            )) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }
        for (interaction_columns[self.placement.interaction_col_offset..interaction_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(
                poly,
                self.claim.descriptor.log_size,
                eval_log_size,
            )) {
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
        var evaluations: [PreparedDomainState.source_count][]const M31 = undefined;
        var source: usize = 0;
        inline for (selector_polys) |poly| {
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
        for (main[self.placement.main_col_offset..main_end]) |poly| {
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
        for (interaction_columns[self.placement.interaction_col_offset..interaction_end]) |poly| {
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
        std.debug.assert(source == evaluations.len);
        std.debug.assert(owned_initialized == owned_count);
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
            PreparedDomainState.denominator_count,
            self.claim.descriptor.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resources(
            eval_size,
            0,
            owned_count,
            @sizeOf(PreparedDomainState),
        );
        const state = try allocator.create(PreparedDomainState);
        errdefer allocator.destroy(state);
        const accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = constraint_count }},
        );
        defer allocator.free(accumulators);
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

    fn runPreparedDomain(
        self: *const @This(),
        state: *PreparedDomainState,
        task_context: *prover_task_graph.TaskContext,
    ) !void {
        const evaluations = &state.evaluations;
        const main_start: usize = preprocessed_column_count;
        const interaction_start = main_start + main_column_count;
        const denominator_shift: std.math.Log2Int(usize) =
            @intCast(self.claim.descriptor.log_size);
        const column_accumulator = &state.column_accumulator;
        const powers = column_accumulator.random_coeff_powers;

        for (0..state.eval_size) |row| {
            if ((row & (PreparedDomainState.cancellation_poll_rows - 1)) == 0 and
                task_context.isCancelled())
            {
                return;
            }
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.claim.descriptor.log_size,
                state.eval_log_size,
            );
            var sampled_main: [main_column_count]QM31 = undefined;
            for (&sampled_main, evaluations[main_start..][0..main_column_count]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            var folded = foldDirectPrepared(
                &sampled_main,
                QM31.fromBase(evaluations[1][row]),
                powers,
            );
            var current: [batch_count]QM31 = undefined;
            var previous: [batch_count]QM31 = undefined;
            for (0..batch_count) |batch| {
                const offset = interaction_start + 4 * batch;
                current[batch] = component_mask.secureAt(evaluations[offset..][0..4], row);
                previous[batch] = component_mask.secureAt(
                    evaluations[offset..][0..4],
                    previous_row,
                );
            }
            folded = folded.add(try component_interaction.fold(
                &sampled_main,
                &current,
                &previous,
                QM31.fromBase(evaluations[0][row]),
                &self.claim.batch_sums,
                self.relations,
                powers,
            ));
            column_accumulator.accumulate(
                row,
                folded.mulM31(
                    state.denominator_inv[row >> denominator_shift],
                ),
            );
        }
    }

    /// Allocation-free row composition shared by verifier and prover paths.
    pub fn evaluateRow(
        self: *const @This(),
        main: [main_column_count]QM31,
        current: [batch_count]QM31,
        previous: [batch_count]QM31,
        is_first: QM31,
        is_active: QM31,
    ) Error!Evaluation {
        const direct = direct_constraints.evaluateCaller(main, is_active);
        const lookup = try component_interaction.evaluate(
            &main,
            is_first,
            current,
            previous,
            self.claim.batch_sums,
            self.relations,
        );
        var result: Evaluation = undefined;
        @memcpy(
            result.values[ConstraintOrder.direct_start..ConstraintOrder.interaction_start],
            &direct,
        );
        @memcpy(
            result.values[ConstraintOrder.interaction_start..ConstraintOrder.end],
            &lookup,
        );
        return result;
    }

    fn mainEnd(self: *const @This()) usize {
        return self.placement.main_col_offset + main_column_count;
    }

    fn interactionEnd(self: *const @This()) usize {
        return self.placement.interaction_col_offset + interaction_column_count;
    }
};

fn foldDirectPrepared(
    main: *const [main_column_count]QM31,
    is_active: QM31,
    powers: []const QM31,
) QM31 {
    const constraints = direct_constraints.evaluateCaller(main.*, is_active);
    var folded = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        folded = folded.add(
            powers[powers.len - 1 - index].mul(constraint),
        );
    }
    return folded;
}

const PreparedDomainState = struct {
    const cancellation_poll_rows: usize = 4096;
    const source_count: usize =
        preprocessed_column_count + main_column_count + interaction_column_count;
    const denominator_count: usize = 2;

    comptime {
        if (cancellation_poll_rows == 0 or
            cancellation_poll_rows > 4096 or
            !std.math.isPowerOfTwo(cancellation_poll_rows))
        {
            @compileError("caller cancellation polling must be power-of-two tiles of at most 4,096 rows");
        }
    }

    allocator: std.mem.Allocator,
    component: *const CallerComponent,
    evaluations: [source_count][]const M31,
    owned_buffers: [][]M31,
    denominator_inv: [denominator_count]M31,
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
        for (self.owned_buffers) |values| allocator.free(values);
        allocator.free(self.owned_buffers);
        allocator.destroy(self);
    }
};

fn validateLogSize(log_size: u32) InitError!void {
    if (log_size < components.minimum_log_size) return error.InvalidTraceLogSize;
    const evaluation_log_size = std.math.add(u32, log_size, 1) catch
        return error.InvalidTraceLogSize;
    if (evaluation_log_size >= circle.M31_CIRCLE_LOG_ORDER) {
        return error.InvalidTraceLogSize;
    }
}

fn sumBatchClaims(claims: *const [batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (claims) |claim| result = result.add(claim);
    return result;
}

comptime {
    if (preprocessed_column_count != 2 or main_column_count != 286 or
        event_count != 153 or batch_count != 77 or
        interaction_column_count != 308)
    {
        @compileError("caller proof-component geometry drifted");
    }
    if (direct_constraint_count != 417 or constraint_count != 494 or
        ConstraintOrder.end != constraint_count or maximum_constraint_degree != 3)
    {
        @compileError("caller proof-component constraint identity drifted");
    }
    if (relation_challenges.relation_count != 13) {
        @compileError("caller proof component must consume the shared 12+1 challenge schedule");
    }
}
