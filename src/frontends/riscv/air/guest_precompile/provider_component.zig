//! Stwo prover/verifier adapter for the authenticated guest Poseidon2 provider.
//!
//! The component keeps compatibility-v1's 445-column permutation witness but
//! not its legacy narrow shell.  Direct constraints, the four provider events,
//! and both pairs-batched cumulative columns share one fixed row evaluator.

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
const prover_work_pool = prover_engine.work_pool;
const composition_work_support = @import("../composition_work_support.zig");
const logup = @import("../logup.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");
const components = @import("component_registry.zig");
const direct = @import("direct_constraints.zig");
const guest_interaction = @import("interaction.zig");
const interaction_plan = @import("interaction_plan.zig");
const challenges = @import("relation_challenges.zig");
const provider_support = @import("provider_component_support.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const Relations = challenges.Poseidon2V1Relations;

pub const preprocessed_column_count: usize = 2;
pub const main_column_count: usize = direct.provider_main_column_count;
pub const interaction_column_count: usize = components.provider_interaction_columns;
pub const event_count: usize = components.provider_event_count;
pub const batch_count: usize = components.provider_batch_count;
pub const direct_constraint_count: usize = direct.provider_constraint_count;
pub const interaction_constraint_count: usize = batch_count;
pub const constraint_count: usize =
    direct_constraint_count + interaction_constraint_count;
pub const maximum_constraint_degree: u8 = direct.maximum_constraint_degree;
pub const row_evaluation_allocation_count: usize = 0;
/// Reviewed Debug-safe stack certificate for the 445-input/875-output
/// Poseidon2 provider row. This wide kernel carries its own reservation so the
/// generic 256 KiB evaluator bound remains available to narrower components.
pub const prepared_row_stack_bytes: usize = 1024 * 1024;
const prepared_source_count = preprocessed_column_count + main_column_count +
    interaction_column_count;

pub const ConstraintOrder = struct {
    pub const direct_start: usize = 0;
    pub const interaction_start: usize = direct_constraint_count;
    pub const end: usize = constraint_count;

    pub fn interaction(batch: usize) usize {
        std.debug.assert(batch < batch_count);
        return interaction_start + batch;
    }
};

/// Authenticated component geometry plus the two physical cumulative claims.
/// Batch zero is structurally coefficient-zero and therefore has exact claim 0.
pub const Claim = struct {
    descriptor: components.Descriptor,
    batch_sums: [batch_count]QM31,
    component_sum: QM31,

    pub fn canonical(
        authority: components.ProviderConstruction,
        batch_sums: [batch_count]QM31,
    ) InitError!Claim {
        const result = Claim{
            .descriptor = authority.descriptor,
            .batch_sums = batch_sums,
            .component_sum = sumBatchClaims(batch_sums),
        };
        try result.validate(authority);
        return result;
    }

    pub fn init(
        authority: components.ProviderConstruction,
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
        authority: components.ProviderConstruction,
    ) InitError!void {
        try authority.validate();
        try self.descriptor.validate();
        if (!std.meta.eql(self.descriptor, authority.descriptor))
            return error.ClaimDescriptorMismatch;
        if (!sumBatchClaims(self.batch_sums).eql(self.component_sum))
            return error.ComponentClaimMismatch;
        if (!self.batch_sums[0].isZero()) return error.NonzeroLegacyBatchClaim;
        if (self.descriptor.n_rows == 0) for (self.batch_sums) |sum| {
            if (!sum.isZero()) return error.NonZeroEmptyClaim;
        };
    }

    pub fn total(self: Claim) QM31 {
        return self.component_sum;
    }
};

/// Global tree offsets.  The two provider selectors must remain adjacent and
/// ordered as `is_first,is_active`; main and interaction blocks are contiguous.
pub const Placement = struct {
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,

    pub fn validate(self: Placement) InitError!void {
        const active = std.math.add(usize, self.is_first_col_idx, 1) catch
            return error.InvalidColumnPlacement;
        if (self.is_active_col_idx != active)
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

pub const InitError = components.Error || error{
    ClaimDescriptorMismatch,
    ComponentClaimMismatch,
    InvalidColumnPlacement,
    InvalidTraceLogSize,
    NonZeroEmptyClaim,
    NonzeroLegacyBatchClaim,
};

pub const Evaluation = struct {
    values: [constraint_count]QM31,

    pub fn allZero(self: Evaluation) bool {
        for (self.values) |value| if (!value.isZero()) return false;
        return true;
    }
};

pub const ProviderComponent = struct {
    authority: components.ProviderConstruction,
    claim: Claim,
    placement: Placement,
    relations: *const Relations,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        authority: components.ProviderConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!ProviderComponent {
        return init(authority, claim, placement, relations);
    }

    pub fn initProver(
        authority: components.ProviderConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!ProviderComponent {
        return init(authority, claim, placement, relations);
    }

    fn init(
        authority: components.ProviderConstruction,
        claim: Claim,
        placement: Placement,
        relations: *const Relations,
    ) InitError!ProviderComponent {
        try claim.validate(authority);
        try placement.validate();
        try validateTraceLogSize(authority.descriptor.log_size);
        return .{
            .authority = authority,
            .claim = claim,
            .placement = placement,
            .relations = relations,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.profile_identity = .riscv_guest_poseidon2_provider_v1;
        result.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        result.composition_work_profile = compositionWorkProfileErased;
        result.oods_work_profile = oodsWorkProfileErased;
        return result;
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
            self.claim.descriptor.log_size,
            max_log_degree_bound,
            2 * batch_count,
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
        const relations = composition_work_support.GuestRelations.init();
        const main = composition_work_support.values(main_column_count, 0);
        const current = composition_work_support.values(batch_count, 500);
        const previous = composition_work_support.values(batch_count, 520);
        const claims = composition_work_support.values(batch_count, 540);
        const selectors = composition_work_support.values(2, 900);
        var expression: composition_work_support.FieldOperations = undefined;
        try composition_work_support.begin(&expression);
        defer composition_work_support.end();
        _ = direct.evaluateProviderGeneric(Scalar, main, selectors[1]);
        const pairs = try interaction_plan.providerRowPairsGeneric(
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
            .guest_provider,
            "riscv-guest-poseidon2-provider-row-v1",
            self.maxConstraintLogDegreeBound(),
            self.nConstraints(),
            expression,
            .{},
            &.{
                @as(u64, self.claim.descriptor.log_size),
                @as(u64, main_column_count),
                @as(u64, event_count),
                @as(u64, batch_count),
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
        return constraint_count;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.claim.descriptor.log_size + 1;
    }

    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index < direct_constraint_count)
            return direct.providerConstraintDegreeBound(index);
        if (index < constraint_count) return maximum_constraint_degree;
        return error.InvalidConstraintIndex;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const log_size = self.claim.descriptor.log_size;
        const preprocessed = try allocator.dupe(
            u32,
            &.{ log_size, log_size },
        );
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, main_column_count);
        errdefer allocator.free(main);
        @memset(main, log_size);
        const interaction = try allocator.alloc(u32, interaction_column_count);
        errdefer allocator.free(interaction);
        @memset(interaction, log_size);
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
        if (max_log_degree_bound < self.maxConstraintLogDegreeBound())
            return error.InvalidProofShape;
        const preprocessed = try pointColumns(
            allocator,
            preprocessed_column_count,
            &.{point},
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try pointColumns(allocator, main_column_count, &.{point});
        errdefer freePointColumns(allocator, main);
        const interaction = try pointColumns(
            allocator,
            interaction_column_count,
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
        const log_size = self.claim.descriptor.log_size;
        if (max_log_degree_bound < self.maxConstraintLogDegreeBound() or
            mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main_mask = mask.items[1];
        const interaction_mask = mask.items[2];
        const main_end = try checkedEnd(
            self.placement.main_col_offset,
            main_column_count,
        );
        const interaction_end = try checkedEnd(
            self.placement.interaction_col_offset,
            interaction_column_count,
        );
        if (preprocessed.len <= self.placement.is_active_col_idx or
            preprocessed[self.placement.is_first_col_idx].len != 1 or
            preprocessed[self.placement.is_active_col_idx].len != 1 or
            main_mask.len < main_end or interaction_mask.len < interaction_end)
        {
            return error.InvalidProofShape;
        }
        const main = try sampleMain(
            main_mask[self.placement.main_col_offset..main_end],
        );
        var current: [batch_count]QM31 = undefined;
        var previous: [batch_count]QM31 = undefined;
        try sampleInteraction(
            interaction_mask,
            self.placement.interaction_col_offset,
            &current,
            &previous,
        );
        const evaluation = try self.evaluateRow(
            &main,
            current,
            previous,
            preprocessed[self.placement.is_first_col_idx][0],
            preprocessed[self.placement.is_active_col_idx][0],
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - log_size),
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
        var task_context = serialTaskContext(prepared.context, &cancellation);
        try prepared.run(&task_context);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace_data.polys.items.len != 3) return error.InvalidProofShape;
        const log_size = self.claim.descriptor.log_size;
        const eval_log_size = std.math.add(u32, log_size, 1) catch
            return error.InvalidProofShape;
        if (log_size == 0 or eval_log_size >= circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidProofShape;
        const trace_size = @as(usize, 1) << @intCast(log_size);
        if (@as(usize, self.claim.descriptor.n_rows) > trace_size)
            return error.InvalidProofShape;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();

        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const interaction = trace_data.polys.items[2];
        const main_end = try checkedEnd(
            self.placement.main_col_offset,
            main_column_count,
        );
        const interaction_end = try checkedEnd(
            self.placement.interaction_col_offset,
            interaction_column_count,
        );
        if (preprocessed.len <= self.placement.is_active_col_idx or
            main.len < main_end or interaction.len < interaction_end)
        {
            return error.InvalidProofShape;
        }

        var owned_count: usize = 0;
        const selectors = .{
            preprocessed[self.placement.is_first_col_idx],
            preprocessed[self.placement.is_active_col_idx],
        };
        inline for (selectors) |poly| if (try prepared_support.sourceNeedsExtension(
            poly,
            log_size,
            eval_log_size,
        )) {
            owned_count = try checkedAdd(owned_count, 1);
        };
        for (main[self.placement.main_col_offset..main_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, log_size, eval_log_size))
                owned_count = try checkedAdd(owned_count, 1);
        }
        for (interaction[self.placement.interaction_col_offset..interaction_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, log_size, eval_log_size))
                owned_count = try checkedAdd(owned_count, 1);
        }

        var evaluations: [prepared_source_count][]const M31 = undefined;
        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var owned_initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..owned_initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        var source: usize = 0;
        inline for (selectors) |poly| {
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
        for (interaction[self.placement.interaction_col_offset..interaction_end]) |poly| {
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
            log_size,
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

    pub fn evaluateRow(
        self: *const @This(),
        main: []const QM31,
        current: [batch_count]QM31,
        previous: [batch_count]QM31,
        is_first: QM31,
        is_active: QM31,
    ) !Evaluation {
        if (main.len != main_column_count) return error.InvalidProofShape;
        const direct_constraints = direct.evaluateProvider(
            main[0..main_column_count].*,
            is_active,
        );
        const interaction_constraints = try guest_interaction
            .providerInteractionConstraints(
            main,
            is_first,
            current,
            previous,
            self.claim.batch_sums,
            self.relations,
        );
        var result: Evaluation = undefined;
        @memcpy(result.values[0..direct_constraint_count], &direct_constraints);
        @memcpy(
            result.values[ConstraintOrder.interaction_start..],
            &interaction_constraints,
        );
        return result;
    }
};

const PreparedDomainState = struct {
    const cancellation_poll_rows: usize = 4096;
    const denominator_count: usize = 2;

    allocator: std.mem.Allocator,
    component: *const ProviderComponent,
    evaluations: [prepared_source_count][]const M31,
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
        const main_start: usize = preprocessed_column_count;
        const interaction_start = main_start + main_column_count;
        const powers = self.column_accumulator.random_coeff_powers;
        const denominator_shift: std.math.Log2Int(usize) =
            @intCast(self.component.claim.descriptor.log_size);
        for (0..self.eval_size) |row| {
            if ((row & (cancellation_poll_rows - 1)) == 0 and
                task_context.isCancelled()) return;
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.component.claim.descriptor.log_size,
                self.eval_log_size,
            );
            const main = readMain(
                self.evaluations[main_start..][0..main_column_count],
                row,
            );
            var current: [batch_count]QM31 = undefined;
            var previous: [batch_count]QM31 = undefined;
            readInteraction(
                &self.evaluations,
                interaction_start,
                row,
                previous_row,
                &current,
                &previous,
            );
            const is_first = QM31.fromBase(self.evaluations[0][row]);
            const is_active = QM31.fromBase(self.evaluations[1][row]);
            const direct_evaluation = direct.evaluateProvider(main, is_active);
            const interaction_evaluation = try guest_interaction
                .providerInteractionConstraints(
                &main,
                is_first,
                current,
                previous,
                self.component.claim.batch_sums,
                self.component.relations,
            );
            var folded = QM31.zero();
            for (direct_evaluation, 0..) |constraint, index| {
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            for (interaction_evaluation, 0..) |constraint, index| {
                const constraint_index = direct_constraint_count + index;
                folded = folded.add(powers[
                    powers.len - 1 - constraint_index
                ].mul(constraint));
            }
            self.column_accumulator.accumulate(
                row,
                folded.mulM31(
                    self.denominator_inv[row >> denominator_shift],
                ),
            );
        }
    }

    comptime {
        if (cancellation_poll_rows == 0 or
            cancellation_poll_rows > 4096 or
            !std.math.isPowerOfTwo(cancellation_poll_rows))
        {
            @compileError("provider cancellation tile must be a power of two <=4096");
        }
    }
};

fn checkedEnd(offset: usize, count: usize) !usize {
    return std.math.add(usize, offset, count) catch error.InvalidProofShape;
}

fn checkedAdd(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch
        error.ResourceReservationOverflow;
}

fn validateTraceLogSize(log_size: u32) InitError!void {
    const eval_log_size = std.math.add(u32, log_size, 1) catch
        return error.InvalidTraceLogSize;
    if (log_size < components.minimum_log_size or
        eval_log_size >= circle.M31_CIRCLE_LOG_ORDER)
    {
        return error.InvalidTraceLogSize;
    }
}

fn sumBatchClaims(batch_sums: [batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (batch_sums) |sum| result = result.add(sum);
    return result;
}

const serialTaskContext = provider_support.serialTaskContext;
const pointColumns = provider_support.pointColumns;
const freePointColumns = provider_support.freePointColumns;
const sampleMain = provider_support.sampleMain;
const sampleInteraction = provider_support.sampleInteraction;
const sampledSecure = provider_support.sampledSecure;
const readMain = provider_support.readMain;
const readInteraction = provider_support.readInteraction;

comptime {
    if (preprocessed_column_count != 2 or main_column_count != 445 or
        interaction_column_count != 8 or event_count != 4 or batch_count != 2 or
        direct_constraint_count != 875 or constraint_count != 877 or
        ConstraintOrder.end != constraint_count or maximum_constraint_degree != 3 or
        challenges.relation_count != 13)
    {
        @compileError("guest provider proof-component geometry drifted");
    }
    if (components.provider_events[0].numerator != .zero_in_guest_mode or
        components.provider_events[1].numerator != .zero_in_guest_mode or
        components.provider_events[2].numerator != .zero_in_guest_mode or
        components.provider_events[3].numerator != .positive_active)
    {
        @compileError("guest provider authenticated coefficient program drifted");
    }
}
