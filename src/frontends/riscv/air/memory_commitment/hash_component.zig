//! Prover/verifier adapter for the exact Merkle-node and Poseidon2 AIRs.

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
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const work_pool = @import("stwo_prover_engine").work_pool;
const composition_work_support = @import("../composition_work_support.zig");
const prepared_parallel = @import("../prepared_parallel.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const merkle_node = @import("merkle_node.zig");
const prepared_support = @import("hash_component_prepared_support.zig");
const poseidon2_air = @import("poseidon2_air.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const N_POSEIDON_SHELL_CONSTRAINTS: usize = 3;
pub const N_POSEIDON_COMPONENT_CONSTRAINTS: usize =
    poseidon2_air.N_CONSTRAINTS + N_POSEIDON_SHELL_CONSTRAINTS + poseidon2_air.N_SUMS;
/// Stark-V general mode owns the canonical 430 direct constraints and two
/// pairs-batched LogUp recurrences. It intentionally omits only the three
/// RISC-V sparse-memory shell constraints.
pub const N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS: usize =
    poseidon2_air.N_CONSTRAINTS + poseidon2_air.N_SUMS;

pub const Kind = enum { merkle, poseidon2 };
pub const PoseidonShell = enum {
    /// Sparse-memory ownership: bind the committed enabler to an external
    /// activity selector and prohibit wide/atomic-IO modes.
    narrow_memory,
    /// Stark-V's generated shared provider: the committed enabler and mode
    /// flags are already constrained by the canonical Poseidon2 AIR.
    universal,
};

/// Single authority for the verifier-visible constraint count of a hash
/// component.  Recursive schedule construction calls this rather than
/// transcribing the Poseidon shell arithmetic a second time.
pub fn constraintCount(kind: Kind, poseidon_shell: PoseidonShell) usize {
    return switch (kind) {
        .merkle => merkle_node.N_CONSTRAINTS,
        .poseidon2 => switch (poseidon_shell) {
            .narrow_memory => N_POSEIDON_COMPONENT_CONSTRAINTS,
            .universal => N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS,
        },
    };
}
pub const PREPARED_DENOMINATOR_COUNT: usize = 2;
pub const PARALLEL_DOMAIN_LOG_SIZE: u32 = 12;
/// Reviewed cross-host stack certificate for the generated Merkle/Poseidon2
/// row evaluator. Linux x86_64 Debug code generation exceeds the generic
/// prepared-row bound, so this wide component carries a local reservation.
pub const prepared_row_stack_bytes: usize = 1024 * 1024;

pub const PreparedParallelTelemetrySnapshot = prepared_parallel.TelemetrySnapshot;
var prepared_parallel_telemetry: prepared_parallel.Telemetry = .{};

pub fn preparedParallelTelemetrySnapshot() PreparedParallelTelemetrySnapshot {
    return prepared_parallel_telemetry.snapshot();
}

pub const HashComponent = struct {
    kind: Kind,
    log_size: u32,
    n_rows: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    poseidon_shell: PoseidonShell = .narrow_memory,
    merkle_claims: [merkle_node.N_SUMS]QM31 = .{QM31.zero()} ** merkle_node.N_SUMS,
    poseidon_claims: [poseidon2_air.N_SUMS]QM31 = .{QM31.zero()} ** poseidon2_air.N_SUMS,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        component.composition_work_profile = compositionWorkProfileErased;
        component.oods_work_profile = oodsWorkProfileErased;
        if (self.kind == .poseidon2 and self.poseidon_shell == .narrow_memory) {
            component.backend_composition_capability = hash_component_backend.capability();
        }
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
        const partial_evaluations: usize = switch (self.kind) {
            .merkle => 2 * merkle_node.N_SUMS,
            .poseidon2 => 2 * poseidon2_air.N_SUMS,
        };
        return composition_work_support.oodsProfile(
            source,
            self.log_size,
            max_log_degree_bound,
            partial_evaluations,
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
        const is_first = composition_work_support.values(1, 900)[0];
        const is_active = composition_work_support.values(1, 901)[0];
        var expression: composition_work_support.FieldOperations = undefined;
        switch (self.kind) {
            .merkle => {
                const main = composition_work_support.values(
                    merkle_node.N_MAIN_COLUMNS,
                    0,
                );
                const sums = composition_work_support.values(merkle_node.N_SUMS, 32);
                const previous = composition_work_support.values(merkle_node.N_SUMS, 48);
                const claims = composition_work_support.values(merkle_node.N_SUMS, 64);
                try composition_work_support.begin(&expression);
                defer composition_work_support.end();
                _ = merkle_node.evaluateGeneric(
                    Scalar,
                    main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    claims,
                    &relations,
                );
                return composition_work_support.profile(
                    .merkle,
                    "riscv-merkle-node-evaluate-generic-v1",
                    self.maxConstraintLogDegreeBound(),
                    self.nConstraints(),
                    expression,
                    .{},
                    &.{
                        @as(u64, self.log_size),
                        @as(u64, merkle_node.N_MAIN_COLUMNS),
                        @as(u64, merkle_node.N_SUMS),
                    },
                );
            },
            .poseidon2 => {
                const main = composition_work_support.values(
                    poseidon2_air.N_MAIN_COLUMNS,
                    0,
                );
                const sums = composition_work_support.values(poseidon2_air.N_SUMS, 500);
                const previous = composition_work_support.values(poseidon2_air.N_SUMS, 520);
                const claims = composition_work_support.values(poseidon2_air.N_SUMS, 540);
                try composition_work_support.begin(&expression);
                defer composition_work_support.end();
                switch (self.poseidon_shell) {
                    .narrow_memory => _ = poseidonConstraintsGeneric(
                        Scalar,
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        claims,
                        &relations,
                    ),
                    .universal => _ = poseidonGeneralConstraintsGeneric(
                        Scalar,
                        main,
                        is_first,
                        sums,
                        previous,
                        claims,
                        &relations,
                    ),
                }
                return composition_work_support.profile(
                    .poseidon2,
                    switch (self.poseidon_shell) {
                        .narrow_memory => "riscv-poseidon2-narrow-evaluate-generic-v1",
                        .universal => "riscv-poseidon2-general-evaluate-generic-v1",
                    },
                    self.maxConstraintLogDegreeBound(),
                    self.nConstraints(),
                    expression,
                    .{},
                    &.{
                        @as(u64, self.log_size),
                        @as(u64, @intFromEnum(self.poseidon_shell)),
                        @as(u64, poseidon2_air.N_MAIN_COLUMNS),
                        @as(u64, poseidon2_air.N_SUMS),
                    },
                );
            },
        }
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

    pub fn nConstraints(self: *const @This()) usize {
        return constraintCount(self.kind, self.poseidon_shell);
    }

    pub fn nPreprocessedColumns(self: *const @This()) usize {
        return @as(usize, 1) + @intFromBool(self.usesActiveSelector());
    }

    fn usesActiveSelector(self: *const @This()) bool {
        return self.kind == .merkle or self.poseidon_shell == .narrow_memory;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + switch (self.kind) {
            .merkle => @as(u32, 1),
            .poseidon2 => @as(u32, 1),
        };
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, self.nPreprocessedColumns());
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, nMainColumns(self.kind));
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(u32, nInteractionColumns(self.kind));
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main, interaction }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try currentPointColumns(
            allocator,
            self.nPreprocessedColumns(),
            point,
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, nMainColumns(self.kind), point);
        errdefer freePointColumns(allocator, main);
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const interaction = try currentAndPreviousPointColumns(
            allocator,
            nInteractionColumns(self.kind),
            point,
            previous_point,
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
        if (self.usesActiveSelector()) return allocator.dupe(
            usize,
            &.{ self.is_first_col_idx, self.is_active_col_idx },
        );
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
        const main_mask = mask.items[1];
        const interaction_mask = mask.items[2];
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        if (preprocessed.len <= self.is_first_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            (self.usesActiveSelector() and
                (preprocessed.len <= self.is_active_col_idx or
                    preprocessed[self.is_active_col_idx].len < 1)) or
            main_mask.len < self.main_col_offset + n_main or
            interaction_mask.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        const is_first = preprocessed[self.is_first_col_idx][0];

        switch (self.kind) {
            .merkle => {
                const is_active = preprocessed[self.is_active_col_idx][0];
                const main = try sampleMain(
                    merkle_node.N_MAIN_COLUMNS,
                    main_mask,
                    self.main_col_offset,
                );
                var sums: [merkle_node.N_SUMS]QM31 = undefined;
                var previous: [merkle_node.N_SUMS]QM31 = undefined;
                try sampleInteraction(
                    merkle_node.N_SUMS,
                    interaction_mask,
                    self.interaction_col_offset,
                    &sums,
                    &previous,
                );
                const constraints = merkle_node.evaluate(
                    main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.merkle_claims,
                    self.relations,
                );
                for (constraints) |constraint| accumulator.accumulate(constraint.mul(denominator_inv));
            },
            .poseidon2 => {
                const main = try sampleMain(
                    poseidon2_air.N_MAIN_COLUMNS,
                    main_mask,
                    self.main_col_offset,
                );
                var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                try sampleInteraction(
                    poseidon2_air.N_SUMS,
                    interaction_mask,
                    self.interaction_col_offset,
                    &sums,
                    &previous,
                );
                switch (self.poseidon_shell) {
                    .narrow_memory => {
                        const constraints = poseidonConstraints(
                            main,
                            preprocessed[self.is_active_col_idx][0],
                            is_first,
                            sums,
                            previous,
                            self.poseidon_claims,
                            self.relations,
                        );
                        for (constraints) |constraint| accumulator.accumulate(
                            constraint.mul(denominator_inv),
                        );
                    },
                    .universal => {
                        const constraints = poseidonGeneralConstraints(
                            main,
                            is_first,
                            sums,
                            previous,
                            self.poseidon_claims,
                            self.relations,
                        );
                        for (constraints) |constraint| accumulator.accumulate(
                            constraint.mul(denominator_inv),
                        );
                    },
                }
            },
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
        if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
        const eval_log_size = std.math.add(u32, self.log_size, 1) catch
            return error.InvalidProofShape;
        if (self.log_size == 0 or eval_log_size >= circle.M31_CIRCLE_LOG_ORDER) {
            return error.InvalidProofShape;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const trace_size = @as(usize, 1) << @intCast(self.log_size);
        if (@as(usize, self.n_rows) > trace_size) return error.InvalidProofShape;
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        const n_preprocessed = self.nPreprocessedColumns();
        const main_end = std.math.add(usize, self.main_col_offset, n_main) catch
            return error.InvalidProofShape;
        const interaction_end = std.math.add(
            usize,
            self.interaction_col_offset,
            n_interaction,
        ) catch return error.InvalidProofShape;
        const source_count = std.math.add(
            usize,
            std.math.add(usize, n_preprocessed, n_main) catch
                return error.ResourceReservationOverflow,
            n_interaction,
        ) catch return error.ResourceReservationOverflow;
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const interaction = trace_data.polys.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            (self.usesActiveSelector() and
                preprocessed.len <= self.is_active_col_idx) or
            main.len < main_end or interaction.len < interaction_end)
        {
            return error.InvalidProofShape;
        }

        var owned_count: usize = 0;
        if (try prepared_support.sourceNeedsExtension(
            preprocessed[self.is_first_col_idx],
            self.log_size,
            eval_log_size,
        )) {
            owned_count = std.math.add(usize, owned_count, 1) catch
                return error.ResourceReservationOverflow;
        }
        if (self.usesActiveSelector() and try prepared_support.sourceNeedsExtension(
            preprocessed[self.is_active_col_idx],
            self.log_size,
            eval_log_size,
        )) {
            owned_count = std.math.add(usize, owned_count, 1) catch
                return error.ResourceReservationOverflow;
        }
        for (main[self.main_col_offset..main_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, self.log_size, eval_log_size)) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }
        for (interaction[self.interaction_col_offset..interaction_end]) |poly| {
            if (try prepared_support.sourceNeedsExtension(poly, self.log_size, eval_log_size)) {
                owned_count = std.math.add(usize, owned_count, 1) catch
                    return error.ResourceReservationOverflow;
            }
        }

        const evaluations = try allocator.alloc([]const M31, source_count);
        errdefer allocator.free(evaluations);
        const owned_buffers = try allocator.alloc([]M31, owned_count);
        var owned_initialized: usize = 0;
        errdefer {
            for (owned_buffers[0..owned_initialized]) |values| allocator.free(values);
            allocator.free(owned_buffers);
        }
        var source: usize = 0;
        evaluations[source] = try prepared_support.evaluationValues(
            allocator,
            preprocessed[self.is_first_col_idx],
            eval_log_size,
            eval_size,
            owned_buffers,
            &owned_initialized,
        );
        source += 1;
        if (self.usesActiveSelector()) {
            evaluations[source] = try prepared_support.evaluationValues(
                allocator,
                preprocessed[self.is_active_col_idx],
                eval_log_size,
                eval_size,
                owned_buffers,
                &owned_initialized,
            );
            source += 1;
        }
        for (main[self.main_col_offset..main_end]) |poly| {
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
        for (interaction[self.interaction_col_offset..interaction_end]) |poly| {
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
        std.debug.assert(source == source_count);
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

        const denominator_inv = try prepared_support.quotientDenominators(
            PREPARED_DENOMINATOR_COUNT,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        const resources = try prepared_support.resourcesWithStack(
            eval_size,
            source_count,
            owned_count,
            @sizeOf(PreparedDomainState),
            prepared_row_stack_bytes,
        );
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
            .owned_buffers = owned_buffers,
            .denominator_inv = denominator_inv,
            .column_accumulator = accumulators[0],
            .direct_store = accumulators[0].next_fresh_index == 0,
            .main_start = n_preprocessed,
            .interaction_start = n_preprocessed + n_main,
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
        };
        return .{
            .context = state,
            .vtable = &PreparedDomainState.vtable,
            .task_class = if (self.log_size >= PARALLEL_DOMAIN_LOG_SIZE)
                .pool_exclusive
            else
                .leaf,
            .resources = resources,
        };
    }
};

const hash_component_backend =
    @import("hash_component_backend.zig").Namespace(HashComponent);

const hash_component_prepared_domain = @import("hash_component_prepared_domain.zig").Namespace(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .utils = utils,
    .prover_air_accumulation = prover_air_accumulation,
    .prepared_domain = prepared_domain,
    .prover_task_graph = prover_task_graph,
    .work_pool = work_pool,
    .prepared_parallel = prepared_parallel,
    .merkle_node = merkle_node,
    .poseidon2_air = poseidon2_air,
    .PREPARED_DENOMINATOR_COUNT = PREPARED_DENOMINATOR_COUNT,
    .prepared_parallel_telemetry = &prepared_parallel_telemetry,
    .HashComponent = HashComponent,
    .poseidonConstraints = poseidonConstraints,
    .poseidonGeneralConstraints = poseidonGeneralConstraints,
    .readMain = readMain,
    .readInteraction = readInteraction,
    .combineConstraints = combineConstraints,
});
const PreparedDomainState = hash_component_prepared_domain.PreparedDomainState;
const PreparedRangeWorker = hash_component_prepared_domain.PreparedRangeWorker;
const serialTaskContext = hash_component_prepared_domain.serialTaskContext;

pub fn nMainColumns(kind: Kind) usize {
    return switch (kind) {
        .merkle => merkle_node.N_MAIN_COLUMNS,
        .poseidon2 => poseidon2_air.N_MAIN_COLUMNS,
    };
}

pub fn nInteractionColumns(kind: Kind) usize {
    return switch (kind) {
        .merkle => merkle_node.N_INTERACTION_COLUMNS,
        .poseidon2 => poseidon2_air.N_INTERACTION_COLUMNS,
    };
}

pub fn poseidonConstraints(
    main: [poseidon2_air.N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [poseidon2_air.N_SUMS]QM31,
    previous: [poseidon2_air.N_SUMS]QM31,
    claims: [poseidon2_air.N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_POSEIDON_COMPONENT_CONSTRAINTS]QM31 {
    return poseidonConstraintsGeneric(
        QM31,
        main,
        is_active,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
}

pub fn poseidonConstraintsGeneric(
    comptime S: type,
    main: [poseidon2_air.N_MAIN_COLUMNS]S,
    is_active: S,
    is_first: S,
    sums: [poseidon2_air.N_SUMS]S,
    previous: [poseidon2_air.N_SUMS]S,
    claims: [poseidon2_air.N_SUMS]S,
    relations: anytype,
) [N_POSEIDON_COMPONENT_CONSTRAINTS]S {
    const air_constraints = poseidon2_air.evaluateGeneric(S, main);
    const interaction_constraints = poseidon2_air.interactionConstraintsGeneric(
        S,
        main,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
    var constraints: [N_POSEIDON_COMPONENT_CONSTRAINTS]S = undefined;
    @memcpy(constraints[0..poseidon2_air.N_CONSTRAINTS], &air_constraints);
    constraints[poseidon2_air.N_CONSTRAINTS] = main[0].sub(is_active);
    const narrow_mode = poseidon2_air.narrowModeConstraintsGeneric(S, main);
    @memcpy(
        constraints[poseidon2_air.N_CONSTRAINTS + 1 ..][0..narrow_mode.len],
        &narrow_mode,
    );
    @memcpy(
        constraints[poseidon2_air.N_CONSTRAINTS + N_POSEIDON_SHELL_CONSTRAINTS ..],
        &interaction_constraints,
    );
    return constraints;
}

/// Exact general-mode component generated by Stark-V's embedded Poseidon2
/// function: canonical permutation/enabler/mode constraints followed by the
/// two pairs-batched LogUp recurrences.  Unlike the sparse-memory shell above,
/// it permits narrow, wide, and atomic input/output provider rows.
pub fn poseidonGeneralConstraints(
    main: [poseidon2_air.N_MAIN_COLUMNS]QM31,
    is_first: QM31,
    sums: [poseidon2_air.N_SUMS]QM31,
    previous: [poseidon2_air.N_SUMS]QM31,
    claims: [poseidon2_air.N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS]QM31 {
    return poseidonGeneralConstraintsGeneric(
        QM31,
        main,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
}

pub fn poseidonGeneralConstraintsGeneric(
    comptime S: type,
    main: [poseidon2_air.N_MAIN_COLUMNS]S,
    is_first: S,
    sums: [poseidon2_air.N_SUMS]S,
    previous: [poseidon2_air.N_SUMS]S,
    claims: [poseidon2_air.N_SUMS]S,
    relations: anytype,
) [N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS]S {
    const air_constraints = poseidon2_air.evaluateGeneric(S, main);
    const interaction_constraints = poseidon2_air.interactionConstraintsGeneric(
        S,
        main,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
    var constraints: [N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS]S = undefined;
    @memcpy(constraints[0..poseidon2_air.N_CONSTRAINTS], &air_constraints);
    @memcpy(constraints[poseidon2_air.N_CONSTRAINTS..], &interaction_constraints);
    return constraints;
}

const hash_component_sampling = @import("hash_component_sampling.zig").Namespace(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .CirclePointQM31 = CirclePointQM31,
});
const currentPointColumns = hash_component_sampling.currentPointColumns;
const currentAndPreviousPointColumns = hash_component_sampling.currentAndPreviousPointColumns;
const freePointColumns = hash_component_sampling.freePointColumns;
const sampleMain = hash_component_sampling.sampleMain;
const sampleInteraction = hash_component_sampling.sampleInteraction;
const sampledSecure = hash_component_sampling.sampledSecure;
const readMain = hash_component_sampling.readMain;
const readInteraction = hash_component_sampling.readInteraction;
const secureAt = hash_component_sampling.secureAt;
const combineConstraints = hash_component_sampling.combineConstraints;

comptime {
    if (poseidon2_air.N_CONSTRAINTS != 430 or
        poseidon2_air.N_SUMS != 2 or
        N_POSEIDON_SHELL_CONSTRAINTS != 3 or
        N_POSEIDON_COMPONENT_CONSTRAINTS != 435 or
        N_POSEIDON_GENERAL_COMPONENT_CONSTRAINTS != 432)
    {
        @compileError("Poseidon2 general/sparse component constraint geometry drifted");
    }
}
