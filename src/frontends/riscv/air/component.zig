//! Per-shard RISC-V AIR component with real LogUp constraints.
//!
//! Every component references three committed trees:
//!   tree 0: its IsFirst column at `preprocessed_col_idx`;
//!   tree 1: `desc.n_columns` main columns starting at `main_col_offset`;
//!   tree 2: its interaction columns starting at `interaction_col_offset`
//!           (family-specific for opcode shards, 16 for the program ROM, and
//!           16 for a memory-boundary shard).
//!
//! Opcode components enforce the two pairs-batched LogUp transitions (CPU
//! state chain and program-bus consume); the program component enforces the
//! ROM emission columns; memory components enforce their four pairs-batched
//! boundary transitions. Hash, lookup-table, and clock-update infrastructure
//! use their dedicated AIR component types.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const composition_work_support = @import("composition_work_support.zig");
const prepared_execution = @import("component_prepared_execution.zig");
const interaction_gen = @import("interaction_gen.zig");
const logup = @import("logup.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");
const opcode_memory = @import("opcode_memory.zig");
const prepared_evaluation = @import("prepared_evaluation_owner.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const relation_challenges = @import("relation_challenges.zig");
const semantic_eval = @import("semantic_eval.zig");
const trace_mod = @import("../runner/trace.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;

/// Per-family component descriptor within the proof.
pub const FamilyComponentDesc = struct {
    family: trace_mod.OpcodeFamily,
    log_size: u32,
    n_rows: u32,
    n_columns: u32 = 10,
};

/// Constraint role of a component.
pub const Kind = enum { opcode, program, memory };

/// Number of committed M31 interaction columns for a component kind.
pub fn nInteractionCols(kind: Kind) u32 {
    return switch (kind) {
        .opcode => @intCast(interaction_gen.OPCODE_INTERACTION_COLS),
        .program => @intCast(program_interaction.N_COLUMNS),
        .memory => @intCast(memory_interaction.N_COLUMNS),
    };
}

pub const RiscVTraceComponent = struct {
    desc: FamilyComponentDesc,
    initial_pc: u32,
    total_steps: u32,
    /// Deterministic selector columns in tree 0.
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    /// Offset of this component's first column within tree 1 (main trace).
    main_col_offset: usize,
    kind: Kind,
    relations: *const relation_challenges.Relations,
    /// Offset of this component's first column within tree 2 (interaction).
    interaction_col_offset: usize = 0,
    state_claim: QM31 = QM31.zero(),
    prog_claim: QM31 = QM31.zero(),
    program_claims: [program_interaction.N_SUMS]QM31 =
        .{QM31.zero()} ** program_interaction.N_SUMS,
    opcode_memory_claims: [opcode_memory.N_ACCESSES]QM31 =
        .{QM31.zero()} ** opcode_memory.N_ACCESSES,
    memory_claims: [memory_interaction.N_SUMS]QM31 =
        .{QM31.zero()} ** memory_interaction.N_SUMS,
    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        component.composition_work_profile = switch (self.kind) {
            .program => compositionWorkProfileErased,
            .memory => compositionWorkProfileErased,
            // Legacy opcode shards do not have a single generic semantic
            // evaluator. The typed semantic/lookup components publish their
            // own source-identical profiles; a legacy-only route fails closed.
            .opcode => null,
        };
        component.oods_work_profile = switch (self.kind) {
            .program, .memory => oodsWorkProfileErased,
            .opcode => null,
        };
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
            .program => 2 * program_interaction.N_SUMS,
            .memory => 2 * memory_interaction.N_SUMS,
            .opcode => return error.UnsupportedOodsWorkProfile,
        };
        return composition_work_support.oodsProfile(
            source,
            self.desc.log_size,
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
        const is_active = composition_work_support.values(1, 100)[0];
        const is_first = composition_work_support.values(1, 101)[0];
        var expression: composition_work_support.FieldOperations = undefined;
        switch (self.kind) {
            .program => {
                const main = composition_work_support.values(
                    program_commitment.N_MAIN_COLUMNS,
                    0,
                );
                const sums = composition_work_support.values(
                    program_interaction.N_SUMS,
                    20,
                );
                const previous = composition_work_support.values(
                    program_interaction.N_SUMS,
                    40,
                );
                const claims = composition_work_support.values(
                    program_interaction.N_SUMS,
                    60,
                );
                try composition_work_support.begin(&expression);
                defer composition_work_support.end();
                _ = program_interaction.evaluateGeneric(
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
                    .program,
                    "riscv-program-interaction-evaluate-generic-v1",
                    self.maxConstraintLogDegreeBound(),
                    self.nConstraints(),
                    expression,
                    .{},
                    &.{
                        @as(u64, self.desc.log_size),
                        @as(u64, program_commitment.N_MAIN_COLUMNS),
                        @as(u64, program_interaction.N_SUMS),
                    },
                );
            },
            .memory => {
                const main = composition_work_support.values(8, 0);
                const sums = composition_work_support.values(
                    memory_interaction.N_SUMS,
                    20,
                );
                const previous = composition_work_support.values(
                    memory_interaction.N_SUMS,
                    40,
                );
                const claims = composition_work_support.values(
                    memory_interaction.N_SUMS,
                    60,
                );
                try composition_work_support.begin(&expression);
                defer composition_work_support.end();
                _ = memory_interaction.evaluateGeneric(
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
                    .memory,
                    "riscv-memory-interaction-evaluate-generic-v1",
                    self.maxConstraintLogDegreeBound(),
                    self.nConstraints(),
                    expression,
                    .{},
                    &.{
                        @as(u64, self.desc.log_size),
                        8,
                        @as(u64, memory_interaction.N_SUMS),
                    },
                );
            },
            .opcode => return error.UnsupportedCompositionWorkProfile,
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
        return switch (self.kind) {
            .opcode => 2 + opcode_memory.N_ACCESSES + if (semantic_eval.isTraceCompatible(self.desc.family))
                semantic_eval.constraintCount(self.desc.family)
            else
                0,
            .program => program_interaction.N_CONSTRAINTS,
            .memory => memory_interaction.N_CONSTRAINTS,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        // The pairs-batched LogUp constraint is degree 3, whose quotient fits
        // in the log_size + 1 coefficient space (the standard stwo bound with
        // one constraint-evaluation blowup bit).
        return self.desc.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &[_]u32{
            self.desc.log_size,
            self.desc.log_size,
        });
        const main = try allocator.alloc(u32, self.desc.n_columns);
        @memset(main, self.desc.log_size);
        const inter = try allocator.alloc(u32, nInteractionCols(self.kind));
        @memset(inter, self.desc.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main, inter }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const is_first_col = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{point});
        const is_active_col = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{point});
        const preprocessed_cols = try allocator.dupe(
            []CirclePointQM31,
            &[_][]CirclePointQM31{ is_first_col, is_active_col },
        );

        const n = self.desc.n_columns;
        const main_cols = try allocator.alloc([]CirclePointQM31, n);
        for (0..n) |i| {
            main_cols[i] = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{point});
        }

        // The PCS samples a column committed at log k+1 at the FOLDED point
        // double^(max_log_degree_bound - k)(q) for a requested point q. The
        // canonic step halves per doubling, so subtracting the step of the
        // MAXIMAL coset from the request shifts the folded point by exactly
        // this component's own coset step — the previous trace row.
        const prev_point = logup.prevRowPoint(max_log_degree_bound, point);
        const n_inter = nInteractionCols(self.kind);
        const inter_cols = try allocator.alloc([]CirclePointQM31, n_inter);
        for (0..n_inter) |i| {
            inter_cols[i] = try allocator.dupe(
                CirclePointQM31,
                &[_]CirclePointQM31{ point, prev_point },
            );
        }

        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                preprocessed_cols,
                main_cols,
                inter_cols,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(
            usize,
            &[_]usize{ self.is_first_col_idx, self.is_active_col_idx },
        );
    }

    fn sampledSecure(cols: [][]QM31, base: usize, point_idx: usize) !QM31 {
        var coords: [4]QM31 = undefined;
        for (0..4) |c| {
            if (cols[base + c].len <= point_idx) return error.InvalidProofShape;
            coords[c] = cols[base + c][point_idx];
        }
        return QM31.fromPartialEvals(coords);
    }

    fn sampledMainRow(
        comptime n: usize,
        main: [][]QM31,
        offset: usize,
    ) ![n]QM31 {
        if (main.len < offset + n) return error.InvalidProofShape;
        var row: [n]QM31 = undefined;
        for (&row, main[offset .. offset + n]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        return row;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.desc.log_size) return error.InvalidProofShape;
        if (mask.items.len < 3) return error.InvalidProofShape;
        const pp = mask.items[0];
        const main = mask.items[1];
        const inter = mask.items[2];
        const o = self.interaction_col_offset;
        if (pp.len <= self.is_active_col_idx or
            pp[self.is_first_col_idx].len < 1 or
            pp[self.is_active_col_idx].len < 1)
            return error.InvalidProofShape;
        if (main.len < self.main_col_offset + self.desc.n_columns) return error.InvalidProofShape;
        if (inter.len < o + nInteractionCols(self.kind)) return error.InvalidProofShape;
        for (inter[o .. o + nInteractionCols(self.kind)]) |col| {
            if (col.len < 2) return error.InvalidProofShape;
        }
        for (main[self.main_col_offset .. self.main_col_offset + self.desc.n_columns]) |col| {
            if (col.len < 1) return error.InvalidProofShape;
        }

        // The sampled values of this component's columns (committed at
        // log_size + 1) are the base polynomials evaluated at the folded
        // point double^fold(point); check the constraint there.
        const fold = max_log_degree_bound - self.desc.log_size;
        const folded_point = point.repeatedDouble(fold);
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.desc.log_size).coset(),
            folded_point,
        ).inv();
        const is_first = pp[self.is_first_col_idx][0];
        const is_active = pp[self.is_active_col_idx][0];

        switch (self.kind) {
            .opcode => {
                const pc = main[self.main_col_offset + semantic_eval.pcColumn(self.desc.family)][0];
                const clk = main[self.main_col_offset + semantic_eval.clockColumn(self.desc.family)][0];
                const bus = self.main_col_offset + self.desc.n_columns - 5;
                const next_pc = main[bus][0];
                const opcode_id = main[bus + 1][0];
                const value_1 = main[bus + 2][0];
                const value_2 = main[bus + 3][0];
                const value_3 = main[bus + 4][0];
                const s_state = try sampledSecure(inter, o, 0);
                const s_state_prev = try sampledSecure(inter, o, 1);
                const s_prog = try sampledSecure(inter, o + 4, 0);
                const s_prog_prev = try sampledSecure(inter, o + 4, 1);

                const state_pair = logup.stateChainPair(self.relations, pc, clk, next_pc, is_active);
                evaluation_accumulator.accumulate(
                    logup.pairConstraint(s_state, s_state_prev, is_first, self.state_claim, state_pair)
                        .mul(denominator_inv),
                );
                const prog_pair = logup.programConsume(
                    self.relations,
                    pc,
                    opcode_id,
                    value_1,
                    value_2,
                    value_3,
                    is_active,
                );
                evaluation_accumulator.accumulate(
                    logup.pairConstraint(s_prog, s_prog_prev, is_first, self.prog_claim, prog_pair)
                        .mul(denominator_inv),
                );
                var sampled: [trace_mod.MAX_FAMILY_COLUMNS]QM31 = undefined;
                const n_columns = semantic_eval.mainColumnCount(self.desc.family);
                for (sampled[0..n_columns], 0..) |*value, column| {
                    value.* = main[self.main_col_offset + column][0];
                }
                var memory_sums: [opcode_memory.N_ACCESSES]QM31 = undefined;
                var memory_previous: [opcode_memory.N_ACCESSES]QM31 = undefined;
                for (0..opcode_memory.N_ACCESSES) |slot| {
                    const memory_offset = o + 8 + slot * 4;
                    memory_sums[slot] = try sampledSecure(inter, memory_offset, 0);
                    memory_previous[slot] = try sampledSecure(inter, memory_offset, 1);
                }
                const memory_constraints = try opcode_memory.constraints(
                    self.desc.family,
                    sampled[0..n_columns],
                    is_active,
                    is_first,
                    memory_sums,
                    memory_previous,
                    self.opcode_memory_claims,
                    &self.relations.memory_access,
                );
                for (memory_constraints) |constraint| {
                    evaluation_accumulator.accumulate(constraint.mul(denominator_inv));
                }
                if (semantic_eval.isTraceCompatible(self.desc.family)) {
                    var constraints: semantic_eval.Evaluation = undefined;
                    try semantic_eval.evaluateInto(
                        self.desc.family,
                        sampled[0..n_columns],
                        is_active,
                        &constraints,
                    );
                    for (constraints.values[0..constraints.len]) |constraint| {
                        evaluation_accumulator.accumulate(constraint.mul(denominator_inv));
                    }
                }
            },
            .program => {
                const sampled = try sampledMainRow(
                    program_commitment.N_MAIN_COLUMNS,
                    main,
                    self.main_col_offset,
                );
                var sums: [program_interaction.N_SUMS]QM31 = undefined;
                var previous: [program_interaction.N_SUMS]QM31 = undefined;
                for (0..program_interaction.N_SUMS) |index| {
                    sums[index] = try sampledSecure(inter, o + index * 4, 0);
                    previous[index] = try sampledSecure(inter, o + index * 4, 1);
                }
                const constraints = program_interaction.evaluate(
                    sampled,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.program_claims,
                    self.relations,
                );
                for (constraints) |constraint| {
                    evaluation_accumulator.accumulate(constraint.mul(denominator_inv));
                }
            },
            .memory => {
                const sampled = try sampledMainRow(8, main, self.main_col_offset);
                var sums: [memory_interaction.N_SUMS]QM31 = undefined;
                var previous: [memory_interaction.N_SUMS]QM31 = undefined;
                for (0..memory_interaction.N_SUMS) |index| {
                    sums[index] = try sampledSecure(inter, o + index * 4, 0);
                    previous[index] = try sampledSecure(inter, o + index * 4, 1);
                }
                const constraints = memory_interaction.evaluate(
                    sampled,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.memory_claims,
                    self.relations,
                );
                for (constraints) |constraint| {
                    evaluation_accumulator.accumulate(constraint.mul(denominator_inv));
                }
            },
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try self.prepareDomainEvaluator(
            evaluation_accumulator.allocator,
            trace,
            evaluation_accumulator,
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
        trace: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        const log_size = self.desc.log_size;
        // Quotient geometry is AIR-owned (`log_size + 1`) and independent of
        // the PCS LDE blowup. Frozen V1 borrows equal-domain values; candidate
        // profiles reconstruct this exact domain from retained coefficients.
        const eval_log_size = try quotientEvaluationLogSize(log_size);
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();

        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const pp = trace.polys.items[0];
        const main = trace.polys.items[1];
        const inter = trace.polys.items[2];
        const n_inter: usize = nInteractionCols(self.kind);
        const descriptor_main_sources = std.math.cast(usize, self.desc.n_columns) orelse
            return error.InvalidProofShape;
        const main_source_count: usize = switch (self.kind) {
            .opcode => trace_mod.nColumnsForFamily(self.desc.family),
            .program => program_commitment.N_MAIN_COLUMNS,
            .memory => 8,
        };
        if (descriptor_main_sources != main_source_count) {
            return error.InvalidProofShape;
        }
        const main_end = std.math.add(usize, self.main_col_offset, main_source_count) catch
            return error.InvalidProofShape;
        const inter_end = std.math.add(usize, self.interaction_col_offset, n_inter) catch
            return error.InvalidProofShape;
        if (pp.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            main.len < main_end or inter.len < inter_end)
        {
            return error.InvalidProofShape;
        }
        // Source order is selectors, relation inputs from the pre-challenge
        // main tree, cumulative interaction columns, then shifted S columns.
        var n_sources = std.math.add(usize, 2, main_source_count) catch
            return error.ResourceReservationOverflow;
        n_sources = std.math.add(usize, n_sources, n_inter) catch
            return error.ResourceReservationOverflow;
        const evaluations = try allocator.alloc([]const M31, n_sources);
        errdefer allocator.free(evaluations);

        var owned_count: usize = 0;
        const selector_sources = .{
            pp[self.is_first_col_idx],
            pp[self.is_active_col_idx],
        };
        inline for (selector_sources) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                log_size,
                eval_log_size,
            ));
        }
        for (main[self.main_col_offset..main_end]) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                log_size,
                eval_log_size,
            ));
        }
        for (inter[self.interaction_col_offset..inter_end]) |poly| {
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                log_size,
                eval_log_size,
            ));
        }
        var evaluation_owner = try prepared_evaluation.Owner.init(
            allocator,
            owned_count,
        );
        errdefer evaluation_owner.deinit();

        var source_index: usize = 0;
        // Committed polynomials: deterministic selectors, relation inputs
        // from main, and cumulative columns from interaction.
        evaluations[source_index] = try evaluation_owner.value(
            pp[self.is_first_col_idx],
            log_size,
            eval_log_size,
            eval_size,
        );
        source_index += 1;
        evaluations[source_index] = try evaluation_owner.value(
            pp[self.is_active_col_idx],
            log_size,
            eval_log_size,
            eval_size,
        );
        source_index += 1;
        for (main[self.main_col_offset..main_end]) |poly| {
            evaluations[source_index] = try evaluation_owner.value(
                poly,
                log_size,
                eval_log_size,
                eval_size,
            );
            source_index += 1;
        }
        for (inter[self.interaction_col_offset..inter_end]) |poly| {
            evaluations[source_index] = try evaluation_owner.value(
                poly,
                log_size,
                eval_log_size,
                eval_size,
            );
            source_index += 1;
        }
        std.debug.assert(source_index == n_sources);
        try evaluation_owner.finish(eval_domain);

        // The trace-coset vanishing polynomial is block-constant over the
        // extended domain in committed order: block b (of 2^log_size rows)
        // carries the value at domain point index bitrev(b, extension_bits)
        // (see the geometry test below). With a single extension bit the
        // reversal is the identity, which is why the wide-Fibonacci template
        // can use `at(k)` directly.
        const extension_bits: u5 = @intCast(eval_log_size - log_size);
        const trace_coset = canonic.CanonicCoset.new(log_size).coset();
        const denominator_inv = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
        errdefer allocator.free(denominator_inv);
        for (denominator_inv, 0..) |*inv, k| {
            inv.* = try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(utils.bitReverseIndex(k, extension_bits)),
            ).inv();
        }

        const resources = try preparedDomainResources(
            eval_size,
            n_sources,
            owned_count,
            denominator_inv.len,
        );
        const state = try allocator.create(PreparedDomainState);
        errdefer allocator.destroy(state);
        const accumulators = try evaluation_accumulator.columns(
            allocator,
            &[_]prover_air_accumulation.ColumnRequest{.{
                .log_size = eval_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .evaluation_owner = evaluation_owner,
            .denominator_inv = denominator_inv,
            .accumulators = accumulators,
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
            .opcode_main_sources = descriptor_main_sources,
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
        try prepared_execution.run(self, state, task_context);
    }
};

const PreparedDomainState = struct {
    const CANCELLATION_POLL_ROWS: usize = 4096;
    comptime {
        if (CANCELLATION_POLL_ROWS == 0 or
            CANCELLATION_POLL_ROWS > 4096 or
            (CANCELLATION_POLL_ROWS & (CANCELLATION_POLL_ROWS - 1)) != 0)
        {
            @compileError("component cancellation polling must be power-of-two and at most 4096 rows");
        }
    }

    allocator: std.mem.Allocator,
    component: *const RiscVTraceComponent,
    evaluations: [][]const M31,
    evaluation_owner: prepared_evaluation.Owner,
    denominator_inv: []M31,
    accumulators: []prover_air_accumulation.ColumnAccumulator,
    eval_log_size: u32,
    eval_size: usize,
    opcode_main_sources: usize,

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
        self.evaluation_owner.deinit();
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
    resident_bytes = std.math.add(
        usize,
        resident_bytes,
        denominator_bytes,
    ) catch return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(
        usize,
        resident_bytes,
        try prepared_evaluation.residentBytes(owned_count, eval_size),
    ) catch return error.ResourceReservationOverflow;
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

fn secureAt(coords: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(coords[0][row], coords[1][row], coords[2][row], coords[3][row]);
}
