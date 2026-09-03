//! Proof-bound ordered-call authority borrowing compiler-selected main columns.
//! Its four-M31 Tree-2 accumulator has a verifier-recomputed range-bound claim,
//! catching omission, reorder, or relabeling under Fiat-Shamir soundness.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const verifier_types = @import("stwo_core").verifier_types;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const infra = @import("../../infra_trace.zig");
const logup = @import("../../air/logup.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const relations_mod = @import("../../air/relation_challenges.zig");
const prepared_evaluation = @import("../../air/prepared_evaluation_owner.zig");
const prepared_support = @import("provider_order_prepared_support.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const INPUT_START: usize = 1;
const OUTPUT_START: usize = 1 + poseidon2_air.N_TEMPORARIES;
pub const selected_main_count: usize = poseidon2_air.WIDTH + 1;
pub const SelectedMainColumns = [selected_main_count]u16;

pub const format_version: u32 = 1;
pub const interaction_column_count: usize = 4;
pub const constraint_count: usize = 4;

/// Field-generic replay of the four ordered-call constraints. Range arguments
/// are plan constants; all others are verifier-owned proof/transcript data.
pub fn evaluateGeneric(
    comptime S: type,
    main: [poseidon2_air.N_MAIN_COLUMNS]S,
    current: S,
    previous: S,
    is_first: S,
    is_active: S,
    row_power: S,
    accumulator_power: S,
    first_call: u64,
    call_count: u32,
    terminal: S,
) [constraint_count]S {
    var selected: [selected_main_count]S = undefined;
    @memcpy(
        selected[0..poseidon2_air.WIDTH],
        main[INPUT_START..][0..poseidon2_air.WIDTH],
    );
    selected[poseidon2_air.WIDTH] = main[OUTPUT_START];
    return evaluateSelectedGeneric(
        S,
        selected,
        current,
        previous,
        is_first,
        is_active,
        row_power,
        accumulator_power,
        first_call,
        call_count,
        terminal,
    );
}

pub fn evaluateSelectedGeneric(
    comptime S: type,
    selected: [selected_main_count]S,
    current: S,
    previous: S,
    is_first: S,
    is_active: S,
    row_power: S,
    accumulator_power: S,
    first_call: u64,
    call_count: u32,
    terminal: S,
) [constraint_count]S {
    var value = domainValue(S, 0x524f_5731);
    for (selected) |felt| value = value.mul(row_power).add(felt);
    const seed = rangeSeedGeneric(S, first_call, call_count, row_power);
    const first_expected = seed.mul(accumulator_power).add(value);
    const continued = previous.mul(accumulator_power).add(value);
    return .{
        is_first.mul(current.sub(first_expected)),
        is_active.sub(is_first).mul(current.sub(continued)),
        S.one().sub(is_active).mul(current.sub(previous)),
        is_first.mul(previous.sub(terminal)),
    };
}

/// Canonical shard-range seed: five 15-bit call limbs plus three count limbs.
pub fn rangeSeedGeneric(
    comptime S: type,
    first_call: u64,
    call_count: u32,
    power: S,
) S {
    var result = domainValue(S, 0x524e_4731);
    var first = first_call;
    for (0..5) |_| {
        result = result.mul(power).add(
            domainValue(S, @intCast(first & 0x7fff)),
        );
        first >>= 15;
    }
    var count = call_count;
    for (0..3) |_| {
        result = result.mul(power).add(domainValue(S, count & 0x7fff));
        count >>= 15;
    }
    return result;
}

pub const ChallengesV1 = struct {
    row_power: QM31,
    accumulator_power: QM31,

    pub fn derive(relations: *const relations_mod.Relations) !@This() {
        const row_power = relations.poseidon2.z.add(domainFelt(0x4f52_4452));
        const accumulator_power = relations.poseidon2.alpha.add(domainFelt(0x4143_4355));
        if (row_power.isZero() or row_power.eql(QM31.one()) or
            accumulator_power.isZero() or accumulator_power.eql(QM31.one()))
        {
            return error.DegenerateProviderOrderChallenge;
        }
        return .{
            .row_power = row_power,
            .accumulator_power = accumulator_power,
        };
    }
};

pub const ClaimV1 = struct {
    format: u32,
    first_call: u64,
    call_count: u32,
    terminal: QM31,
};

pub const Interaction = struct {
    columns: [interaction_column_count][]M31,
    claim: ClaimV1,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn expectedClaim(
    first_call: u64,
    calls: []const poseidon2_air.Call,
    relations: *const relations_mod.Relations,
) !ClaimV1 {
    const count = std.math.cast(u32, calls.len) orelse
        return error.CallCountOutOfRange;
    if (count == 0) return error.EmptyProviderShard;
    const challenges = try ChallengesV1.derive(relations);
    var accumulator = rangeSeed(first_call, count, challenges.row_power);
    for (calls) |call| {
        try validateCall(call);
        accumulator = accumulator.mul(challenges.accumulator_power).add(
            callValue(call, challenges.row_power),
        );
    }
    return .{
        .format = format_version,
        .first_call = first_call,
        .call_count = count,
        .terminal = accumulator,
    };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    first_call: u64,
    calls: []const poseidon2_air.Call,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len == 0 or calls.len > size) return error.InvalidTraceShape;
    const claim = try expectedClaim(first_call, calls, relations);
    const challenges = try ChallengesV1.derive(relations);
    var columns: [interaction_column_count][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        initialized += 1;
    }
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    var accumulator = rangeSeed(first_call, claim.call_count, challenges.row_power);
    for (0..size) |row| {
        if (row < calls.len) {
            accumulator = accumulator.mul(challenges.accumulator_power).add(
                callValue(calls[row], challenges.row_power),
            );
        }
        const coordinates = accumulator.toM31Array();
        const destination = table.map(row);
        for (&columns, coordinates) |column, value| column[destination] = value;
    }
    if (!accumulator.eql(claim.terminal)) return error.ProviderOrderClaimMismatch;
    return .{ .columns = columns, .claim = claim };
}

pub const ProviderOrderComponent = struct {
    log_size: u32,
    n_rows: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    main_column_count: usize,
    selected_main_columns: SelectedMainColumns,
    composition_log_split: u32,
    interaction_col_offset: usize,
    challenges: ChallengesV1,
    claim: ClaimV1,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn init(
        log_size: u32,
        n_rows: u32,
        first_call: u64,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: ClaimV1,
    ) !@This() {
        return initProjected(
            log_size,
            n_rows,
            first_call,
            is_first_col_idx,
            is_active_col_idx,
            main_col_offset,
            poseidon2_air.N_MAIN_COLUMNS,
            legacySelectedMainColumns(),
            verifier_types.COMPOSITION_LOG_SPLIT,
            interaction_col_offset,
            relations,
            claim,
        );
    }

    pub fn initProjected(
        log_size: u32,
        n_rows: u32,
        first_call: u64,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        main_column_count: usize,
        selected_main_columns: SelectedMainColumns,
        composition_log_split: u32,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: ClaimV1,
    ) !@This() {
        const canonical = try ChallengesV1.derive(relations);
        const maximum_log_degree_bound = std.math.add(
            u32,
            log_size,
            composition_log_split,
        ) catch return error.InvalidProviderOrderClaim;
        if (claim.format != format_version or claim.first_call != first_call or
            claim.call_count != n_rows or n_rows == 0 or log_size >= @bitSizeOf(u32) or
            n_rows > (@as(u32, 1) << @intCast(log_size)) or
            !validProjection(main_column_count, selected_main_columns) or
            composition_log_split == 0 or
            composition_log_split > verifier_types.MAX_COMPOSITION_LOG_SPLIT or
            maximum_log_degree_bound >= circle.M31_CIRCLE_LOG_ORDER)
        {
            return error.InvalidProviderOrderClaim;
        }
        return .{
            .log_size = log_size,
            .n_rows = n_rows,
            .is_first_col_idx = is_first_col_idx,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
            .main_column_count = main_column_count,
            .selected_main_columns = selected_main_columns,
            .composition_log_split = composition_log_split,
            .interaction_col_offset = interaction_col_offset,
            .challenges = canonical,
            .claim = claim,
        };
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        return component;
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return constraint_count;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + self.composition_log_split;
    }

    pub fn compositionLogSplit(self: *const @This()) u32 {
        return self.composition_log_split;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{ self.log_size, self.log_size });
        errdefer allocator.free(preprocessed);
        // Borrow the preceding Poseidon Tree 1 without recommitting columns.
        const main = try allocator.alloc(u32, 0);
        errdefer allocator.free(main);
        const interaction = try allocator.alloc(u32, interaction_column_count);
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
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
        const preprocessed = try currentPointColumns(allocator, 2, point);
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, 0, point);
        errdefer freePointColumns(allocator, main);
        const interaction = try currentAndPreviousPointColumns(
            allocator,
            interaction_column_count,
            point,
            logup.prevRowPoint(max_log_degree_bound, point),
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
        return allocator.dupe(usize, &.{ self.is_first_col_idx, self.is_active_col_idx });
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
        const main = mask.items[1];
        const interaction = mask.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
            main.len < self.main_col_offset + self.main_column_count or
            interaction.len < self.interaction_col_offset + interaction_column_count)
        {
            return error.InvalidProofShape;
        }
        const current = try sampledSecure(interaction, self.interaction_col_offset, 0);
        const previous = try sampledSecure(interaction, self.interaction_col_offset, 1);
        const constraints = self.evaluateRow(
            main,
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
        for (constraints) |constraint|
            accumulator.accumulate(constraint.mul(denominator_inv));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try self.prepareDomainEvaluator(
            accumulator.allocator,
            trace,
            accumulator,
        );
        defer prepared.deinit();
        var cancellation = prover_task_graph.CancellationToken{};
        var context = prover_task_graph.TaskContext{
            .user_context = prepared.context,
            .cancellation = &cancellation,
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = 0,
                .shard_or_chunk_index = 0,
            },
            .worker_budget = work_pool.WorkerBudget.serial(),
            .task_class = .leaf,
            .exclusive_lease = null,
            .child_wait_group = null,
        };
        try prepared.run(&context);
    }

    fn evaluateRow(
        self: *const @This(),
        main: []const []const QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
        is_active: QM31,
    ) [constraint_count]QM31 {
        var selected: [selected_main_count]QM31 = undefined;
        for (&selected, self.selected_main_columns) |*value, column|
            value.* = main[self.main_col_offset + column][0];
        return evaluateSelectedGeneric(
            QM31,
            selected,
            current,
            previous,
            is_first,
            is_active,
            self.challenges.row_power,
            self.challenges.accumulator_power,
            self.claim.first_call,
            self.claim.call_count,
            self.claim.terminal,
        );
    }

    fn prepareDomainEvaluatorErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return self.prepareDomainEvaluator(allocator, trace, accumulator);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            main.len < self.main_col_offset + self.main_column_count or
            interaction.len < self.interaction_col_offset + interaction_column_count)
        {
            return error.InvalidProofShape;
        }
        const eval_log_size = std.math.add(
            u32,
            self.log_size,
            self.composition_log_split,
        ) catch return error.InvalidProofShape;
        if (self.log_size == 0 or eval_log_size > accumulator.logSize()) {
            return error.InvalidProofShape;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const sources = [_]prover_component.Poly{
            preprocessed[self.is_first_col_idx],
            preprocessed[self.is_active_col_idx],
        };
        var owned_count: usize = 0;
        for (sources) |poly| owned_count += @intFromBool(try prepared_evaluation.needsOwned(
            poly,
            self.log_size,
            eval_log_size,
        ));
        for (selectedMainPolys(
            main,
            self.main_col_offset,
            self.selected_main_columns,
        )) |poly|
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                self.log_size,
                eval_log_size,
            ));
        for (interaction[self.interaction_col_offset..][0..interaction_column_count]) |poly|
            owned_count += @intFromBool(try prepared_evaluation.needsOwned(
                poly,
                self.log_size,
                eval_log_size,
            ));

        var owner = try prepared_evaluation.Owner.init(allocator, owned_count);
        errdefer owner.deinit();
        var evaluations: [PreparedState.source_count][]const M31 = undefined;
        var source: usize = 0;
        for (sources) |poly| {
            evaluations[source] = try owner.value(
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
            );
            source += 1;
        }
        for (selectedMainPolys(
            main,
            self.main_col_offset,
            self.selected_main_columns,
        )) |poly| {
            evaluations[source] = try owner.value(
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
            );
            source += 1;
        }
        for (interaction[self.interaction_col_offset..][0..interaction_column_count]) |poly| {
            evaluations[source] = try owner.value(
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
            );
            source += 1;
        }
        std.debug.assert(source == evaluations.len);
        try owner.finish(eval_domain);
        const denominator_inv = try prepared_support.quotientDenominators(
            allocator,
            self.log_size,
            eval_log_size,
            self.composition_log_split,
            eval_domain,
        );
        errdefer allocator.free(denominator_inv);
        const state = try allocator.create(PreparedState);
        errdefer allocator.destroy(state);
        const columns = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = constraint_count }},
        );
        defer allocator.free(columns);
        state.* = .{
            .allocator = allocator,
            .component = self,
            .evaluations = evaluations,
            .owner = owner,
            .denominator_inv = denominator_inv,
            .accumulator = columns[0],
            .eval_log_size = eval_log_size,
            .eval_size = eval_size,
        };
        const resources = try prepared_support.resources(
            eval_size,
            owned_count,
            denominator_inv.len,
            @sizeOf(PreparedState),
        );
        return .{
            .context = state,
            .vtable = &PreparedState.vtable,
            .task_class = .leaf,
            .resources = resources,
        };
    }

    fn runPrepared(
        self: *const @This(),
        state: *PreparedState,
        task: *prover_task_graph.TaskContext,
    ) !void {
        const main_start: usize = 2;
        const interaction_start = main_start + selected_main_count;
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..state.eval_size) |row| {
            if ((row & (PreparedState.poll_rows - 1)) == 0 and task.isCancelled()) return;
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                state.eval_log_size,
            );
            const current = secureAt(
                state.evaluations[interaction_start..][0..4],
                row,
            );
            const previous = secureAt(
                state.evaluations[interaction_start..][0..4],
                previous_row,
            );
            var selected: [selected_main_count]QM31 = undefined;
            for (&selected, state.evaluations[main_start..][0..selected_main_count]) |
                *value,
                column,
            | value.* = QM31.fromBase(column[row]);
            const constraints = self.evaluateSelectedRow(
                selected,
                current,
                previous,
                QM31.fromBase(state.evaluations[0][row]),
                QM31.fromBase(state.evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (constraints, 0..) |constraint, index| {
                const powers = state.accumulator.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
            }
            state.accumulator.accumulate(
                row,
                folded.mulM31(state.denominator_inv[row >> denominator_shift]),
            );
        }
    }

    fn evaluateSelectedRow(
        self: *const @This(),
        selected: [selected_main_count]QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
        is_active: QM31,
    ) [constraint_count]QM31 {
        return evaluateSelectedGeneric(
            QM31,
            selected,
            current,
            previous,
            is_first,
            is_active,
            self.challenges.row_power,
            self.challenges.accumulator_power,
            self.claim.first_call,
            self.claim.call_count,
            self.claim.terminal,
        );
    }
};

const PreparedState = struct {
    const source_count = 2 + selected_main_count + interaction_column_count;
    const poll_rows: usize = 4096;
    allocator: std.mem.Allocator,
    component: *const ProviderOrderComponent,
    evaluations: [source_count][]const M31,
    owner: prepared_evaluation.Owner,
    denominator_inv: []M31,
    accumulator: prover_air_accumulation.ColumnAccumulator,
    eval_log_size: u32,
    eval_size: usize,

    const vtable = prepared_domain.VTable{
        .run = runErased,
        .deinit = deinitErased,
    };

    fn runErased(context: *anyopaque, task: *prover_task_graph.TaskContext) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context));
        try self.component.runPrepared(self, task);
    }

    fn deinitErased(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        self.owner.deinit();
        allocator.free(self.denominator_inv);
        allocator.destroy(self);
    }
};

fn callValue(call: poseidon2_air.Call, power: QM31) QM31 {
    var result = domainFelt(0x524f_5731);
    for (call.input) |value|
        result = result.mul(power).add(QM31.fromBase(M31.fromCanonical(value)));
    return result.mul(power).add(
        QM31.fromBase(M31.fromCanonical(call.narrow_output.?)),
    );
}

fn rangeSeed(first_call: u64, call_count: u32, power: QM31) QM31 {
    return rangeSeedGeneric(QM31, first_call, call_count, power);
}

fn validateCall(call: poseidon2_air.Call) !void {
    if (call.wide or call.io or call.narrow_output == null)
        return error.NonCanonicalNarrowCall;
    for (call.input) |value| if (value >= @import("stwo_core").fields.m31.Modulus)
        return error.NonCanonicalM31Value;
    if (call.narrow_output.? >= @import("stwo_core").fields.m31.Modulus)
        return error.NonCanonicalM31Value;
}

fn domainFelt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn domainValue(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

fn selectedMainPolys(
    main: anytype,
    offset: usize,
    selected_columns: SelectedMainColumns,
) [selected_main_count]@TypeOf(main[0]) {
    var selected: [selected_main_count]@TypeOf(main[0]) = undefined;
    for (&selected, selected_columns) |*value, column|
        value.* = main[offset + column];
    return selected;
}

fn legacySelectedMainColumns() SelectedMainColumns {
    var result: SelectedMainColumns = undefined;
    for (result[0..poseidon2_air.WIDTH], 0..) |*column, lane|
        column.* = @intCast(INPUT_START + lane);
    result[poseidon2_air.WIDTH] = OUTPUT_START;
    return result;
}

fn validProjection(
    main_column_count: usize,
    selected_columns: SelectedMainColumns,
) bool {
    if (main_column_count == 0) return false;
    for (selected_columns, 0..) |column, index| {
        if (column >= main_column_count) return false;
        for (selected_columns[0..index]) |previous|
            if (column == previous) return false;
    }
    return true;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer freePointColumnsPrefix(allocator, columns, initialized);
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return columns;
}

fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer freePointColumnsPrefix(allocator, columns, initialized);
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
        initialized += 1;
    }
    return columns;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    freePointColumnsPrefix(allocator, columns, columns.len);
}

fn freePointColumnsPrefix(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
    initialized: usize,
) void {
    for (columns[0..initialized]) |column| allocator.free(column);
    allocator.free(columns);
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var values: [4]QM31 = undefined;
    for (&values, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(values);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

comptime {
    if (OUTPUT_START + poseidon2_air.WIDTH != poseidon2_air.WIDE_COLUMN or
        interaction_column_count != 4 or constraint_count != 4)
    {
        @compileError("provider ordered-call AIR geometry drifted");
    }
}
