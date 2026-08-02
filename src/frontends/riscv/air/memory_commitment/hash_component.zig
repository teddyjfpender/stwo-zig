//! Prover/verifier adapter for the exact Merkle-node and Poseidon2 AIRs.

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
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const merkle_node = @import("merkle_node.zig");
const poseidon2_air = @import("poseidon2_air.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const N_POSEIDON_SHELL_CONSTRAINTS: usize = 3;
const N_POSEIDON_COMPONENT_CONSTRAINTS: usize =
    poseidon2_air.N_CONSTRAINTS + N_POSEIDON_SHELL_CONSTRAINTS + poseidon2_air.N_SUMS;

pub const Kind = enum { merkle, poseidon2 };

pub const HashComponent = struct {
    kind: Kind,
    log_size: u32,
    n_rows: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
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
        if (self.log_size >= 12) {
            component.domain_parallel_evaluator = evaluateDomainParallelAdapter;
        }
        return component;
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return switch (self.kind) {
            .merkle => merkle_node.N_CONSTRAINTS,
            .poseidon2 => N_POSEIDON_COMPONENT_CONSTRAINTS,
        };
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
        const preprocessed = try allocator.dupe(u32, &[_]u32{ self.log_size, self.log_size });
        errdefer allocator.free(preprocessed);
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
        const preprocessed = try currentPointColumns(allocator, 2, point);
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
        const main_mask = mask.items[1];
        const interaction_mask = mask.items[2];
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        if (preprocessed.len <= self.is_active_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
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
        const is_active = preprocessed[self.is_active_col_idx][0];

        switch (self.kind) {
            .merkle => {
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
                const constraints = poseidonConstraints(
                    main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.poseidon_claims,
                    self.relations,
                );
                for (constraints) |constraint| {
                    accumulator.accumulate(constraint.mul(denominator_inv));
                }
            },
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        return self.evaluateConstraintQuotientsOnDomainImpl(trace, accumulator, null);
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) !void {
        return self.evaluateConstraintQuotientsOnDomainImpl(trace, accumulator, pool);
    }

    fn evaluateConstraintQuotientsOnDomainImpl(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        maybe_pool: ?*work_pool.WorkPool,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const allocator = accumulator.allocator;
        const eval_log_size = self.maxConstraintLogDegreeBound();
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_main = nMainColumns(self.kind);
        const n_interaction = nInteractionColumns(self.kind);
        const n_committed = 2 + n_main + n_interaction;
        const n_sources = n_committed;
        const preprocessed = trace.polys.items[0];
        const main_polys = trace.polys.items[1];
        const interaction_polys = trace.polys.items[2];
        if (preprocessed.len <= self.is_active_col_idx or
            main_polys.len < self.main_col_offset + n_main or
            interaction_polys.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;

        const evaluations = try allocator.alloc([]const M31, n_sources);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        var source: usize = 0;
        const committed = try allocator.alloc(prover_component.Poly, n_committed);
        defer allocator.free(committed);
        committed[0] = preprocessed[self.is_first_col_idx];
        committed[1] = preprocessed[self.is_active_col_idx];
        for (0..n_main) |index| committed[2 + index] = main_polys[self.main_col_offset + index];
        for (0..n_interaction) |index| {
            committed[2 + n_main + index] = interaction_polys[self.interaction_col_offset + index];
        }
        for (committed) |poly| {
            try poly.validate();
            if (poly.log_size == eval_log_size) {
                evaluations[source] = poly.values;
            } else {
                const coefficients = poly.coefficients orelse return error.InvalidProofShape;
                if (coefficients.logSize() != self.log_size) return error.InvalidProofShape;
                const extended = try allocator.alloc(M31, eval_size);
                errdefer allocator.free(extended);
                const values = coefficients.coefficients();
                @memcpy(extended[0..values.len], values);
                @memset(extended[values.len..], M31.zero());
                try extension_buffers.append(allocator, extended);
                evaluations[source] = extended;
            }
            source += 1;
        }
        std.debug.assert(source == n_sources);
        var eval_twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
        defer prover_twiddles.deinitM31(allocator, &eval_twiddles);
        const eval_twiddle_view = prover_twiddles.TwiddleTree([]const M31).init(
            eval_twiddles.root_coset,
            eval_twiddles.twiddles,
            eval_twiddles.itwiddles,
        );
        try prover_poly.evaluateBuffersWithTwiddles(
            extension_buffers.items,
            eval_domain,
            eval_twiddle_view,
        );

        const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
        const extension_bits: u5 = @intCast(eval_log_size - self.log_size);
        var denominator_inv: [2]M31 = undefined;
        const denominator_count = @as(usize, 1) << extension_bits;
        std.debug.assert(denominator_count == denominator_inv.len);
        for (denominator_inv[0..denominator_count], 0..) |*inverse, index| {
            inverse.* = try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
            ).inv();
        }
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }},
        );
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const main_start: usize = 2;
        const interaction_start = main_start + n_main;
        const direct_store = column_accumulator.next_fresh_index == 0;
        const evaluation = HashDomainEvaluation{
            .component = self,
            .evaluations = evaluations,
            .main_start = main_start,
            .interaction_start = interaction_start,
            .column_accumulator = column_accumulator,
            .denominator_inv = denominator_inv,
            .direct_store = direct_store,
        };
        if (maybe_pool) |pool| {
            try evaluation.evaluateParallel(allocator, pool, eval_size);
        } else {
            try evaluation.evaluateRange(0, eval_size);
        }
        column_accumulator.next_fresh_index = if (direct_store) eval_size else null;
    }
};

const HashDomainEvaluation = struct {
    component: *const HashComponent,
    evaluations: []const []const M31,
    main_start: usize,
    interaction_start: usize,
    column_accumulator: *prover_air_accumulation.ColumnAccumulator,
    denominator_inv: [2]M31,
    direct_store: bool,

    fn evaluateParallel(
        self: *const @This(),
        allocator: std.mem.Allocator,
        pool: *work_pool.WorkPool,
        row_count: usize,
    ) !void {
        const worker_count = @min(pool.workerCount(), @max(@as(usize, 1), row_count / 4096));
        if (worker_count <= 1) return self.evaluateRange(0, row_count);

        const workers = try allocator.alloc(HashRangeWorker, worker_count);
        defer allocator.free(workers);
        for (workers, 0..) |*worker, index| {
            worker.* = .{
                .evaluation = self,
                .row_start = row_count * index / worker_count,
                .row_end = row_count * (index + 1) / worker_count,
            };
        }
        var wait_group = std.Thread.WaitGroup{};
        for (workers[1..]) |*worker| pool.spawnWg(&wait_group, HashRangeWorker.run, .{worker});
        HashRangeWorker.run(&workers[0]);
        wait_group.wait();
        for (workers) |worker| if (worker.err) |err| return err;
    }

    fn evaluateRange(self: *const @This(), row_start: usize, row_end: usize) !void {
        const component = self.component;
        const eval_log_size = component.maxConstraintLogDegreeBound();
        for (row_start..row_end) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                component.log_size,
                eval_log_size,
            );
            const is_first = QM31.fromBase(self.evaluations[0][row]);
            const is_active = QM31.fromBase(self.evaluations[1][row]);
            var row_evaluation = QM31.zero();
            switch (component.kind) {
                .merkle => {
                    const main = readMain(
                        merkle_node.N_MAIN_COLUMNS,
                        self.evaluations[self.main_start..][0..merkle_node.N_MAIN_COLUMNS],
                        row,
                    );
                    var sums: [merkle_node.N_SUMS]QM31 = undefined;
                    var previous: [merkle_node.N_SUMS]QM31 = undefined;
                    readInteraction(
                        merkle_node.N_SUMS,
                        self.evaluations,
                        self.interaction_start,
                        row,
                        previous_row,
                        &sums,
                        &previous,
                    );
                    const constraints = merkle_node.evaluate(
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        component.merkle_claims,
                        component.relations,
                    );
                    row_evaluation = combineConstraints(
                        self.column_accumulator.random_coeff_powers,
                        &constraints,
                    );
                },
                .poseidon2 => {
                    const main = readMain(
                        poseidon2_air.N_MAIN_COLUMNS,
                        self.evaluations[self.main_start..][0..poseidon2_air.N_MAIN_COLUMNS],
                        row,
                    );
                    var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                    var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                    readInteraction(
                        poseidon2_air.N_SUMS,
                        self.evaluations,
                        self.interaction_start,
                        row,
                        previous_row,
                        &sums,
                        &previous,
                    );
                    const constraints = poseidonConstraints(
                        main,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        component.poseidon_claims,
                        component.relations,
                    );
                    row_evaluation = combineConstraints(
                        self.column_accumulator.random_coeff_powers,
                        &constraints,
                    );
                },
            }
            const contribution = row_evaluation.mulM31(
                self.denominator_inv[row >> @intCast(component.log_size)],
            );
            const output = self.column_accumulator.col;
            if (self.direct_store) {
                output.set(row, contribution);
            } else {
                output.set(row, output.at(row).add(contribution));
            }
        }
    }
};

const HashRangeWorker = struct {
    evaluation: *const HashDomainEvaluation,
    row_start: usize,
    row_end: usize,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.evaluation.evaluateRange(self.row_start, self.row_end) catch |err| {
            self.err = err;
        };
    }
};

fn evaluateDomainParallelAdapter(
    raw_context: *const anyopaque,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    pool: *work_pool.WorkPool,
) anyerror!void {
    const self: *const HashComponent = @ptrCast(@alignCast(raw_context));
    return self.evaluateConstraintQuotientsOnDomainParallel(trace_data, accumulator, pool);
}

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

fn poseidonConstraints(
    main: [poseidon2_air.N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [poseidon2_air.N_SUMS]QM31,
    previous: [poseidon2_air.N_SUMS]QM31,
    claims: [poseidon2_air.N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_POSEIDON_COMPONENT_CONSTRAINTS]QM31 {
    const air_constraints = poseidon2_air.evaluate(main);
    const interaction_constraints = poseidon2_air.interactionConstraints(
        main,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
    var constraints: [N_POSEIDON_COMPONENT_CONSTRAINTS]QM31 = undefined;
    @memcpy(constraints[0..poseidon2_air.N_CONSTRAINTS], &air_constraints);
    constraints[poseidon2_air.N_CONSTRAINTS] = main[0].sub(is_active);
    const narrow_mode = poseidon2_air.narrowModeConstraints(main);
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

fn sampleMain(
    comptime n: usize,
    columns: [][]QM31,
    offset: usize,
) ![n]QM31 {
    if (columns.len < offset + n) return error.InvalidProofShape;
    var result: [n]QM31 = undefined;
    for (&result, columns[offset..][0..n]) |*value, column| {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
    return result;
}

fn sampleInteraction(
    comptime n: usize,
    columns: [][]QM31,
    offset: usize,
    sums: *[n]QM31,
    previous: *[n]QM31,
) !void {
    for (0..n) |index| {
        sums[index] = try sampledSecure(columns, offset + 4 * index, 0);
        previous[index] = try sampledSecure(columns, offset + 4 * index, 1);
    }
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn readMain(comptime n: usize, columns: []const []const M31, row: usize) [n]QM31 {
    var result: [n]QM31 = undefined;
    for (&result, columns) |*value, column| value.* = QM31.fromBase(column[row]);
    return result;
}

fn readInteraction(
    comptime n: usize,
    evaluations: []const []const M31,
    interaction_start: usize,
    row: usize,
    previous_row: usize,
    sums: *[n]QM31,
    previous: *[n]QM31,
) void {
    for (0..n) |index| {
        sums[index] = secureAt(evaluations[interaction_start + 4 * index ..][0..4], row);
        previous[index] = secureAt(
            evaluations[interaction_start + 4 * index ..][0..4],
            previous_row,
        );
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn combineConstraints(powers: []const QM31, constraints: []const QM31) QM31 {
    var result = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        result = result.add(powers[powers.len - 1 - index].mul(constraint));
    }
    return result;
}

test "hash component: exact shapes remain pinned" {
    try std.testing.expectEqual(@as(usize, 445), nMainColumns(.poseidon2));
    try std.testing.expectEqual(@as(usize, 8), nInteractionColumns(.poseidon2));
    try std.testing.expectEqual(@as(usize, 435), N_POSEIDON_COMPONENT_CONSTRAINTS);
    try std.testing.expectEqual(@as(usize, 10), nMainColumns(.merkle));
    try std.testing.expectEqual(@as(usize, 12), nInteractionColumns(.merkle));
}

test "hash component: large domains expose one bounded row splitter" {
    const relations = relations_mod.Relations.dummy();
    var component = HashComponent{
        .kind = .poseidon2,
        .log_size = 11,
        .n_rows = 1,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = &relations,
    };
    try std.testing.expect(component.asProverComponent().domain_parallel_evaluator == null);
    component.log_size = 12;
    const split = component.asProverComponent();
    try std.testing.expect(split.domain_parallel_evaluator != null);
    try std.testing.expect(!split.pool_exclusive_domain);
}

test "hash component: RISC-V Poseidon shell binds selector and narrow mode" {
    const row = poseidon2_air.fill(poseidon2_air.Call.narrow(1, 2));
    var main: [poseidon2_air.N_MAIN_COLUMNS]QM31 = undefined;
    for (&main, row) |*dst, value| dst.* = QM31.fromBase(value);
    const zeros = [_]QM31{QM31.zero()} ** poseidon2_air.N_SUMS;
    const relations = relations_mod.Relations.dummy();
    const honest = poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (honest[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS].isZero());
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS + 2].isZero());

    const inactive = poseidonConstraints(
        main,
        QM31.zero(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (inactive[0..poseidon2_air.N_CONSTRAINTS], honest[0..poseidon2_air.N_CONSTRAINTS]) |actual, expected| {
        try std.testing.expect(actual.eql(expected));
    }
    try std.testing.expect(!inactive[poseidon2_air.N_CONSTRAINTS].isZero());

    var wide_call = poseidon2_air.Call.narrow(1, 2);
    wide_call.wide = true;
    const wide_row = poseidon2_air.fill(wide_call);
    for (&main, wide_row) |*dst, value| dst.* = QM31.fromBase(value);
    const wide = poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (wide[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(!wide[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(wide[poseidon2_air.N_CONSTRAINTS + 2].isZero());

    var io_call = poseidon2_air.Call.narrow(1, 2);
    io_call.io = true;
    const io_row = poseidon2_air.fill(io_call);
    for (&main, io_row) |*dst, value| dst.* = QM31.fromBase(value);
    const io = poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (io[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(io[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(!io[poseidon2_air.N_CONSTRAINTS + 2].isZero());
}

fn allocateHashMetadata(
    allocator: std.mem.Allocator,
    component: *const HashComponent,
) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
}

test "hash component: metadata allocations roll back completely" {
    const relations = relations_mod.Relations.dummy();
    const component = HashComponent{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 1,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = &relations,
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateHashMetadata,
        .{&component},
    );
}
