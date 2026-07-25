//! Exact pinned-Stwo Poseidon2 transitions and 16-tuple LogUp AIR.

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
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_circle = @import("stwo_prover_impl").poly.circle;
const prover_twiddles = @import("stwo_prover_impl").poly.twiddles;
const input = @import("input.zig");
const interaction = @import("interaction.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const N_TRANSITION_CONSTRAINTS: usize = input.N_INSTANCES_PER_ROW *
    (input.N_FULL_ROUNDS * input.N_STATE + input.N_PARTIAL_ROUNDS);
pub const N_LOGUP_CONSTRAINTS: usize = input.N_INSTANCES_PER_ROW;
pub const N_CONSTRAINTS: usize = N_TRANSITION_CONSTRAINTS + N_LOGUP_CONSTRAINTS;

const RowEvaluation = struct {
    transitions: [N_TRANSITION_CONSTRAINTS]QM31,
    numerators: [N_LOGUP_CONSTRAINTS]QM31,
    denominators: [N_LOGUP_CONSTRAINTS]QM31,
};

/// Complete expanded-domain row consumed by the exact composition kernel.
/// `interaction_previous_last` is the previous-circle-row value of the final
/// secure interaction column; the other seven columns have no row offset.
pub const DomainRowInput = struct {
    log_n_rows: u32,
    main: [input.N_COLUMNS]M31,
    interaction_current: [N_LOGUP_CONSTRAINTS]QM31,
    interaction_previous_last: QM31,
    lookup_elements: interaction.LookupElements,
    claimed_sum: QM31,
    random_powers: [N_CONSTRAINTS]QM31,
    denominator_inverse: M31,
};

/// Scalar oracle for one exact expanded-domain composition row.
pub fn evaluateDomainRow(row: DomainRowInput) !QM31 {
    if (row.log_n_rows >= 31) return error.InvalidProofShape;
    const component = Component{
        .log_n_rows = row.log_n_rows,
        .lookup_elements = row.lookup_elements,
        .claimed_sum = row.claimed_sum,
    };
    var main: [input.N_COLUMNS]QM31 = undefined;
    for (&main, row.main) |*out, value| out.* = QM31.fromBase(value);
    const evaluated = evaluateRow(&component, main);

    var combined = QM31.zero();
    var constraint_index: usize = 0;
    for (evaluated.transitions) |constraint| {
        combined = combined.add(
            row.random_powers[N_CONSTRAINTS - 1 - constraint_index]
                .mul(constraint),
        );
        constraint_index += 1;
    }

    const inverse_rows = if (row.log_n_rows == 0)
        M31.one()
    else
        M31.fromCanonical(
            @as(u32, 1) << @intCast(31 - row.log_n_rows),
        );
    const shift = row.claimed_sum.mulM31(inverse_rows);
    var previous_column = QM31.zero();
    for (0..N_LOGUP_CONSTRAINTS) |rep| {
        const current = row.interaction_current[rep];
        const diff = if (rep + 1 == N_LOGUP_CONSTRAINTS)
            current.sub(row.interaction_previous_last)
                .sub(previous_column).add(shift)
        else
            current.sub(previous_column);
        const constraint = diff.mul(evaluated.denominators[rep])
            .sub(evaluated.numerators[rep]);
        combined = combined.add(
            row.random_powers[N_CONSTRAINTS - 1 - constraint_index]
                .mul(constraint),
        );
        constraint_index += 1;
        previous_column = current;
    }
    std.debug.assert(constraint_index == N_CONSTRAINTS);
    return combined.mulM31(row.denominator_inverse);
}

pub const Component = struct {
    log_n_rows: u32,
    lookup_elements: interaction.LookupElements,
    claimed_sum: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_n_rows + 2;
    }

    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 2;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, input.N_COLUMNS, self.log_n_rows);
        errdefer allocator.free(main);
        const interaction_logs = try filledLogs(
            allocator,
            interaction.N_COLUMNS,
            self.log_n_rows,
        );
        errdefer allocator.free(interaction_logs);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction_logs }),
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed);
        const main = try currentPointColumns(allocator, input.N_COLUMNS, point);
        errdefer freePointColumns(allocator, main);
        const secure = try interactionPointColumns(
            allocator,
            point,
            previousRowPoint(max_log_degree_bound, point),
        );
        errdefer freePointColumns(allocator, secure);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const main = mask.items[1];
        const secure = mask.items[2];
        try validatePointMask(mask.items[0], main, secure);

        var main_values: [input.N_COLUMNS]QM31 = undefined;
        for (&main_values, main) |*out, column| out.* = column[0];
        const evaluated = evaluateRow(self, main_values);

        const sample_fold = max_log_degree_bound - self.log_n_rows;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_n_rows).coset(),
            point.repeatedDouble(sample_fold),
        ).inv();
        for (evaluated.transitions) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
        }
        try self.accumulatePointLogup(secure, evaluated, denominator_inv, accumulator);
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len != 3 or
            trace.polys.items[0].len != 0 or
            trace.polys.items[1].len != input.N_COLUMNS or
            trace.polys.items[2].len != interaction.N_COLUMNS)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.maxConstraintLogDegreeBound();
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const source_count = input.N_COLUMNS + interaction.N_COLUMNS;
        const evaluations = try allocator.alloc([]const M31, source_count);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        var source: usize = 0;
        for (trace.polys.items[1..3]) |tree| {
            for (tree) |poly| {
                evaluations[source] = try evaluationOnDomain(
                    allocator,
                    poly,
                    self.log_n_rows,
                    eval_log_size,
                    eval_size,
                    &extension_buffers,
                );
                source += 1;
            }
        }
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                eval_domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            const view = prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover_circle.poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                eval_domain,
                view,
            );
        }

        const trace_coset = canonic.CanonicCoset.new(self.log_n_rows).coset();
        var denominator_inv: [4]M31 = undefined;
        for (&denominator_inv, 0..) |*value, i| {
            value.* = try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(i),
            ).inv();
        }
        utils.bitReverse(M31, &denominator_inv);
        var accumulators = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = self.nConstraints(),
        }});
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const secure_sources = evaluations[input.N_COLUMNS..];
        const denominator_shift: std.math.Log2Int(usize) =
            @intCast(self.log_n_rows);

        for (0..eval_size) |row| {
            var main_values: [input.N_COLUMNS]QM31 = undefined;
            for (&main_values, evaluations[0..input.N_COLUMNS]) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            const evaluated = evaluateRow(self, main_values);
            var combined = QM31.zero();
            var constraint_index: usize = 0;
            for (evaluated.transitions) |constraint| {
                combined = addWeighted(column_accumulator, combined, constraint, constraint_index);
                constraint_index += 1;
            }

            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_n_rows,
                eval_log_size,
            );
            const shift = try self.claimed_sum.divM31(
                M31.fromU64(@as(u64, 1) << @intCast(self.log_n_rows)),
            );
            var previous_column = QM31.zero();
            for (0..N_LOGUP_CONSTRAINTS) |rep| {
                const current = secureAt(secure_sources, rep, row);
                const diff = if (rep + 1 == N_LOGUP_CONSTRAINTS)
                    current.sub(secureAt(secure_sources, rep, previous_row))
                        .sub(previous_column).add(shift)
                else
                    current.sub(previous_column);
                const constraint = diff.mul(evaluated.denominators[rep])
                    .sub(evaluated.numerators[rep]);
                combined = addWeighted(
                    column_accumulator,
                    combined,
                    constraint,
                    constraint_index,
                );
                constraint_index += 1;
                previous_column = current;
            }
            std.debug.assert(constraint_index == self.nConstraints());
            column_accumulator.accumulate(
                row,
                combined.mulM31(denominator_inv[row >> denominator_shift]),
            );
        }
    }

    fn accumulatePointLogup(
        self: *const @This(),
        secure: [][]QM31,
        evaluated: RowEvaluation,
        denominator_inv: QM31,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
    ) !void {
        const shift = try self.claimed_sum.divM31(
            M31.fromU64(@as(u64, 1) << @intCast(self.log_n_rows)),
        );
        var previous_column = QM31.zero();
        for (0..N_LOGUP_CONSTRAINTS) |rep| {
            const final_column = rep + 1 == N_LOGUP_CONSTRAINTS;
            const current = try sampledSecure(secure, rep, @intFromBool(final_column));
            const diff = if (final_column)
                current.sub(try sampledSecure(secure, rep, 0)).sub(previous_column).add(shift)
            else
                current.sub(previous_column);
            accumulator.accumulate(
                diff.mul(evaluated.denominators[rep])
                    .sub(evaluated.numerators[rep])
                    .mul(denominator_inv),
            );
            previous_column = current;
        }
    }
};

fn evaluateRow(component: *const Component, main: [input.N_COLUMNS]QM31) RowEvaluation {
    var result: RowEvaluation = undefined;
    var column: usize = 0;
    var constraint: usize = 0;
    for (0..input.N_INSTANCES_PER_ROW) |rep| {
        var state: [input.N_STATE]QM31 = undefined;
        var initial: [input.N_STATE]QM31 = undefined;
        for (&state, &initial) |*value, *first| {
            value.* = main[column];
            first.* = value.*;
            column += 1;
        }

        for (0..input.N_HALF_FULL_ROUNDS) |_| {
            applyExternalRound(&state);
            for (&state) |*value| {
                const stored = main[column];
                result.transitions[constraint] = value.*.sub(stored);
                value.* = stored;
                column += 1;
                constraint += 1;
            }
        }
        for (0..input.N_PARTIAL_ROUNDS) |_| {
            state[0] = state[0].addM31(M31.fromCanonical(1234));
            applyInternalRoundMatrix(&state);
            state[0] = pow5(state[0]);
            const stored = main[column];
            result.transitions[constraint] = state[0].sub(stored);
            state[0] = stored;
            column += 1;
            constraint += 1;
        }
        for (0..input.N_HALF_FULL_ROUNDS) |_| {
            applyExternalRound(&state);
            for (&state) |*value| {
                const stored = main[column];
                result.transitions[constraint] = value.*.sub(stored);
                value.* = stored;
                column += 1;
                constraint += 1;
            }
        }

        const initial_denominator = component.lookup_elements.combineSecure(initial);
        const final_denominator = component.lookup_elements.combineSecure(state);
        result.numerators[rep] = final_denominator.sub(initial_denominator);
        result.denominators[rep] = initial_denominator.mul(final_denominator);
    }
    std.debug.assert(column == input.N_COLUMNS);
    std.debug.assert(constraint == N_TRANSITION_CONSTRAINTS);
    return result;
}

fn applyExternalRound(state: *[input.N_STATE]QM31) void {
    for (state) |*value| value.* = value.*.addM31(M31.fromCanonical(1234));
    applyExternalRoundMatrix(state);
    for (state) |*value| value.* = pow5(value.*);
}

fn applyM4(x: [4]QM31) [4]QM31 {
    const t0 = x[0].add(x[1]);
    const t02 = t0.add(t0);
    const t1 = x[2].add(x[3]);
    const t12 = t1.add(t1);
    const t2 = x[1].add(x[1]).add(t1);
    const t3 = x[3].add(x[3]).add(t0);
    const t4 = t12.add(t12).add(t3);
    const t5 = t02.add(t02).add(t2);
    return .{ t3.add(t5), t5, t2.add(t4), t4 };
}

fn applyExternalRoundMatrix(state: *[input.N_STATE]QM31) void {
    for (0..4) |i| {
        const offset = i * 4;
        const mixed = applyM4(state[offset..][0..4].*);
        for (0..4) |j| state[offset + j] = mixed[j];
    }
    for (0..4) |j| {
        const sum = state[j].add(state[j + 4]).add(state[j + 8]).add(state[j + 12]);
        for (0..4) |i| {
            const index = i * 4 + j;
            state[index] = state[index].add(sum);
        }
    }
}

fn applyInternalRoundMatrix(state: *[input.N_STATE]QM31) void {
    var sum = state[0];
    for (state[1..]) |value| sum = sum.add(value);
    for (state, 0..) |*value, i| {
        value.* = value.*.mulM31(
            M31.fromU64(@as(u64, 1) << @intCast(i + 1)),
        ).add(sum);
    }
}

fn pow5(value: QM31) QM31 {
    const squared = value.square();
    return squared.square().mul(value);
}

fn addWeighted(
    accumulator: *const prover_air_accumulation.ColumnAccumulator,
    combined: QM31,
    constraint: QM31,
    constraint_index: usize,
) QM31 {
    return combined.add(
        accumulator.random_coeff_powers[accumulator.random_coeff_powers.len - 1 - constraint_index]
            .mul(constraint),
    );
}

fn sampledSecure(columns: [][]QM31, secure_index: usize, point_index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, coordinate| {
        const column = columns[secure_index * 4 + coordinate];
        if (column.len <= point_index) return error.InvalidProofShape;
        value.* = column[point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, secure_index: usize, row: usize) QM31 {
    const start = secure_index * 4;
    return QM31.fromM31(
        columns[start][row],
        columns[start + 1][row],
        columns[start + 2][row],
        columns[start + 3][row],
    );
}

fn validatePointMask(empty: [][]QM31, main: [][]QM31, secure: [][]QM31) !void {
    if (empty.len != 0 or main.len != input.N_COLUMNS or
        secure.len != interaction.N_COLUMNS)
    {
        return error.InvalidProofShape;
    }
    for (main) |column| if (column.len != 1) return error.InvalidProofShape;
    for (secure[0 .. secure.len - 4]) |column| {
        if (column.len != 1) return error.InvalidProofShape;
    }
    for (secure[secure.len - 4 ..]) |column| {
        if (column.len != 2) return error.InvalidProofShape;
    }
}

fn interactionPointColumns(
    allocator: std.mem.Allocator,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, interaction.N_COLUMNS);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns[0 .. columns.len - 4]) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    for (columns[columns.len - 4 ..]) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ previous, point });
        initialized += 1;
    }
    return columns;
}

fn evaluationOnDomain(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
    eval_size: usize,
    buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log_size) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

fn filledLogs(allocator: std.mem.Allocator, n: usize, value: u32) ![]u32 {
    const result = try allocator.alloc(u32, n);
    @memset(result, value);
    return result;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    n: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, n);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return columns;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn previousTraceRow(row: usize, log_size: u32) usize {
    const n = @as(usize, 1) << @intCast(log_size);
    const circle_index = utils.bitReverseIndex(row, log_size);
    const coset_index = utils.circleDomainIndexToCosetIndex(circle_index, log_size);
    const previous_coset_index = (coset_index + n - 1) % n;
    const previous_circle_index = utils.cosetIndexToCircleDomainIndex(
        previous_coset_index,
        log_size,
    );
    return utils.bitReverseIndex(previous_circle_index, log_size);
}

test "exact Poseidon component exposes pinned AIR geometry" {
    const component = Component{
        .log_n_rows = 4,
        .lookup_elements = interaction.LookupElements.fromZAlpha(QM31.one(), QM31.one()),
        .claimed_sum = QM31.zero(),
    };
    try std.testing.expectEqual(@as(usize, 1144), component.nConstraints());
    try std.testing.expectEqual(@as(u32, 6), component.maxConstraintLogDegreeBound());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 1264), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 32), bounds.items[2].len);
}

test "exact Poseidon witness satisfies transitions and LogUp row constraints" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{ .log_n_instances = 7 });
    defer prepared.deinit(allocator);
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try interaction.generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);
    const component = Component{
        .log_n_rows = 4,
        .lookup_elements = generated.lookup_elements,
        .claimed_sum = generated.claimed_sum,
    };
    const main = prepared.trace.main.columns.?;
    const secure = generated.columns.columns.?;
    const n: usize = 16;
    const shift = try generated.claimed_sum.divM31(M31.fromCanonical(n));

    for (0..n) |row| {
        var main_values: [input.N_COLUMNS]QM31 = undefined;
        for (&main_values, main) |*out, column| out.* = QM31.fromBase(column.values[row]);
        const evaluated = evaluateRow(&component, main_values);
        for (evaluated.transitions) |constraint| {
            try std.testing.expect(constraint.isZero());
        }
        const previous_row = previousTraceRow(row, 4);
        var previous_column = QM31.zero();
        for (0..N_LOGUP_CONSTRAINTS) |rep| {
            const current = secureAtPrepared(secure, rep, row);
            const diff = if (rep + 1 == N_LOGUP_CONSTRAINTS)
                current.sub(secureAtPrepared(secure, rep, previous_row))
                    .sub(previous_column).add(shift)
            else
                current.sub(previous_column);
            try std.testing.expect(
                diff.mul(evaluated.denominators[rep])
                    .sub(evaluated.numerators[rep]).isZero(),
            );
            previous_column = current;
        }
    }
}

fn secureAtPrepared(
    columns: []const @import("stwo_prover_impl").pcs.ColumnEvaluation,
    secure_index: usize,
    row: usize,
) QM31 {
    const start = secure_index * 4;
    return QM31.fromM31(
        columns[start].values[row],
        columns[start + 1].values[row],
        columns[start + 2].values[row],
        columns[start + 3].values[row],
    );
}
