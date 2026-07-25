//! Exact pinned-Stwo Plonk algebraic and two-column LogUp AIR.

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
const interaction = @import("interaction.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const DomainRowInput = struct {
    log_n_rows: u32,
    preprocessed: [4]M31,
    main: [4]M31,
    first_sum: QM31,
    cumulative_previous: QM31,
    cumulative_current: QM31,
    lookup_elements: interaction.LookupElements,
    claimed_sum: [4]M31,
    random_powers: [3]QM31,
    denominator_inverse: M31,
};

pub const Component = struct {
    log_n_rows: u32,
    lookup_elements: interaction.LookupElements,
    claimed_sum: [4]M31,

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
        return 3;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_n_rows + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(allocator, 4, self.log_n_rows);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, 4, self.log_n_rows);
        errdefer allocator.free(main);
        const interaction_logs = try filledLogs(allocator, 8, self.log_n_rows);
        errdefer allocator.free(interaction_logs);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe(
                []u32,
                &[_][]u32{ preprocessed, main, interaction_logs },
            ),
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try currentPointColumns(allocator, 4, point);
        errdefer freeMaskColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, 4, point);
        errdefer freeMaskColumns(allocator, main);

        const interaction_columns = try allocator.alloc([]CirclePointQM31, 8);
        var initialized: usize = 0;
        errdefer {
            for (interaction_columns[0..initialized]) |column| allocator.free(column);
            allocator.free(interaction_columns);
        }
        for (interaction_columns[0..4]) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{point});
            initialized += 1;
        }
        const previous = previousRowPoint(max_log_degree_bound, point);
        for (interaction_columns[4..8]) |*column| {
            column.* = try allocator.dupe(
                CirclePointQM31,
                &[_]CirclePointQM31{ previous, point },
            );
            initialized += 1;
        }

        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe(
                [][]CirclePointQM31,
                &[_][][]CirclePointQM31{ preprocessed, main, interaction_columns },
            ),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &[_]usize{ 0, 1, 2, 3 });
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const interaction_values = mask.items[2];
        try validatePointMask(preprocessed, main, interaction_values);

        const sample_fold = max_log_degree_bound - self.log_n_rows;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_n_rows).coset(),
            point.repeatedDouble(sample_fold),
        ).inv();

        const algebraic = algebraicConstraint(
            preprocessed[3][0],
            main[1][0],
            main[2][0],
            main[3][0],
        );
        const q0 = self.lookup_elements.combineSecure(preprocessed[0][0], main[1][0]);
        const q1 = self.lookup_elements.combineSecure(preprocessed[1][0], main[2][0]);
        const first_sum = try sampledSecure(interaction_values, 0, 0);
        const first_logup = first_sum.mul(q0).mul(q1).sub(q0.add(q1));

        const q2 = self.lookup_elements.combineSecure(preprocessed[2][0], main[3][0]);
        const previous = try sampledSecure(interaction_values, 4, 0);
        const current = try sampledSecure(interaction_values, 4, 1);
        const n = M31.fromU64(@as(u64, 1) << @intCast(self.log_n_rows));
        const shifted_diff = current.sub(previous).sub(first_sum)
            .add(try self.claimedSum().divM31(n));
        const final_logup = shifted_diff.mul(q2).add(main[0][0]);

        accumulator.accumulate(algebraic.mul(denominator_inv));
        accumulator.accumulate(first_logup.mul(denominator_inv));
        accumulator.accumulate(final_logup.mul(denominator_inv));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        if (trace.polys.items[0].len != 4 or
            trace.polys.items[1].len != 4 or
            trace.polys.items[2].len != 8)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.log_n_rows + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        var evaluations: [16][]const M31 = undefined;
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        var index: usize = 0;
        for (trace.polys.items[0..3]) |tree| {
            for (tree) |poly| {
                evaluations[index] = try evaluationOnDomain(
                    allocator,
                    poly,
                    self.log_n_rows,
                    eval_log_size,
                    eval_size,
                    &extension_buffers,
                );
                index += 1;
            }
        }
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
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
        const denominator_inv = [_]M31{
            try core_constraints.cosetVanishing(M31, trace_coset, eval_domain.at(0)).inv(),
            try core_constraints.cosetVanishing(M31, trace_coset, eval_domain.at(1)).inv(),
        };
        var accumulators = try accumulator.columns(
            allocator,
            &[_]prover_air_accumulation.ColumnRequest{.{
                .log_size = eval_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(accumulators);
        var column_accumulator = &accumulators[0];

        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_n_rows);
        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_n_rows,
                eval_log_size,
            );
            const powers = column_accumulator.random_coeff_powers;
            if (powers.len < 3) return error.InvalidProofShape;
            const combined = try evaluateDomainRow(.{
                .log_n_rows = self.log_n_rows,
                .preprocessed = .{
                    evaluations[0][row],
                    evaluations[1][row],
                    evaluations[2][row],
                    evaluations[3][row],
                },
                .main = .{
                    evaluations[4][row],
                    evaluations[5][row],
                    evaluations[6][row],
                    evaluations[7][row],
                },
                .first_sum = secureAt(evaluations[8..12], row),
                .cumulative_previous = secureAt(
                    evaluations[12..16],
                    previous_row,
                ),
                .cumulative_current = secureAt(
                    evaluations[12..16],
                    row,
                ),
                .lookup_elements = self.lookup_elements,
                .claimed_sum = self.claimed_sum,
                .random_powers = .{
                    powers[powers.len - 3],
                    powers[powers.len - 2],
                    powers[powers.len - 1],
                },
                .denominator_inverse = denominator_inv[row >> denominator_shift],
            });
            column_accumulator.accumulate(
                row,
                combined,
            );
        }
    }

    fn claimedSum(self: *const @This()) QM31 {
        return QM31.fromM31Array(self.claimed_sum);
    }
};

pub fn evaluateDomainRow(input: DomainRowInput) !QM31 {
    const algebraic = algebraicConstraint(
        QM31.fromBase(input.preprocessed[3]),
        QM31.fromBase(input.main[1]),
        QM31.fromBase(input.main[2]),
        QM31.fromBase(input.main[3]),
    );
    const q0 = input.lookup_elements.combineBase(
        input.preprocessed[0],
        input.main[1],
    );
    const q1 = input.lookup_elements.combineBase(
        input.preprocessed[1],
        input.main[2],
    );
    const first_logup = input.first_sum.mul(q0).mul(q1).sub(q0.add(q1));
    const q2 = input.lookup_elements.combineBase(
        input.preprocessed[2],
        input.main[3],
    );
    const rows = M31.fromU64(
        @as(u64, 1) << @intCast(input.log_n_rows),
    );
    const shift = try QM31.fromM31Array(input.claimed_sum).divM31(rows);
    const final_logup = input.cumulative_current
        .sub(input.cumulative_previous)
        .sub(input.first_sum)
        .add(shift)
        .mul(q2)
        .addM31(input.main[0]);
    return input.random_powers[2].mul(algebraic)
        .add(input.random_powers[1].mul(first_logup))
        .add(input.random_powers[0].mul(final_logup))
        .mulM31(input.denominator_inverse);
}

fn algebraicConstraint(op: QM31, a: QM31, b: QM31, c: QM31) QM31 {
    return c.sub(op.mul(a.add(b))).add(QM31.one().sub(op).mul(a).mul(b));
}

fn sampledSecure(columns: [][]QM31, base: usize, point_index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |coordinate| {
        if (columns[base + coordinate].len <= point_index) return error.InvalidProofShape;
        coordinates[coordinate] = columns[base + coordinate][point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

fn validatePointMask(preprocessed: [][]QM31, main: [][]QM31, inter: [][]QM31) !void {
    if (preprocessed.len != 4 or main.len != 4 or inter.len != 8)
        return error.InvalidProofShape;
    for (preprocessed) |column| if (column.len != 1) return error.InvalidProofShape;
    for (main) |column| if (column.len != 1) return error.InvalidProofShape;
    for (inter[0..4]) |column| if (column.len != 1) return error.InvalidProofShape;
    for (inter[4..8]) |column| if (column.len != 2) return error.InvalidProofShape;
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

fn filledLogs(allocator: std.mem.Allocator, n: usize, log_size: u32) ![]u32 {
    const values = try allocator.alloc(u32, n);
    @memset(values, log_size);
    return values;
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
        column.* = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{point});
        initialized += 1;
    }
    return columns;
}

fn freeMaskColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    const lifted = CirclePointQM31{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    };
    return point.sub(lifted);
}

test "exact Plonk component exposes the pinned three-tree geometry" {
    const component = Component{
        .log_n_rows = 4,
        .lookup_elements = .{
            .z = QM31.one().toM31Array(),
            .alpha = QM31.one().toM31Array(),
        },
        .claimed_sum = QM31.zero().toM31Array(),
    };
    try std.testing.expectEqual(@as(usize, 3), component.nConstraints());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 8), bounds.items[2].len);
}
