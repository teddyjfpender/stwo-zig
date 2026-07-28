//! Real wide-Fibonacci AIR component shared by the prover and verifier.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_circle = @import("stwo_prover_engine").poly.circle;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const trace_input = @import("trace.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("stwo_core").circle.CirclePointQM31;

pub const Component = struct {
    statement: trace_input.Statement,

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
        var component = Adapter.asProverComponent(self);
        component.backend_composition_capability = .{
            .quadratic_sum_squares_v1 = .{
                .trace_tree_index = 1,
                .first_column = 0,
            },
        };
        return component;
    }

    pub fn nConstraints(self: *const @This()) usize {
        return @as(usize, @intCast(self.statement.sequence_len)) - 2;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.statement.log_n_rows + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, @intCast(self.statement.sequence_len));
        errdefer allocator.free(main);
        @memset(main, self.statement.log_n_rows);

        const trees = try allocator.dupe([]u32, &[_][]u32{ preprocessed, main });
        return core_air_components.TraceLogDegreeBounds.initOwned(trees);
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed_cols = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed_cols);

        const n_cols: usize = @intCast(self.statement.sequence_len);
        const main_cols = try allocator.alloc([]CirclePointQM31, n_cols);
        var initialized_cols: usize = 0;
        errdefer {
            for (main_cols[0..initialized_cols]) |col| allocator.free(col);
            allocator.free(main_cols);
        }

        for (main_cols) |*col| {
            col.* = try allocator.alloc(CirclePointQM31, 1);
            initialized_cols += 1;
            col.*[0] = point;
        }

        const trees = try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
            preprocessed_cols,
            main_cols,
        });
        return core_air_components.MaskPoints.initOwned(trees);
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
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        if (mask.items.len <= 1) return error.InvalidProofShape;
        const main = mask.items[1];
        const n_cols: usize = @intCast(self.statement.sequence_len);
        if (main.len != n_cols) return error.InvalidProofShape;
        for (main) |column| {
            if (column.len != 1) return error.InvalidProofShape;
        }

        const denominator = core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.statement.log_n_rows).coset(),
            point,
        );
        const denominator_inv = try denominator.inv();

        var a = main[0][0];
        var b = main[1][0];
        for (main[2..]) |column| {
            const c = column[0];
            const constraint = c.sub(a.square().add(b.square()));
            evaluation_accumulator.accumulate(constraint.mul(denominator_inv));
            a = b;
            b = c;
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const allocator = evaluation_accumulator.allocator;
        if (trace.polys.items.len <= 1) return error.InvalidProofShape;
        const main = trace.polys.items[1];
        const n_cols: usize = @intCast(self.statement.sequence_len);
        if (main.len != n_cols) return error.InvalidProofShape;

        const eval_log_size = self.statement.log_n_rows + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();

        const evaluations = try allocator.alloc([]const M31, n_cols);
        defer allocator.free(evaluations);

        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        for (main, 0..) |poly, i| {
            try poly.validate();
            if (poly.log_size == eval_log_size) {
                // With one bit of PCS blowup the retained commitment column is
                // already the canonical quotient domain in bit-reversed order.
                evaluations[i] = poly.values;
                continue;
            }

            const coefficients = poly.coefficients orelse return error.InvalidProofShape;
            if (coefficients.logSize() != self.statement.log_n_rows) {
                return error.InvalidProofShape;
            }

            const values = try allocator.alloc(M31, eval_size);
            errdefer allocator.free(values);
            const coefficient_values = coefficients.coefficients();
            @memcpy(values[0..coefficient_values.len], coefficient_values);
            @memset(values[coefficient_values.len..], M31.zero());
            try extension_buffers.append(allocator, values);
            evaluations[i] = values;
        }

        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            const twiddle_view = prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover_circle.poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                eval_domain,
                twiddle_view,
            );
        }

        const trace_coset = canonic.CanonicCoset.new(self.statement.log_n_rows).coset();
        const denominator_inv = [_]M31{
            try core_constraints.cosetVanishing(M31, trace_coset, eval_domain.at(0)).inv(),
            try core_constraints.cosetVanishing(M31, trace_coset, eval_domain.at(1)).inv(),
        };

        var accumulators = try evaluation_accumulator.columns(
            allocator,
            &[_]prover_air_accumulation.ColumnRequest{.{
                .log_size = eval_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(accumulators);
        var column_accumulator = &accumulators[0];

        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.statement.log_n_rows);
        for (0..eval_size) |row| {
            var a = evaluations[0][row];
            var b = evaluations[1][row];
            var row_evaluation = QM31.zero();
            for (evaluations[2..], 0..) |column, constraint_index| {
                const c = column[row];
                const constraint = c.sub(a.square().add(b.square()));
                const power_index = self.nConstraints() - 1 - constraint_index;
                row_evaluation = row_evaluation.add(
                    column_accumulator.random_coeff_powers[power_index].mulM31(constraint),
                );
                a = b;
                b = c;
            }
            column_accumulator.accumulate(
                row,
                row_evaluation.mulM31(denominator_inv[row >> denominator_shift]),
            );
        }
    }
};

test "wide Fibonacci component: OODS quotient and coefficient order match scalar recurrence" {
    const point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const alpha = QM31.fromU32Unchecked(2, 3, 5, 7);
    var values = [_]QM31{
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(4)),
        QM31.fromBase(M31.fromCanonical(31)),
        QM31.fromBase(M31.fromCanonical(19)),
        QM31.fromBase(M31.fromCanonical(47)),
    };
    var main = [_][]QM31{
        values[0..1],
        values[1..2],
        values[2..3],
        values[3..4],
        values[4..5],
    };
    var preprocessed = [_][]QM31{};
    var trees = [_][][]QM31{ preprocessed[0..], main[0..] };
    const mask = core_air_components.MaskValues.initOwned(trees[0..]);

    const component = Component{ .statement = .{ .log_n_rows = 5, .sequence_len = 5 } };
    try std.testing.expectEqual(@as(usize, 3), component.nConstraints());
    const backend_component = component.asProverComponent();
    const capability = backend_component.backend_composition_capability orelse
        return error.MissingBackendCompositionCapability;
    switch (capability) {
        .quadratic_sum_squares_v1 => |recurrence| {
            try std.testing.expectEqual(@as(usize, 1), recurrence.trace_tree_index);
            try std.testing.expectEqual(@as(usize, 0), recurrence.first_column);
        },
    }

    var actual = core_air_accumulation.PointEvaluationAccumulator.init(alpha);
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, 5);

    const denominator_inv = try core_constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(5).coset(),
        point,
    ).inv();
    var expected = core_air_accumulation.PointEvaluationAccumulator.init(alpha);
    var a = values[0];
    var b = values[1];
    for (values[2..]) |c| {
        expected.accumulate(c.sub(a.square().add(b.square())).mul(denominator_inv));
        a = b;
        b = c;
    }

    try std.testing.expect(actual.finalize().eql(expected.finalize()));
    try std.testing.expect(!actual.finalize().isZero());
}
