//! Prover/verifier component for ordered SM83 state and bus continuity.

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
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const N_CONSTRAINTS: usize =
    execution.N_CONSTRAINTS + execution.N_FAMILY_CONSTRAINTS;

pub const FamilyActivityColumns = struct {
    instruction: usize,
    interrupt_service: usize,
};

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    main_offset: usize,
    family_activity_columns: ?FamilyActivityColumns = null,
    initial: execution.Boundary,
    final: execution.Boundary,

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
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{
            self.log_size,
            self.log_size,
        });
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(
            u32,
            self.mainEnd(),
        );
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(allocator, 2, point);
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            self.mainEnd(),
            point,
            nextRowPoint(max_log_degree_bound, point),
        );
        errdefer component_domain.freePointColumns(allocator, main);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.is_last_column,
        });
    }

    pub fn evaluateRow(
        self: *const @This(),
        current: execution.Row(QM31),
        next: execution.Row(QM31),
        is_first: QM31,
        is_last: QM31,
    ) execution.Shipped.Evaluation {
        return execution.Shipped.evaluate(
            current,
            next,
            is_first,
            is_last,
            self.initial,
            self.final,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len != 1 or
            preprocessed[self.is_last_column].len != 1 or
            main.len < self.mainEnd())
        {
            return error.InvalidProofShape;
        }

        var current_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var next_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current_values,
            &next_values,
            main[self.main_offset..][0..execution.N_MAIN_COLUMNS],
        ) |*current, *next, column| {
            if (column.len != 2) return error.InvalidProofShape;
            current.* = column[0];
            next.* = column[1];
        }
        const evaluation = self.evaluateRow(
            try execution.Row(QM31).fromColumns(&current_values),
            try execution.Row(QM31).fromColumns(&next_values),
            preprocessed[self.is_first_column][0],
            preprocessed[self.is_last_column][0],
        );
        const denominator_inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
        var selectors: [execution.N_FAMILY_SELECTORS]QM31 = undefined;
        for (
            &selectors,
            main[self.main_offset + execution.N_MAIN_COLUMNS ..][0..execution.N_FAMILY_SELECTORS],
        ) |*selector, column| selector.* = column[0];
        const expected_activity = if (self.family_activity_columns) |columns| blk: {
            if (main[columns.instruction].len < 1 or
                main[columns.interrupt_service].len < 1)
                return error.InvalidProofShape;
            break :blk main[columns.instruction][0].add(
                main[columns.interrupt_service][0],
            );
        } else QM31.one();
        for (
            execution.familyConstraintsForActivity(
                QM31,
                selectors,
                expected_activity,
            ),
        ) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 2) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            main.len < self.mainEnd())
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const evaluation_domain = canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = evaluation_domain.size();
        const base_evaluation_count =
            2 + execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS;
        const activity_count: usize =
            if (self.family_activity_columns == null) 0 else 2;
        const evaluations = try allocator.alloc(
            []const M31,
            base_evaluation_count + activity_count,
        );
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        evaluations[0] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_first_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extension_buffers,
        );
        evaluations[1] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_last_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extension_buffers,
        );
        for (
            main[self.main_offset..][0 .. execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS],
            evaluations[2..base_evaluation_count],
        ) |polynomial, *values| {
            values.* = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extension_buffers,
            );
        }
        if (self.family_activity_columns) |columns| {
            evaluations[base_evaluation_count] =
                try component_domain.evaluationValues(
                    allocator,
                    main[columns.instruction],
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
            evaluations[base_evaluation_count + 1] =
                try component_domain.evaluationValues(
                    allocator,
                    main[columns.interrupt_service],
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
        }
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                evaluation_domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                evaluation_domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const denominator_inverses = try component_domain.quotientDenominators(
            allocator,
            self.log_size,
            evaluation_log_size,
            evaluation_domain,
        );
        defer allocator.free(denominator_inverses);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);

        for (0..evaluation_size) |row| {
            const next_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var next_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &current_values,
                &next_values,
                evaluations[2 .. 2 + execution.N_MAIN_COLUMNS],
            ) |*current, *next, values| {
                current.* = QM31.fromBase(values[row]);
                next.* = QM31.fromBase(values[next_row]);
            }
            const evaluation = self.evaluateRow(
                try execution.Row(QM31).fromColumns(&current_values),
                try execution.Row(QM31).fromColumns(&next_values),
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
            }
            var selectors: [execution.N_FAMILY_SELECTORS]QM31 = undefined;
            for (
                &selectors,
                evaluations[2 + execution.N_MAIN_COLUMNS ..][0..execution.N_FAMILY_SELECTORS],
            ) |*selector, values| selector.* = QM31.fromBase(values[row]);
            const expected_activity =
                if (self.family_activity_columns == null)
                    QM31.one()
                else
                    QM31.fromBase(
                        evaluations[base_evaluation_count][row],
                    ).add(QM31.fromBase(
                        evaluations[base_evaluation_count + 1][row],
                    ));
            for (
                execution.familyConstraintsForActivity(
                    QM31,
                    selectors,
                    expected_activity,
                ),
                execution.N_CONSTRAINTS..,
            ) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
            }
            column.accumulate(
                row,
                folded.mulM31(denominator_inverses[row >> denominator_shift]),
            );
        }
    }

    fn mainEnd(self: *const @This()) usize {
        var result = self.main_offset +
            execution.N_MAIN_COLUMNS +
            execution.N_FAMILY_SELECTORS;
        if (self.family_activity_columns) |columns| {
            result = @max(
                result,
                @max(columns.instruction, columns.interrupt_service) + 1,
            );
        }
        return result;
    }
};

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

test "execution component exposes the canonical constraint count" {
    const component = Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = .{ .cpu = .{}, .mcycle = 0 },
        .final = .{ .cpu = .{}, .mcycle = 16 },
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(
        execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS,
        component.mainEnd(),
    );
    var machine_component = component;
    machine_component.family_activity_columns = .{
        .instruction = execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS + 3,
        .interrupt_service = execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS + 4,
    };
    try std.testing.expectEqual(
        execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS + 5,
        machine_component.mainEnd(),
    );
    _ = component.asProverComponent();
    _ = component.asVerifierComponent();
}
