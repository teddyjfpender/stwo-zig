//! Shared prover/verifier adapter for execution-bound SM83 family AIRs.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub fn Component(comptime FamilyAir: type) type {
    return struct {
        log_size: u32,
        is_active_main_column: usize,
        execution_offset: usize,
        main_offset: usize,

        const Self = @This();
        const N_CONSTRAINTS: usize = FamilyAir.N_BOUND_CONSTRAINTS + 1;
        const Adapter = core_air_derive.ComponentAdapter(
            Self,
            prover_component.ComponentProver,
            prover_component.Trace,
            prover_air_accumulation.DomainEvaluationAccumulator,
        );

        pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
            return Adapter.asVerifierComponent(self);
        }

        pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
            return Adapter.asProverComponent(self);
        }

        pub fn nConstraints(_: *const Self) usize {
            return N_CONSTRAINTS;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            // Selector-gated IME promotion is degree 3; after division by the
            // trace vanishing polynomial its quotient fits the standard
            // log_size + 1 coefficient space.
            return self.log_size + 1;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try allocator.alloc(u32, 0);
            errdefer allocator.free(preprocessed);
            const main = try allocator.alloc(u32, FamilyAir.N_MAIN_COLUMNS);
            errdefer allocator.free(main);
            @memset(main, self.log_size);
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &.{ preprocessed, main }),
            );
        }

        pub fn maskPoints(
            self: *const Self,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) !core_air_components.MaskPoints {
            if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
            const preprocessed = try component_domain.currentPointColumns(
                allocator,
                0,
                point,
            );
            errdefer component_domain.freePointColumns(allocator, preprocessed);
            const main = try component_domain.currentPointColumns(
                allocator,
                FamilyAir.N_MAIN_COLUMNS,
                point,
            );
            errdefer component_domain.freePointColumns(allocator, main);
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main }),
            );
        }

        pub fn preprocessedColumnIndices(
            _: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            return allocator.alloc(usize, 0);
        }

        pub fn evaluateRow(
            _: *const Self,
            main: []const QM31,
            machine: execution.Row(QM31),
            is_active: QM31,
        ) !FamilyAir.Shipped.BoundEvaluation {
            return FamilyAir.Shipped.evaluateBound(
                try FamilyAir.Shipped.Row.fromColumns(main),
                machine,
                is_active,
            );
        }

        pub fn evaluateConstraintQuotientsAtPoint(
            self: *const Self,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) !void {
            if (max_log_degree_bound < self.log_size or mask.items.len < 2)
                return error.InvalidProofShape;
            const main = mask.items[1];
            if (main.len <= self.is_active_main_column or
                main[self.is_active_main_column].len < 1 or
                main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
                main.len < self.main_offset + FamilyAir.N_MAIN_COLUMNS)
            {
                return error.InvalidProofShape;
            }

            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &machine_values,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            var sampled: [FamilyAir.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &sampled,
                main[self.main_offset..][0..FamilyAir.N_MAIN_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            const active = main[self.is_active_main_column][0];
            const evaluation = try self.evaluateRow(
                &sampled,
                try execution.Row(QM31).fromColumns(&machine_values),
                active,
            );
            const denominator_inverse = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(self.log_size).coset(),
                point.repeatedDouble(max_log_degree_bound - self.log_size),
            ).inv();
            for (evaluation.values) |constraint| {
                accumulator.accumulate(constraint.mul(denominator_inverse));
            }
            accumulator.accumulate(
                active.mul(active.sub(QM31.one())).mul(denominator_inverse),
            );
        }

        pub fn evaluateConstraintQuotientsOnDomain(
            self: *const Self,
            trace: *const prover_component.Trace,
            accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !void {
            if (trace.polys.items.len < 2) return error.InvalidProofShape;
            const main = trace.polys.items[1];
            if (main.len <= self.is_active_main_column or
                main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
                main.len < self.main_offset + FamilyAir.N_MAIN_COLUMNS)
            {
                return error.InvalidProofShape;
            }

            const allocator = accumulator.allocator;
            const evaluation_log_size = self.maxConstraintLogDegreeBound();
            const evaluation_domain = canonic.CanonicCoset.new(
                evaluation_log_size,
            ).circleDomain();
            const evaluation_size = evaluation_domain.size();
            const evaluations = try allocator.alloc(
                []const M31,
                1 + execution.N_MAIN_COLUMNS + FamilyAir.N_MAIN_COLUMNS,
            );
            defer allocator.free(evaluations);
            var extension_buffers = std.ArrayList([]M31).empty;
            defer {
                for (extension_buffers.items) |values| allocator.free(values);
                extension_buffers.deinit(allocator);
            }

            evaluations[0] = try component_domain.evaluationValues(
                allocator,
                main[self.is_active_main_column],
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extension_buffers,
            );
            for (
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
                evaluations[1 .. 1 + execution.N_MAIN_COLUMNS],
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
            for (
                main[self.main_offset..][0..FamilyAir.N_MAIN_COLUMNS],
                evaluations[1 + execution.N_MAIN_COLUMNS ..],
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
                &.{.{ .log_size = evaluation_log_size, .n_cols = N_CONSTRAINTS }},
            );
            defer allocator.free(accumulators);
            const column = &accumulators[0];
            const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);

            for (0..evaluation_size) |row| {
                var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
                for (
                    &machine_values,
                    evaluations[1 .. 1 + execution.N_MAIN_COLUMNS],
                ) |*value, values| value.* = QM31.fromBase(values[row]);
                var sampled: [FamilyAir.N_MAIN_COLUMNS]QM31 = undefined;
                for (
                    &sampled,
                    evaluations[1 + execution.N_MAIN_COLUMNS ..],
                ) |*value, values| value.* = QM31.fromBase(values[row]);
                const active = QM31.fromBase(evaluations[0][row]);
                const evaluation = try self.evaluateRow(
                    &sampled,
                    try execution.Row(QM31).fromColumns(&machine_values),
                    active,
                );
                var folded = QM31.zero();
                for (evaluation.values, 0..) |constraint, index| {
                    const powers = column.random_coeff_powers;
                    folded = folded.add(
                        powers[powers.len - 1 - index].mul(constraint),
                    );
                }
                folded = folded.add(
                    column.random_coeff_powers[0].mul(
                        active.mul(active.sub(QM31.one())),
                    ),
                );
                column.accumulate(
                    row,
                    folded.mulM31(denominator_inverses[row >> denominator_shift]),
                );
            }
        }
    };
}

test "family AIRs fit the shared cubic component bound" {
    inline for (.{
        @import("alu8.zig"),
        @import("daa.zig"),
        @import("incdec8.zig"),
        @import("incdec16.zig"),
        @import("rotate_accumulator.zig"),
        @import("load8.zig"),
        @import("alu16.zig"),
        @import("cb_rotate_shift.zig"),
        @import("cb_bit.zig"),
        @import("cb_res_set.zig"),
        @import("load16.zig"),
        @import("misc.zig"),
        @import("branch.zig"),
        @import("stack.zig"),
        @import("interrupt.zig"),
        @import("interrupt_service.zig"),
    }) |FamilyAir| {
        const Semantics = FamilyAir.Semantics(Degree);
        const variables = [_]Degree{.{ .degree = 1 }} **
            FamilyAir.N_MAIN_COLUMNS;
        const machine_variables = [_]Degree{.{ .degree = 1 }} **
            execution.N_MAIN_COLUMNS;
        const evaluation = Semantics.evaluateBound(
            try Semantics.Row.fromColumns(&variables),
            try execution.Row(Degree).fromColumns(&machine_variables),
            .{ .degree = 1 },
        );
        for (evaluation.values) |constraint|
            try std.testing.expect(constraint.degree <= 3);
    }
}

const Degree = struct {
    degree: u32,

    pub fn zero() Degree {
        return .{ .degree = 0 };
    }

    pub fn one() Degree {
        return .{ .degree = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }

    pub fn add(self: Degree, other: Degree) Degree {
        return .{ .degree = @max(self.degree, other.degree) };
    }

    pub fn sub(self: Degree, other: Degree) Degree {
        return self.add(other);
    }

    pub fn mul(self: Degree, other: Degree) Degree {
        return .{ .degree = self.degree + other.degree };
    }
};
