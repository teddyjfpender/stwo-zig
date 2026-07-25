//! Exact arithmetic and relation component for one Blake round shard.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const support = @import("component_support.zig");
const geometry = @import("geometry.zig");
const constraints_mod = @import("round_constraints.zig");
const statement_mod = @import("statement.zig");

pub const Component = struct {
    log_size: u32,
    main_offset: usize,
    interaction_offset: usize,
    elements: statement_mod.AllElements,
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
        return geometry.ROUND_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        return support.traceBounds(
            allocator,
            0,
            geometry.ROUND_MAIN_COLUMNS,
            4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS,
            self.log_size,
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: support.CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        return support.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
            0,
            geometry.ROUND_MAIN_COLUMNS,
            geometry.ROUND_INTERACTION_SECURE_COLUMNS,
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
        point: support.CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or
            mask.items[1].len < self.main_offset + geometry.ROUND_MAIN_COLUMNS or
            mask.items[2].len <
                self.interaction_offset +
                    4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        var main: [geometry.ROUND_MAIN_COLUMNS]QM31 = undefined;
        for (&main, mask.items[1][self.main_offset..][0..main.len]) |*out, column| {
            if (column.len != 1) return error.InvalidProofShape;
            out.* = column[0];
        }
        var current: [geometry.ROUND_INTERACTION_SECURE_COLUMNS]QM31 = undefined;
        const previous = try support.pointSecureColumns(
            mask.items[2],
            self.interaction_offset,
            current.len,
            &current,
        );
        const constraints = try constraints_mod.evaluate(
            main,
            current,
            previous,
            &self.elements,
            self.claimed_sum,
            self.log_size,
        );
        const denominator_inverse = try support.pointDenominatorInverse(
            point,
            self.log_size,
            max_log_degree_bound,
        );
        for (constraints) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3 or
            trace.polys.items[1].len <
                self.main_offset + geometry.ROUND_MAIN_COLUMNS or
            trace.polys.items[2].len <
                self.interaction_offset +
                    4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const interaction_columns =
            4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS;
        const source_count = geometry.ROUND_MAIN_COLUMNS + interaction_columns;
        const evaluations = try allocator.alloc([]const M31, source_count);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        for (0..geometry.ROUND_MAIN_COLUMNS) |index| {
            evaluations[index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[1][self.main_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        const interaction_start = geometry.ROUND_MAIN_COLUMNS;
        for (0..interaction_columns) |index| {
            evaluations[interaction_start + index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[2][self.interaction_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        try support.extendEvaluations(
            allocator,
            eval_domain,
            extension_buffers.items,
        );

        const denominator_inverses =
            try support.domainDenominatorInverses(self.log_size, eval_domain);
        var accumulator_columns = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = geometry.ROUND_CONSTRAINTS,
        }});
        defer allocator.free(accumulator_columns);
        const column = &accumulator_columns[0];

        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            var main: [geometry.ROUND_MAIN_COLUMNS]QM31 = undefined;
            for (&main, evaluations[0..geometry.ROUND_MAIN_COLUMNS]) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            var current: [geometry.ROUND_INTERACTION_SECURE_COLUMNS]QM31 =
                undefined;
            for (&current, 0..) |*out, secure_index| {
                out.* = support.secureAt(
                    evaluations,
                    interaction_start,
                    secure_index,
                    row,
                );
            }
            const previous = support.secureAt(
                evaluations,
                interaction_start,
                current.len - 1,
                previous_row,
            );
            const constraints = try constraints_mod.evaluate(
                main,
                current,
                previous,
                &self.elements,
                self.claimed_sum,
                self.log_size,
            );
            try accumulate(
                column,
                row,
                constraints,
                denominator_inverses[row >> @intCast(self.log_size)],
            );
        }
    }
};

fn accumulate(
    column: *prover_air_accumulation.ColumnAccumulator,
    row: usize,
    constraints: [geometry.ROUND_CONSTRAINTS]QM31,
    denominator_inverse: M31,
) !void {
    if (column.random_coeff_powers.len != constraints.len)
        return error.InvalidProofShape;
    var combined = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        combined = combined.add(
            column.random_coeff_powers[constraints.len - 1 - index]
                .mul(constraint),
        );
    }
    column.accumulate(row, combined.mulM31(denominator_inverse));
}

test "exact Blake round component exposes arithmetic and paired LogUp constraints" {
    const component = Component{
        .log_size = 7,
        .main_offset = geometry.ROUND_MAIN_OFFSETS[0],
        .interaction_offset = geometry.ROUND_INTERACTION_OFFSETS[0],
        .elements = undefined,
        .claimed_sum = QM31.zero(),
    };
    try std.testing.expectEqual(@as(usize, 129), component.nConstraints());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinit(std.testing.allocator);
    try std.testing.expectEqual(geometry.ROUND_MAIN_COLUMNS, bounds.items[1].len);
    try std.testing.expectEqual(
        4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS,
        bounds.items[2].len,
    );
}
