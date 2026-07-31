//! AIR adapter for byte-memory access and boundary LogUp columns.

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
const memory_lookup = @import("memory_lookup.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Kind = enum { execution, boundary };
pub const N_EXECUTION_CONSTRAINTS: usize =
    memory_lookup.N_CONSTRAINTS + memory_lookup.N_EXECUTION_SUMS;

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    address_column: usize = 0,
    initial_value_column: usize = 0,
    final_value_column: usize = 0,
    execution_offset: usize = 0,
    main_offset: usize,
    interaction_offset: usize,
    relation: *const memory_lookup.Relation,
    claims: [memory_lookup.N_EXECUTION_SUMS]QM31,

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

    pub fn nConstraints(self: *const @This()) usize {
        return switch (self.kind) {
            .execution => N_EXECUTION_CONSTRAINTS,
            .boundary => 1,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(
            u32,
            if (self.kind == .boundary) 4 else 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            if (self.kind == .boundary) 1 else memory_lookup.N_MAIN_COLUMNS,
        );
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(u32, self.interactionColumns());
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
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .boundary) 4 else 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .boundary) 1 else memory_lookup.N_MAIN_COLUMNS,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction = try component_domain.currentAndPreviousPointColumns(
            allocator,
            self.interactionColumns(),
            point,
            previousRowPoint(max_log_degree_bound, point),
        );
        errdefer component_domain.freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return switch (self.kind) {
            .execution => allocator.dupe(usize, &.{self.is_first_column}),
            .boundary => allocator.dupe(usize, &.{
                self.is_first_column,
                self.address_column,
                self.initial_value_column,
                self.final_value_column,
            }),
        };
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
        var constraints: [N_EXECUTION_CONSTRAINTS]QM31 = undefined;
        const count = try self.evaluateSampled(
            mask.items[0],
            mask.items[1],
            mask.items[2],
            &constraints,
        );
        const denominator_inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints[0..count]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_column or
            main.len <= self.main_offset or
            interaction.len < self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain = canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const data_columns = if (self.kind == .execution)
            execution.N_MAIN_COLUMNS + memory_lookup.N_MAIN_COLUMNS
        else
            4;
        const evaluations = try allocator.alloc(
            []const M31,
            1 + data_columns + self.interactionColumns(),
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
        var source: usize = 1;
        if (self.kind == .execution) {
            if (main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
                main.len < self.main_offset + memory_lookup.N_MAIN_COLUMNS)
                return error.InvalidProofShape;
            for (main[self.execution_offset..][0..execution.N_MAIN_COLUMNS]) |polynomial| {
                evaluations[source] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
                source += 1;
            }
            for (main[self.main_offset..][0..memory_lookup.N_MAIN_COLUMNS]) |polynomial| {
                evaluations[source] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
                source += 1;
            }
        } else {
            if (preprocessed.len <= self.address_column or
                preprocessed.len <= self.initial_value_column or
                preprocessed.len <= self.final_value_column)
                return error.InvalidProofShape;
            for ([_]prover_component.Poly{
                preprocessed[self.address_column],
                preprocessed[self.initial_value_column],
                preprocessed[self.final_value_column],
                main[self.main_offset],
            }) |polynomial| {
                evaluations[source] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
                source += 1;
            }
        }
        for (
            interaction[self.interaction_offset..][0..self.interactionColumns()],
        ) |polynomial| {
            evaluations[source] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extension_buffers,
            );
            source += 1;
        }
        std.debug.assert(source == evaluations.len);
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                domain,
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
            domain,
        );
        defer allocator.free(denominator_inverses);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = evaluation_log_size, .n_cols = self.nConstraints() }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const interaction_start = evaluations.len - self.interactionColumns();
        for (0..evaluation_size) |row| {
            const previous = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
            );
            var constraints: [N_EXECUTION_CONSTRAINTS]QM31 = undefined;
            const count = if (self.kind == .execution)
                try self.evaluateExecutionOnDomain(
                    evaluations,
                    interaction_start,
                    row,
                    previous,
                    &constraints,
                )
            else
                self.evaluateBoundaryOnDomain(
                    evaluations,
                    interaction_start,
                    row,
                    previous,
                    &constraints,
                );
            var folded = QM31.zero();
            for (constraints[0..count], 0..) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
            }
            column.accumulate(
                row,
                folded.mulM31(denominator_inverses[row >> denominator_shift]),
            );
        }
    }

    fn evaluateSampled(
        self: *const @This(),
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_EXECUTION_CONSTRAINTS]QM31,
    ) !usize {
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1)
            return error.InvalidProofShape;
        if (self.kind == .execution) {
            if (main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
                main.len < self.main_offset + memory_lookup.N_MAIN_COLUMNS)
                return error.InvalidProofShape;
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var memory_values: [memory_lookup.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &machine_values,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            for (
                &memory_values,
                main[self.main_offset..][0..memory_lookup.N_MAIN_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            const machine = try execution.Row(QM31).fromColumns(&machine_values);
            const memory = try memory_lookup.Row(QM31).fromColumns(&memory_values);
            const semantic = memory_lookup.Shipped.evaluate(machine, memory);
            @memcpy(constraints[0..memory_lookup.N_CONSTRAINTS], &semantic.values);
            const pairs = memory_lookup.executionPairs(machine, memory, self.relation.*);
            for (pairs, 0..) |pair, index| {
                constraints[memory_lookup.N_CONSTRAINTS + index] =
                    memory_lookup.pairConstraint(
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * index,
                            0,
                        ),
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * index,
                            1,
                        ),
                        preprocessed[self.is_first_column][0],
                        self.claims[index],
                        pair,
                    );
            }
            return N_EXECUTION_CONSTRAINTS;
        }
        if (preprocessed.len <= self.address_column or
            preprocessed.len <= self.initial_value_column or
            preprocessed.len <= self.final_value_column or
            main.len <= self.main_offset or
            main[self.main_offset].len < 1)
            return error.InvalidProofShape;
        constraints[0] = memory_lookup.pairConstraint(
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            preprocessed[self.is_first_column][0],
            self.claims[0],
            memory_lookup.boundaryPair(
                preprocessed[self.address_column][0],
                preprocessed[self.initial_value_column][0],
                main[self.main_offset][0],
                preprocessed[self.final_value_column][0],
                self.relation.*,
            ),
        );
        return 1;
    }

    fn evaluateExecutionOnDomain(
        self: *const @This(),
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_EXECUTION_CONSTRAINTS]QM31,
    ) !usize {
        var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var memory_values: [memory_lookup.N_MAIN_COLUMNS]QM31 = undefined;
        for (&machine_values, evaluations[1..][0..execution.N_MAIN_COLUMNS]) |*value, values| {
            value.* = QM31.fromBase(values[row]);
        }
        for (
            &memory_values,
            evaluations[1 + execution.N_MAIN_COLUMNS ..][0..memory_lookup.N_MAIN_COLUMNS],
        ) |*value, values| value.* = QM31.fromBase(values[row]);
        const machine = try execution.Row(QM31).fromColumns(&machine_values);
        const memory = try memory_lookup.Row(QM31).fromColumns(&memory_values);
        const semantic = memory_lookup.Shipped.evaluate(machine, memory);
        @memcpy(constraints[0..memory_lookup.N_CONSTRAINTS], &semantic.values);
        const pairs = memory_lookup.executionPairs(machine, memory, self.relation.*);
        for (pairs, 0..) |pair, index| {
            constraints[memory_lookup.N_CONSTRAINTS + index] =
                memory_lookup.pairConstraint(
                    secureAt(
                        evaluations[interaction_start + 4 * index ..][0..4],
                        row,
                    ),
                    secureAt(
                        evaluations[interaction_start + 4 * index ..][0..4],
                        previous,
                    ),
                    QM31.fromBase(evaluations[0][row]),
                    self.claims[index],
                    pair,
                );
        }
        return N_EXECUTION_CONSTRAINTS;
    }

    fn evaluateBoundaryOnDomain(
        self: *const @This(),
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_EXECUTION_CONSTRAINTS]QM31,
    ) usize {
        constraints[0] = memory_lookup.pairConstraint(
            secureAt(evaluations[interaction_start..][0..4], row),
            secureAt(evaluations[interaction_start..][0..4], previous),
            QM31.fromBase(evaluations[0][row]),
            self.claims[0],
            memory_lookup.boundaryPair(
                QM31.fromBase(evaluations[1][row]),
                QM31.fromBase(evaluations[2][row]),
                QM31.fromBase(evaluations[4][row]),
                QM31.fromBase(evaluations[3][row]),
                self.relation.*,
            ),
        );
        return 1;
    }

    fn interactionColumns(self: *const @This()) usize {
        return switch (self.kind) {
            .execution => memory_lookup.N_EXECUTION_COLUMNS,
            .boundary => memory_lookup.N_BOUNDARY_COLUMNS,
        };
    }
};

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns.len <= offset + index or columns[offset + index].len <= point)
            return error.InvalidProofShape;
        coordinate.* = columns[offset + index][point];
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

test "memory lookup component separates access and boundary ownership" {
    const relation = memory_lookup.Relation.dummy();
    const access = Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** memory_lookup.N_EXECUTION_SUMS,
    };
    const boundary = Component{
        .kind = .boundary,
        .log_size = 16,
        .is_first_column = 0,
        .address_column = 1,
        .initial_value_column = 2,
        .final_value_column = 3,
        .main_offset = execution.N_MAIN_COLUMNS + memory_lookup.N_MAIN_COLUMNS,
        .interaction_offset = memory_lookup.N_EXECUTION_COLUMNS,
        .relation = &relation,
        .claims = .{QM31.zero()} ** memory_lookup.N_EXECUTION_SUMS,
    };
    try std.testing.expectEqual(N_EXECUTION_CONSTRAINTS, access.nConstraints());
    try std.testing.expectEqual(@as(usize, 1), boundary.nConstraints());
    try std.testing.expectEqual(@as(u32, 5), access.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 17), boundary.maxConstraintLogDegreeBound());
    _ = access.asVerifierComponent();
    _ = boundary.asProverComponent();
}

test "memory boundary component rejects final-memory drift" {
    const relation = memory_lookup.Relation.dummy();
    const honest_pair = memory_lookup.boundaryPair(
        QM31.fromBase(M31.fromCanonical(0x8000)),
        QM31.fromBase(M31.fromCanonical(2)),
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(3)),
        relation,
    );
    const claim = honest_pair.n1.mul(try honest_pair.d1.inv()).add(
        honest_pair.n2.mul(try honest_pair.d2.inv()),
    );
    const component = Component{
        .kind = .boundary,
        .log_size = 16,
        .is_first_column = 0,
        .address_column = 1,
        .initial_value_column = 2,
        .final_value_column = 3,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{claim} ++
            .{QM31.zero()} ** (memory_lookup.N_EXECUTION_SUMS - 1),
    };
    var is_first_values = [_]QM31{QM31.one()};
    var address_values = [_]QM31{QM31.fromBase(M31.fromCanonical(0x8000))};
    var initial_values = [_]QM31{QM31.fromBase(M31.fromCanonical(2))};
    var final_values = [_]QM31{QM31.fromBase(M31.fromCanonical(3))};
    var preprocessed = [_][]QM31{
        &is_first_values,
        &address_values,
        &initial_values,
        &final_values,
    };
    var clock_values = [_]QM31{QM31.fromBase(M31.fromCanonical(5))};
    var main = [_][]QM31{&clock_values};
    const coordinates = claim.toM31Array();
    var interaction_values: [4][2]QM31 = undefined;
    var interaction: [4][]QM31 = undefined;
    for (&interaction_values, &interaction, coordinates) |*values, *column, coordinate| {
        values.* = .{
            QM31.fromBase(coordinate),
            QM31.fromBase(coordinate),
        };
        column.* = values;
    }
    var constraints: [N_EXECUTION_CONSTRAINTS]QM31 = undefined;
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(constraints[0].isZero());

    final_values[0] = QM31.fromBase(M31.fromCanonical(4));
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!constraints[0].isZero());
}
