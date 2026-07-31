//! AIR adapter for execution-consume and committed-ROM LogUp columns.

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
const program_lookup = @import("program_lookup.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Kind = enum { execution, rom };

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    address_column: usize = 0,
    value_column: usize = 0,
    main_offset: usize,
    interaction_offset: usize,
    relation: *const program_lookup.Relation,
    claims: [program_lookup.N_EXECUTION_SUMS]QM31,

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
            .execution => program_lookup.N_EXECUTION_SUMS,
            .rom => 1,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, if (self.kind == .rom) 3 else 1);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, if (self.kind == .rom) 1 else 0);
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
            if (self.kind == .rom) 3 else 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .rom) 1 else 0,
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
            .rom => allocator.dupe(usize, &.{
                self.is_first_column,
                self.address_column,
                self.value_column,
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
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const interaction = mask.items[2];
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len != 1 or
            interaction.len < self.interaction_offset + self.interactionColumns())
        {
            return error.InvalidProofShape;
        }

        var constraints: [program_lookup.N_EXECUTION_SUMS]QM31 = undefined;
        const constraint_count = try self.evaluateSampled(
            preprocessed,
            main,
            interaction,
            &constraints,
        );
        const denominator_inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints[0..constraint_count]) |constraint| {
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
            interaction.len < self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const evaluation_domain = canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = evaluation_domain.size();
        const source_count = 1 +
            (if (self.kind == .execution) execution.N_MAIN_COLUMNS else 3) +
            self.interactionColumns();
        const evaluations = try allocator.alloc([]const M31, source_count);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        var source: usize = 0;
        evaluations[source] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_first_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extension_buffers,
        );
        source += 1;
        if (self.kind == .execution) {
            if (main.len < self.main_offset + execution.N_MAIN_COLUMNS)
                return error.InvalidProofShape;
            for (main[self.main_offset..][0..execution.N_MAIN_COLUMNS]) |polynomial| {
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
                preprocessed.len <= self.value_column or
                main.len <= self.main_offset)
                return error.InvalidProofShape;
            for ([_]prover_component.Poly{
                preprocessed[self.address_column],
                preprocessed[self.value_column],
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
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const data_start: usize = 1;
        const interaction_start = evaluations.len - self.interactionColumns();
        for (0..evaluation_size) |row| {
            const previous = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
            );
            var constraints: [program_lookup.N_EXECUTION_SUMS]QM31 = undefined;
            if (self.kind == .execution) {
                var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
                for (
                    &machine_values,
                    evaluations[data_start..][0..execution.N_MAIN_COLUMNS],
                ) |*value, values| value.* = QM31.fromBase(values[row]);
                const pairs = program_lookup.executionPairs(
                    try execution.Row(QM31).fromColumns(&machine_values),
                    self.relation.*,
                );
                for (0..program_lookup.N_EXECUTION_SUMS) |sum| {
                    constraints[sum] = program_lookup.pairConstraint(
                        secureAt(evaluations[interaction_start + 4 * sum ..][0..4], row),
                        secureAt(
                            evaluations[interaction_start + 4 * sum ..][0..4],
                            previous,
                        ),
                        QM31.fromBase(evaluations[0][row]),
                        self.claims[sum],
                        pairs[sum],
                    );
                }
            } else {
                constraints[0] = program_lookup.pairConstraint(
                    secureAt(evaluations[interaction_start..][0..4], row),
                    secureAt(evaluations[interaction_start..][0..4], previous),
                    QM31.fromBase(evaluations[0][row]),
                    self.claims[0],
                    program_lookup.romPair(
                        QM31.fromBase(evaluations[data_start][row]),
                        QM31.fromBase(evaluations[data_start + 1][row]),
                        QM31.fromBase(evaluations[data_start + 2][row]),
                        self.relation.*,
                    ),
                );
            }
            var folded = QM31.zero();
            for (constraints[0..self.nConstraints()], 0..) |constraint, index| {
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
        constraints: *[program_lookup.N_EXECUTION_SUMS]QM31,
    ) !usize {
        if (self.kind == .execution) {
            if (main.len < self.main_offset + execution.N_MAIN_COLUMNS)
                return error.InvalidProofShape;
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &machine_values,
                main[self.main_offset..][0..execution.N_MAIN_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            const pairs = program_lookup.executionPairs(
                try execution.Row(QM31).fromColumns(&machine_values),
                self.relation.*,
            );
            for (0..program_lookup.N_EXECUTION_SUMS) |sum| {
                constraints[sum] = program_lookup.pairConstraint(
                    try sampledSecure(interaction, self.interaction_offset + 4 * sum, 0),
                    try sampledSecure(interaction, self.interaction_offset + 4 * sum, 1),
                    preprocessed[self.is_first_column][0],
                    self.claims[sum],
                    pairs[sum],
                );
            }
            return program_lookup.N_EXECUTION_SUMS;
        }
        if (preprocessed.len <= self.address_column or
            preprocessed.len <= self.value_column or
            main.len <= self.main_offset or
            main[self.main_offset].len < 1)
            return error.InvalidProofShape;
        constraints[0] = program_lookup.pairConstraint(
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            preprocessed[self.is_first_column][0],
            self.claims[0],
            program_lookup.romPair(
                preprocessed[self.address_column][0],
                preprocessed[self.value_column][0],
                main[self.main_offset][0],
                self.relation.*,
            ),
        );
        return 1;
    }

    fn interactionColumns(self: *const @This()) usize {
        return switch (self.kind) {
            .execution => program_lookup.N_EXECUTION_COLUMNS,
            .rom => program_lookup.N_ROM_COLUMNS,
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

test "program lookup component separates execution and ROM ownership" {
    const relation = program_lookup.Relation.dummy();
    const execution_component = Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{ QM31.zero(), QM31.zero() },
    };
    const rom_component = Component{
        .kind = .rom,
        .log_size = 15,
        .is_first_column = 3,
        .address_column = 4,
        .value_column = 5,
        .main_offset = execution.N_MAIN_COLUMNS,
        .interaction_offset = program_lookup.N_EXECUTION_COLUMNS,
        .relation = &relation,
        .claims = .{ QM31.zero(), QM31.zero() },
    };
    try std.testing.expectEqual(@as(usize, 2), execution_component.nConstraints());
    try std.testing.expectEqual(@as(usize, 1), rom_component.nConstraints());
    _ = execution_component.asVerifierComponent();
    _ = rom_component.asProverComponent();
}
