//! AIR adapter for mapper-aware mutable-memory LogUp columns.
//!
//! Execution rows consume shared execution and packed cartridge-access
//! columns plus this lookup's predecessor witness. Boundary rows consume the
//! canonical public log17 system/SRAM table and one committed final-clock
//! column. All of those are pre-challenge; only LogUp accumulators are
//! post-challenge, preserving backend-independent transcript ordering.

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
const cartridge_access_component = @import("cartridge_access_component.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");
const lookup = @import("cartridge_memory_lookup.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Kind = enum { execution, boundary };
pub const N_EXECUTION_CONSTRAINTS: usize =
    lookup.N_CONSTRAINTS + lookup.N_EXECUTION_SUMS;
pub const N_BOUNDARY_CONSTRAINTS: usize = 6;
pub const N_MAX_CONSTRAINTS: usize =
    @max(N_EXECUTION_CONSTRAINTS, N_BOUNDARY_CONSTRAINTS);

pub const Claims = lookup.Claims;

pub fn verifyCancellation(claims: Claims) !void {
    return lookup.verifyCancellation(claims);
}

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    enabled_column: usize = 0,
    address_column: usize = 0,
    initial_value_column: usize = 0,
    final_value_column: usize = 0,
    execution_offset: usize = 0,
    access_offset: usize = 0,
    main_offset: usize,
    interaction_offset: usize,
    relation: *const lookup.Relation,
    claims: [lookup.N_EXECUTION_SUMS]QM31,

    const Self = @This();
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

    pub fn nConstraints(self: *const Self) usize {
        return switch (self.kind) {
            .execution => N_EXECUTION_CONSTRAINTS,
            .boundary => N_BOUNDARY_CONSTRAINTS,
        };
    }

    /// Both lookup recurrences have cubic numerators.
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        try self.validateConfiguration();
        const preprocessed = try allocator.alloc(
            u32,
            if (self.kind == .boundary) 5 else 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            if (self.kind == .boundary) 1 else lookup.N_MAIN_COLUMNS,
        );
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interactionColumns(),
        );
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .boundary) 5 else 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .boundary) 1 else lookup.N_MAIN_COLUMNS,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interactionColumns(),
                point,
                previousRowPoint(max_log_degree_bound, point),
            );
        errdefer component_domain.freePointColumns(
            allocator,
            interaction,
        );
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        try self.validateConfiguration();
        return switch (self.kind) {
            .execution => allocator.dupe(usize, &.{
                self.is_first_column,
            }),
            .boundary => allocator.dupe(usize, &.{
                self.is_first_column,
                self.enabled_column,
                self.address_column,
                self.initial_value_column,
                self.final_value_column,
            }),
        };
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
        const count = try self.evaluateSampled(
            mask.items[0],
            mask.items[1],
            mask.items[2],
            &constraints,
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints[0..count]) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len < self.preprocessedEnd() or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const data_columns = if (self.kind == .execution)
            execution.N_MAIN_COLUMNS +
                cartridge_access_component.N_MAIN_COLUMNS +
                lookup.N_MAIN_COLUMNS
        else
            5;
        const evaluations = try allocator.alloc(
            []const M31,
            1 + data_columns + self.interactionColumns(),
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }
        evaluations[0] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_first_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        var at: usize = 1;
        if (self.kind == .execution) {
            at = try extendRange(
                allocator,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
            at = try extendRange(
                allocator,
                main[self.access_offset..][0..cartridge_access_component.N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
            at = try extendRange(
                allocator,
                main[self.main_offset..][0..lookup.N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        } else {
            for ([_]prover_component.Poly{
                preprocessed[self.enabled_column],
                preprocessed[self.address_column],
                preprocessed[self.initial_value_column],
                preprocessed[self.final_value_column],
                main[self.main_offset],
            }) |polynomial| {
                evaluations[at] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
                at += 1;
            }
        }
        at = try extendRange(
            allocator,
            interaction[self.interaction_offset..][0..self.interactionColumns()],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        std.debug.assert(at == evaluations.len);
        if (extensions.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extensions.items,
                domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const inverses = try component_domain.quotientDenominators(
            allocator,
            self.log_size,
            evaluation_log_size,
            domain,
        );
        defer allocator.free(inverses);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const interaction_start =
            evaluations.len - self.interactionColumns();
        for (0..evaluation_size) |row| {
            const previous =
                utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
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
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            column.accumulate(
                row,
                folded.mulM31(inverses[row >> shift]),
            );
        }
    }

    pub fn evaluateBoundaryRow(
        self: *const Self,
        enabled: QM31,
        address: QM31,
        initial_value: QM31,
        final_clock: QM31,
        final_value: QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
    ) [N_BOUNDARY_CONSTRAINTS]QM31 {
        const pair = boundaryPair(
            enabled,
            address,
            initial_value,
            final_clock,
            final_value,
            self.relation.*,
        );
        const one = QM31.one();
        return .{
            lookup.pairConstraint(
                current,
                previous,
                is_first,
                self.claims[0],
                pair,
            ),
            enabled.mul(enabled.sub(one)),
            one.sub(enabled).mul(address),
            one.sub(enabled).mul(initial_value),
            one.sub(enabled).mul(final_clock),
            one.sub(enabled).mul(final_value),
        };
    }

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        try self.validateConfiguration();
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1)
            return error.InvalidProofShape;
        if (self.kind == .execution) {
            if (main.len < self.mainEnd()) return error.InvalidProofShape;
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var access_values: [cartridge_access_component.N_MAIN_COLUMNS]QM31 =
                undefined;
            var lookup_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
            try sampledColumns(
                &machine_values,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            );
            try sampledColumns(
                &access_values,
                main[self.access_offset..][0..cartridge_access_component.N_MAIN_COLUMNS],
            );
            try sampledColumns(
                &lookup_values,
                main[self.main_offset..][0..lookup.N_MAIN_COLUMNS],
            );
            const machine =
                try execution.Row(QM31).fromColumns(&machine_values);
            const accesses =
                try cartridge_access_component.PackedRow(QM31)
                    .fromColumns(&access_values);
            const memory = try lookup.Row(QM31).fromColumns(&lookup_values);
            const semantic =
                lookup.Shipped.evaluate(machine, accesses.cycles, memory);
            @memcpy(
                constraints[0..lookup.N_CONSTRAINTS],
                &semantic.values,
            );
            const pairs = lookup.executionPairs(
                machine,
                accesses.cycles,
                memory,
                self.relation.*,
            );
            for (pairs, 0..) |pair, index| {
                constraints[lookup.N_CONSTRAINTS + index] =
                    lookup.pairConstraint(
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
        if (preprocessed.len < self.preprocessedEnd() or
            main.len <= self.main_offset or
            main[self.main_offset].len < 1)
            return error.InvalidProofShape;
        const values = self.evaluateBoundaryRow(
            preprocessed[self.enabled_column][0],
            preprocessed[self.address_column][0],
            preprocessed[self.initial_value_column][0],
            main[self.main_offset][0],
            preprocessed[self.final_value_column][0],
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            preprocessed[self.is_first_column][0],
        );
        @memcpy(
            constraints[0..N_BOUNDARY_CONSTRAINTS],
            &values,
        );
        return N_BOUNDARY_CONSTRAINTS;
    }

    fn evaluateExecutionOnDomain(
        self: *const Self,
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        var at: usize = 1;
        var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var access_values: [cartridge_access_component.N_MAIN_COLUMNS]QM31 =
            undefined;
        var lookup_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        at = domainColumns(&machine_values, evaluations, at, row);
        at = domainColumns(&access_values, evaluations, at, row);
        at = domainColumns(&lookup_values, evaluations, at, row);
        const machine =
            try execution.Row(QM31).fromColumns(&machine_values);
        const accesses =
            try cartridge_access_component.PackedRow(QM31)
                .fromColumns(&access_values);
        const memory = try lookup.Row(QM31).fromColumns(&lookup_values);
        const semantic =
            lookup.Shipped.evaluate(machine, accesses.cycles, memory);
        @memcpy(
            constraints[0..lookup.N_CONSTRAINTS],
            &semantic.values,
        );
        const pairs = lookup.executionPairs(
            machine,
            accesses.cycles,
            memory,
            self.relation.*,
        );
        for (pairs, 0..) |pair, index| {
            constraints[lookup.N_CONSTRAINTS + index] =
                lookup.pairConstraint(
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
        self: *const Self,
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) usize {
        const values = self.evaluateBoundaryRow(
            QM31.fromBase(evaluations[1][row]),
            QM31.fromBase(evaluations[2][row]),
            QM31.fromBase(evaluations[3][row]),
            QM31.fromBase(evaluations[5][row]),
            QM31.fromBase(evaluations[4][row]),
            secureAt(
                evaluations[interaction_start..][0..4],
                row,
            ),
            secureAt(
                evaluations[interaction_start..][0..4],
                previous,
            ),
            QM31.fromBase(evaluations[0][row]),
        );
        @memcpy(
            constraints[0..N_BOUNDARY_CONSTRAINTS],
            &values,
        );
        return N_BOUNDARY_CONSTRAINTS;
    }

    fn preprocessedEnd(self: *const Self) usize {
        return switch (self.kind) {
            .execution => self.is_first_column + 1,
            .boundary => 1 + @max(
                @max(self.is_first_column, self.enabled_column),
                @max(
                    self.address_column,
                    @max(
                        self.initial_value_column,
                        self.final_value_column,
                    ),
                ),
            ),
        };
    }

    fn mainEnd(self: *const Self) usize {
        return switch (self.kind) {
            .execution => @max(
                self.execution_offset + execution.N_MAIN_COLUMNS,
                @max(
                    self.access_offset +
                        cartridge_access_component.N_MAIN_COLUMNS,
                    self.main_offset + lookup.N_MAIN_COLUMNS,
                ),
            ),
            .boundary => self.main_offset + 1,
        };
    }

    fn interactionColumns(self: *const Self) usize {
        return switch (self.kind) {
            .execution => lookup.N_EXECUTION_COLUMNS,
            .boundary => lookup.N_BOUNDARY_COLUMNS,
        };
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.kind == .boundary and
            self.log_size != lookup.BOUNDARY_LOG_SIZE)
            return error.InvalidBoundaryLogSize;
    }
};

fn boundaryPair(
    enabled: QM31,
    address: QM31,
    initial_value: QM31,
    final_clock: QM31,
    final_value: QM31,
    relation: lookup.Relation,
) lookup.RowPair {
    return .{
        .n1 = enabled,
        .d1 = relation.combine(address, QM31.zero(), initial_value),
        .n2 = enabled.neg(),
        .d2 = relation.combine(address, final_clock, final_value),
    };
}

fn extendRange(
    allocator: std.mem.Allocator,
    polynomials: []const prover_component.Poly,
    evaluations: [][]const M31,
    start: usize,
    source_log_size: u32,
    evaluation_log_size: u32,
    evaluation_size: usize,
    extensions: *std.ArrayList([]M31),
) !usize {
    var at = start;
    for (polynomials) |polynomial| {
        evaluations[at] = try component_domain.evaluationValues(
            allocator,
            polynomial,
            source_log_size,
            evaluation_log_size,
            evaluation_size,
            extensions,
        );
        at += 1;
    }
    return at;
}

fn sampledColumns(
    output: []QM31,
    columns: [][]QM31,
) !void {
    if (output.len != columns.len) return error.InvalidProofShape;
    for (output, columns) |*value, column| {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
}

fn domainColumns(
    output: []QM31,
    evaluations: []const []const M31,
    start: usize,
    row: usize,
) usize {
    for (output, evaluations[start..][0..output.len]) |*value, values|
        value.* = QM31.fromBase(values[row]);
    return start + output.len;
}

fn previousRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point: usize,
) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns.len <= offset + index or
            columns[offset + index].len <= point)
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
