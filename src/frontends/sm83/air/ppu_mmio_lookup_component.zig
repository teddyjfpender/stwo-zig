//! AIR adapters for execution/PPU MMIO LogUp owners.

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
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const cartridge_access = @import("cartridge_access_component.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");
const ppu_binding = @import("ppu_binding.zig");
const lookup = @import("ppu_mmio_lookup.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Kind = enum { execution, ppu };
pub const N_MAX_CONSTRAINTS: usize = @max(
    lookup.N_EXECUTION_CONSTRAINTS,
    lookup.N_PPU_CONSTRAINTS,
);

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    execution_offset: usize = 0,
    access_offset: usize = 0,
    binding_offset: usize = 0,
    auxiliary_offset: usize = 0,
    interaction_offset: usize,
    relations: *const lookup.Relations,
    claims: lookup.Claims,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(
        self: *const Self,
    ) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(
        self: *const Self,
    ) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const Self) usize {
        return switch (self.kind) {
            .execution => lookup.N_EXECUTION_CONSTRAINTS,
            .ppu => lookup.N_PPU_CONSTRAINTS,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(
            u32,
            self.is_first_column + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, self.mainEnd());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interaction_offset + self.interactionColumns(),
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

    pub fn preprocessedColumnIndices(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{self.is_first_column});
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            self.is_first_column + 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            self.mainEnd(),
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interaction_offset + self.interactionColumns(),
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

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
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
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_column or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const data_columns = self.dataColumns();
        const interaction_columns = self.interactionColumns();
        const evaluations = try allocator.alloc(
            []const M31,
            1 + data_columns + interaction_columns,
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
                main[self.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        } else {
            at = try extendRange(
                allocator,
                main[self.binding_offset..][0..ppu_binding.N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
            at = try extendRange(
                allocator,
                main[self.auxiliary_offset..][0..1],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        }
        at = try extendRange(
            allocator,
            interaction[self.interaction_offset..][0..interaction_columns],
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
        var columns = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const interaction_start = 1 + data_columns;
        for (0..evaluation_size) |row| {
            const previous =
                utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
            const count = try self.evaluateDomainRow(
                evaluations,
                interaction_start,
                row,
                previous,
                &constraints,
            );
            var folded = QM31.zero();
            for (constraints[0..count], 0..) |constraint, index| {
                const powers = output.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            output.accumulate(
                row,
                folded.mulM31(inverses[row >> shift]),
            );
        }
    }

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1 or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;
        if (self.kind == .execution) {
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var access_values: [cartridge_access.N_MAIN_COLUMNS]QM31 =
                undefined;
            try sampledColumns(
                &machine_values,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            );
            try sampledColumns(
                &access_values,
                main[self.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
            );
            const machine =
                try execution.Row(QM31).fromColumns(&machine_values);
            const accesses =
                try cartridge_access.PackedRow(QM31)
                    .fromColumns(&access_values);
            const pairs = lookup.executionPairs(
                machine,
                accesses,
                self.relations.*,
            );
            var at: usize = 0;
            for (pairs, 0..) |relation_pairs, relation_index| {
                for (relation_pairs, 0..) |entry, sum_index| {
                    constraints[at] = lookup.pairConstraint(
                        QM31,
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * at,
                            0,
                        ),
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * at,
                            1,
                        ),
                        preprocessed[self.is_first_column][0],
                        self.claims.execution[relation_index][sum_index],
                        entry.numerator,
                        entry.denominator,
                    );
                    at += 1;
                }
            }
            return at;
        }

        var values: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &values,
            main[self.binding_offset..][0..ppu_binding.N_MAIN_COLUMNS],
        );
        if (main[self.auxiliary_offset].len < 1)
            return error.InvalidProofShape;
        const ppu = try lookup.ppuRow(
            QM31,
            &values,
            main[self.auxiliary_offset][0],
        );
        const pairs = lookup.ppuPairs(ppu, self.relations.*);
        for (pairs, 0..) |entry, index| {
            constraints[index] = lookup.pairConstraint(
                QM31,
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
                self.claims.ppu[index],
                entry.numerator,
                entry.denominator,
            );
        }
        const binding_constraints =
            lookup.ppuBindingConstraints(QM31, ppu);
        @memcpy(
            constraints[lookup.N_RELATIONS..lookup.N_PPU_CONSTRAINTS],
            &binding_constraints,
        );
        return lookup.N_PPU_CONSTRAINTS;
    }

    fn evaluateDomainRow(
        self: *const Self,
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        if (self.kind == .execution) {
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var access_values: [cartridge_access.N_MAIN_COLUMNS]QM31 =
                undefined;
            const at = domainColumns(
                &machine_values,
                evaluations,
                1,
                row,
            );
            _ = domainColumns(
                &access_values,
                evaluations,
                at,
                row,
            );
            const machine =
                try execution.Row(QM31).fromColumns(&machine_values);
            const accesses =
                try cartridge_access.PackedRow(QM31)
                    .fromColumns(&access_values);
            const pairs = lookup.executionPairs(
                machine,
                accesses,
                self.relations.*,
            );
            var constraint_index: usize = 0;
            for (pairs, 0..) |relation_pairs, relation_index| {
                for (relation_pairs, 0..) |entry, sum_index| {
                    constraints[constraint_index] =
                        lookup.pairConstraint(
                            QM31,
                            secureAt(
                                evaluations[interaction_start +
                                    4 * constraint_index ..][0..4],
                                row,
                            ),
                            secureAt(
                                evaluations[interaction_start +
                                    4 * constraint_index ..][0..4],
                                previous,
                            ),
                            QM31.fromBase(evaluations[0][row]),
                            self.claims.execution[
                                relation_index
                            ][sum_index],
                            entry.numerator,
                            entry.denominator,
                        );
                    constraint_index += 1;
                }
            }
            return constraint_index;
        }

        var values: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
        const after_binding =
            domainColumns(&values, evaluations, 1, row);
        const ppu = try lookup.ppuRow(
            QM31,
            &values,
            QM31.fromBase(evaluations[after_binding][row]),
        );
        const pairs = lookup.ppuPairs(ppu, self.relations.*);
        for (pairs, 0..) |entry, index| {
            constraints[index] = lookup.pairConstraint(
                QM31,
                secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    row,
                ),
                secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    previous,
                ),
                QM31.fromBase(evaluations[0][row]),
                self.claims.ppu[index],
                entry.numerator,
                entry.denominator,
            );
        }
        const binding_constraints =
            lookup.ppuBindingConstraints(QM31, ppu);
        @memcpy(
            constraints[lookup.N_RELATIONS..lookup.N_PPU_CONSTRAINTS],
            &binding_constraints,
        );
        return lookup.N_PPU_CONSTRAINTS;
    }

    fn mainEnd(self: *const Self) usize {
        return switch (self.kind) {
            .execution => @max(
                self.execution_offset + execution.N_MAIN_COLUMNS,
                self.access_offset + cartridge_access.N_MAIN_COLUMNS,
            ),
            .ppu => @max(
                self.binding_offset + ppu_binding.N_MAIN_COLUMNS,
                self.auxiliary_offset + 1,
            ),
        };
    }

    fn dataColumns(self: *const Self) usize {
        return switch (self.kind) {
            .execution => execution.N_MAIN_COLUMNS +
                cartridge_access.N_MAIN_COLUMNS,
            .ppu => ppu_binding.N_MAIN_COLUMNS + 1,
        };
    }

    fn interactionColumns(self: *const Self) usize {
        return switch (self.kind) {
            .execution => lookup.N_EXECUTION_INTERACTION_COLUMNS,
            .ppu => lookup.N_PPU_INTERACTION_COLUMNS,
        };
    }
};

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

fn sampledColumns(output: []QM31, columns: [][]QM31) !void {
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
