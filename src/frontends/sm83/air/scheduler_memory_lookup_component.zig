//! AIR adapter for authenticated scheduler IE/IF memory samples.
//!
//! Scheduler semantics, scheduler/execution binding, and global cancellation
//! with the shared cartridge-memory claim remain mandatory companions.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const utils = core.utils;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("component_domain.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const lookup = @import("scheduler_memory_lookup.zig");
const scheduler_component = @import("scheduler_component.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize =
    lookup.N_CONSTRAINTS + lookup.N_SAMPLES;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    scheduler_offset: usize,
    memory_offset: usize,
    interaction_offset: usize,
    relation: *const memory_lookup.Relation,
    claims: lookup.Claims,
    boundary: lookup.Boundary,

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

    pub fn nConstraints(_: *const Self) usize {
        return N_CONSTRAINTS;
    }

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
            @max(self.is_first_column, self.is_last_column) + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, self.mainEnd());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interaction_offset + lookup.N_INTERACTION_COLUMNS,
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
        try self.validateConfiguration();
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.is_last_column,
        });
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
            @max(self.is_first_column, self.is_last_column) + 1,
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
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS,
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

    pub fn evaluateRow(
        self: *const Self,
        scheduler_values: []const QM31,
        memory_values: []const QM31,
        current: [lookup.N_SAMPLES]QM31,
        previous: [lookup.N_SAMPLES]QM31,
        is_first: QM31,
        is_last: QM31,
    ) ![N_CONSTRAINTS]QM31 {
        try self.validateConfiguration();
        const semantic = try lookup.evaluate(
            QM31,
            scheduler_values,
            memory_values,
            is_first,
            is_last,
            self.boundary,
        );
        const scheduled =
            try scheduler_component.Row(QM31).fromColumns(
                scheduler_values,
            );
        const row = try lookup.Row(QM31).fromColumns(memory_values);
        const pairs = lookup.pairsForRows(
            scheduled,
            row,
            is_first,
            self.relation.*,
        );
        var constraints: [N_CONSTRAINTS]QM31 = undefined;
        @memcpy(
            constraints[0..lookup.N_CONSTRAINTS],
            &semantic.values,
        );
        for (pairs, 0..) |pair, index| {
            constraints[lookup.N_CONSTRAINTS + index] =
                memory_lookup.pairConstraint(
                    current[index],
                    previous[index],
                    is_first,
                    self.claims.samples[index],
                    pair,
                );
        }
        return constraints;
    }

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_CONSTRAINTS]QM31,
    ) !void {
        try self.validateSampled(
            preprocessed,
            main,
            interaction,
        );
        var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
        var memory_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &scheduler_values,
            main[self.scheduler_offset..][0..scheduler_component.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &memory_values,
            main[self.memory_offset..][0..lookup.N_MAIN_COLUMNS],
        );
        var current: [lookup.N_SAMPLES]QM31 = undefined;
        var previous: [lookup.N_SAMPLES]QM31 = undefined;
        for (&current, &previous, 0..) |
            *current_value,
            *previous_value,
            index,
        | {
            current_value.* = try sampledSecure(
                interaction,
                self.interaction_offset + 4 * index,
                0,
            );
            previous_value.* = try sampledSecure(
                interaction,
                self.interaction_offset + 4 * index,
                1,
            );
        }
        constraints.* = try self.evaluateRow(
            &scheduler_values,
            &memory_values,
            current,
            previous,
            preprocessed[self.is_first_column][0],
            preprocessed[self.is_last_column][0],
        );
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
        var constraints: [N_CONSTRAINTS]QM31 = undefined;
        try self.evaluateSampled(
            mask.items[0],
            mask.items[1],
            mask.items[2],
            &constraints,
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(
                max_log_degree_bound - self.log_size,
            ),
        ).inv();
        for (constraints) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size =
            self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + scheduler_component.N_MAIN_COLUMNS +
                lookup.N_MAIN_COLUMNS + lookup.N_INTERACTION_COLUMNS,
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
        evaluations[1] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_last_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        var at: usize = 2;
        at = try extendRange(
            allocator,
            main[self.scheduler_offset..][0..scheduler_component.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            main[self.memory_offset..][0..lookup.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            interaction[self.interaction_offset..][0..lookup.N_INTERACTION_COLUMNS],
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
            defer prover_twiddles.deinitM31(
                allocator,
                &twiddles,
            );
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

        const inverses =
            try component_domain.quotientDenominators(
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
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) =
            @intCast(self.log_size);
        const scheduler_start: usize = 2;
        const memory_start =
            scheduler_start + scheduler_component.N_MAIN_COLUMNS;
        const interaction_start =
            memory_start + lookup.N_MAIN_COLUMNS;
        for (0..evaluation_size) |row_index| {
            const previous_index =
                utils.previousBitReversedCircleDomainIndex(
                    row_index,
                    self.log_size,
                    evaluation_log_size,
                );
            var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
            var memory_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
            domainColumns(
                &scheduler_values,
                evaluations,
                scheduler_start,
                row_index,
            );
            domainColumns(
                &memory_values,
                evaluations,
                memory_start,
                row_index,
            );
            var current: [lookup.N_SAMPLES]QM31 = undefined;
            var previous: [lookup.N_SAMPLES]QM31 = undefined;
            for (&current, &previous, 0..) |
                *current_value,
                *previous_value,
                index,
            | {
                current_value.* = secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    row_index,
                );
                previous_value.* = secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    previous_index,
                );
            }
            const constraints = try self.evaluateRow(
                &scheduler_values,
                &memory_values,
                current,
                previous,
                QM31.fromBase(evaluations[0][row_index]),
                QM31.fromBase(evaluations[1][row_index]),
            );
            var folded = QM31.zero();
            for (constraints, 0..) |constraint, index| {
                const powers = output.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            output.accumulate(
                row_index,
                folded.mulM31(inverses[row_index >> shift]),
            );
        }
    }

    fn mainEnd(self: *const Self) usize {
        return @max(
            self.scheduler_offset + scheduler_component.N_MAIN_COLUMNS,
            self.memory_offset + lookup.N_MAIN_COLUMNS,
        );
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidSchedulerMemoryLogSize;
        if (self.boundary.initial_mcycle >=
            self.boundary.final_mcycle)
            return error.InvalidSchedulerMemoryBoundary;
        if (self.boundary.final_mcycle >
            memory_lookup.memory_clock.MAX_FINAL_MCYCLE)
            return error.NonCanonicalSchedulerMemoryClock;
        const scheduler_end =
            self.scheduler_offset + scheduler_component.N_MAIN_COLUMNS;
        const memory_end =
            self.memory_offset + lookup.N_MAIN_COLUMNS;
        if (self.scheduler_offset < memory_end and
            self.memory_offset < scheduler_end)
            return error.OverlappingSchedulerMemoryColumns;
    }

    fn validateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
    ) !void {
        try self.validateConfiguration();
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len < 1 or
            preprocessed[self.is_last_column].len < 1 or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;
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

fn sampledColumns(
    output: []QM31,
    columns: [][]QM31,
) !void {
    if (output.len != columns.len)
        return error.InvalidProofShape;
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
) void {
    for (output, evaluations[start..][0..output.len]) |
        *value,
        values,
    | value.* = QM31.fromBase(values[row]);
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

fn secureAt(
    columns: []const []const M31,
    row: usize,
) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}
