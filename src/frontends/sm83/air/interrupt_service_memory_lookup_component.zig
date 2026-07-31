//! AIR adapter for interrupt-service logical memory operations.

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
const execution = @import("execution.zig");
const service_air = @import("interrupt_service.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const lookup = @import("interrupt_service_memory_lookup.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize =
    lookup.N_CONSTRAINTS + lookup.N_OPERATIONS + 2;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    service_active_column: usize,
    execution_offset: usize,
    service_offset: usize,
    memory_offset: usize,
    lookup_offset: usize,
    interaction_offset: usize,
    relation: *const memory_lookup.Relation,
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
        execution_values: []const QM31,
        service_values: []const QM31,
        memory_values: []const QM31,
        lookup_values: []const QM31,
        active: QM31,
        current: [lookup.N_OPERATIONS]QM31,
        previous: [lookup.N_OPERATIONS]QM31,
        activity_current: QM31,
        activity_previous: QM31,
        is_first: QM31,
        is_last: QM31,
    ) ![N_CONSTRAINTS]QM31 {
        try self.validateConfiguration();
        const semantic = try lookup.evaluate(
            QM31,
            execution_values,
            service_values,
            memory_values,
            lookup_values,
            active,
        );
        const executed = try execution.Row(QM31).fromColumns(
            execution_values,
        );
        const service = try service_air.Shipped.Row.fromColumns(
            service_values,
        );
        const row = try lookup.Row(QM31).fromColumns(lookup_values);
        const pairs = lookup.pairsForRows(
            executed,
            service,
            row,
            active,
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
                    self.claims.operations[index],
                    pair,
                );
        }
        constraints[lookup.N_CONSTRAINTS + lookup.N_OPERATIONS] =
            lookup.activityConstraint(
                activity_current,
                activity_previous,
                active,
                is_first,
            );
        constraints[lookup.N_CONSTRAINTS + lookup.N_OPERATIONS + 1] =
            lookup.activityBoundaryConstraint(
                activity_current,
                is_last,
                self.claims.service_count,
            );
        return constraints;
    }

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_CONSTRAINTS]QM31,
    ) !void {
        try self.validateSampled(preprocessed, main, interaction);
        var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var service_values: [service_air.N_MAIN_COLUMNS]QM31 = undefined;
        var memory_values: [memory_lookup.N_MAIN_COLUMNS]QM31 = undefined;
        var lookup_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &execution_values,
            main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &service_values,
            main[self.service_offset..][0..service_air.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &memory_values,
            main[self.memory_offset..][0..memory_lookup.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &lookup_values,
            main[self.lookup_offset..][0..lookup.N_MAIN_COLUMNS],
        );
        var current: [lookup.N_OPERATIONS]QM31 = undefined;
        var previous: [lookup.N_OPERATIONS]QM31 = undefined;
        for (&current, &previous, 0..) |*now, *prior, index| {
            now.* = try sampledSecure(
                interaction,
                self.interaction_offset + 4 * index,
                0,
            );
            prior.* = try sampledSecure(
                interaction,
                self.interaction_offset + 4 * index,
                1,
            );
        }
        const activity_offset =
            self.interaction_offset + lookup.N_INTERACTION_COLUMNS - 1;
        constraints.* = try self.evaluateRow(
            &execution_values,
            &service_values,
            &memory_values,
            &lookup_values,
            main[self.service_active_column][0],
            current,
            previous,
            interaction[activity_offset][0],
            interaction[activity_offset][1],
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
            3 + execution.N_MAIN_COLUMNS +
                service_air.N_MAIN_COLUMNS +
                memory_lookup.N_MAIN_COLUMNS +
                lookup.N_MAIN_COLUMNS +
                lookup.N_INTERACTION_COLUMNS,
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
            main[self.service_offset..][0..service_air.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            main[self.memory_offset..][0..memory_lookup.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            main[self.lookup_offset..][0..lookup.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        evaluations[at] = try component_domain.evaluationValues(
            allocator,
            main[self.service_active_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at += 1;
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
        const execution_start: usize = 2;
        const service_start =
            execution_start + execution.N_MAIN_COLUMNS;
        const memory_start =
            service_start + service_air.N_MAIN_COLUMNS;
        const lookup_start =
            memory_start + memory_lookup.N_MAIN_COLUMNS;
        const activity_start = lookup_start + lookup.N_MAIN_COLUMNS;
        const interaction_start = activity_start + 1;
        for (0..evaluation_size) |row_index| {
            const previous_index =
                utils.previousBitReversedCircleDomainIndex(
                    row_index,
                    self.log_size,
                    evaluation_log_size,
                );
            var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var service_values: [service_air.N_MAIN_COLUMNS]QM31 = undefined;
            var memory_values: [memory_lookup.N_MAIN_COLUMNS]QM31 = undefined;
            var lookup_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
            domainColumns(
                &execution_values,
                evaluations,
                execution_start,
                row_index,
            );
            domainColumns(
                &service_values,
                evaluations,
                service_start,
                row_index,
            );
            domainColumns(
                &memory_values,
                evaluations,
                memory_start,
                row_index,
            );
            domainColumns(
                &lookup_values,
                evaluations,
                lookup_start,
                row_index,
            );
            var current: [lookup.N_OPERATIONS]QM31 = undefined;
            var previous: [lookup.N_OPERATIONS]QM31 = undefined;
            for (&current, &previous, 0..) |*now, *prior, index| {
                now.* = secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    row_index,
                );
                prior.* = secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    previous_index,
                );
            }
            const activity =
                evaluations[
                    interaction_start + lookup.N_INTERACTION_COLUMNS - 1
                ];
            const constraints = try self.evaluateRow(
                &execution_values,
                &service_values,
                &memory_values,
                &lookup_values,
                QM31.fromBase(
                    evaluations[activity_start][row_index],
                ),
                current,
                previous,
                QM31.fromBase(activity[row_index]),
                QM31.fromBase(activity[previous_index]),
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
        var end = self.service_active_column + 1;
        end = @max(end, self.execution_offset + execution.N_MAIN_COLUMNS);
        end = @max(end, self.service_offset + service_air.N_MAIN_COLUMNS);
        end = @max(end, self.memory_offset + memory_lookup.N_MAIN_COLUMNS);
        end = @max(end, self.lookup_offset + lookup.N_MAIN_COLUMNS);
        return end;
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidServiceMemoryLogSize;
        if (self.claims.service_count >
            (@as(u32, 1) << @intCast(self.log_size)))
            return error.InvalidServiceCount;
        const ranges = [_][2]usize{
            .{ self.execution_offset, execution.N_MAIN_COLUMNS },
            .{ self.service_offset, service_air.N_MAIN_COLUMNS },
            .{ self.memory_offset, memory_lookup.N_MAIN_COLUMNS },
            .{ self.lookup_offset, lookup.N_MAIN_COLUMNS },
        };
        for (ranges, 0..) |left, index| {
            if (self.service_active_column >= left[0] and
                self.service_active_column < left[0] + left[1])
                return error.OverlappingServiceMemoryColumns;
            for (ranges[index + 1 ..]) |right|
                if (overlap(left, right))
                    return error.OverlappingServiceMemoryColumns;
        }
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

fn overlap(left: [2]usize, right: [2]usize) bool {
    return left[0] < right[0] + right[1] and
        right[0] < left[0] + left[1];
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

fn sampledColumns(output: []QM31, columns: [][]QM31) !void {
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
