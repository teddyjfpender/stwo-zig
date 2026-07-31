//! AIR adapter for public intermediate RAM observations.
//!
//! Public schedule columns are fixed by the verifier's canonical table. This
//! component owns ordered predecessor columns and one shared-memory LogUp
//! accumulator. The schedule claim must be transcript-mixed before the shared
//! memory relation is drawn.

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
const component_domain = @import("component_domain.zig");
const lookup = @import("intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    public_active_column: usize,
    public_mcycle_column: usize,
    public_key_column: usize,
    public_value_column: usize,
    predecessor_offset: usize,
    interaction_offset: usize,
    relation: *const memory_lookup.Relation,
    schedule_claim: *const lookup.ScheduleClaim,
    claim: QM31,

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
        return lookup.N_CONSTRAINTS;
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
            self.maxPreprocessedIndex() + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            self.predecessor_offset + lookup.N_MAIN_COLUMNS,
        );
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
            self.public_active_column,
            self.public_mcycle_column,
            self.public_key_column,
            self.public_value_column,
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
            self.maxPreprocessedIndex() + 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            self.predecessor_offset + lookup.N_MAIN_COLUMNS,
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

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[lookup.N_CONSTRAINTS]QM31,
    ) !void {
        try self.validateSampled(preprocessed, main, interaction);
        var predecessor_values: [lookup.N_MAIN_COLUMNS]QM31 =
            undefined;
        try sampledColumns(
            &predecessor_values,
            main[self.predecessor_offset..][0..lookup.N_MAIN_COLUMNS],
        );
        constraints.* = lookup.evaluateRows(
            QM31,
            .{
                preprocessed[self.public_active_column][0],
                preprocessed[self.public_mcycle_column][0],
                preprocessed[self.public_key_column][0],
                preprocessed[self.public_value_column][0],
            },
            try lookup.Row(QM31).fromColumns(&predecessor_values),
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            preprocessed[self.is_first_column][0],
            self.claim,
            lookup.relationValues(self.relation.*),
        ).values;
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
        var constraints: [lookup.N_CONSTRAINTS]QM31 = undefined;
        try self.evaluateSampled(
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
        for (constraints) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.maxPreprocessedIndex() or
            main.len < self.predecessor_offset + lookup.N_MAIN_COLUMNS or
            interaction.len <
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const source_count =
            5 + lookup.N_MAIN_COLUMNS + lookup.N_INTERACTION_COLUMNS;
        const evaluations = try allocator.alloc(
            []const M31,
            source_count,
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }
        const sources = .{
            preprocessed[self.is_first_column],
            preprocessed[self.public_active_column],
            preprocessed[self.public_mcycle_column],
            preprocessed[self.public_key_column],
            preprocessed[self.public_value_column],
        };
        inline for (sources, 0..) |polynomial, index|
            evaluations[index] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        var at: usize = 5;
        at = try extendRange(
            allocator,
            main[self.predecessor_offset..][0..lookup.N_MAIN_COLUMNS],
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
                .n_cols = lookup.N_CONSTRAINTS,
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const predecessor_start: usize = 5;
        const interaction_start =
            predecessor_start + lookup.N_MAIN_COLUMNS;
        for (0..evaluation_size) |row| {
            const previous =
                utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var predecessor_values: [lookup.N_MAIN_COLUMNS]QM31 =
                undefined;
            domainColumns(
                &predecessor_values,
                evaluations,
                predecessor_start,
                row,
            );
            const evaluation = lookup.evaluateRows(
                QM31,
                .{
                    QM31.fromBase(evaluations[1][row]),
                    QM31.fromBase(evaluations[2][row]),
                    QM31.fromBase(evaluations[3][row]),
                    QM31.fromBase(evaluations[4][row]),
                },
                try lookup.Row(QM31).fromColumns(
                    &predecessor_values,
                ),
                secureAt(
                    evaluations[interaction_start..][0..4],
                    row,
                ),
                secureAt(
                    evaluations[interaction_start..][0..4],
                    previous,
                ),
                QM31.fromBase(evaluations[0][row]),
                self.claim,
                lookup.relationValues(self.relation.*),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
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

    fn maxPreprocessedIndex(self: *const Self) usize {
        return @max(
            self.is_first_column,
            self.public_active_column,
            self.public_mcycle_column,
            self.public_key_column,
            self.public_value_column,
        );
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidObservationLogSize;
        if (self.schedule_claim.count == 0)
            return error.EmptyObservationSchedule;
        const size = @as(u64, 1) << @intCast(self.log_size);
        if (self.schedule_claim.count > size)
            return error.TooManyObservationsForTrace;
    }

    fn validateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
    ) !void {
        try self.validateConfiguration();
        if (preprocessed.len <= self.maxPreprocessedIndex() or
            preprocessed[self.is_first_column].len < 1 or
            preprocessed[self.public_active_column].len < 1 or
            preprocessed[self.public_mcycle_column].len < 1 or
            preprocessed[self.public_key_column].len < 1 or
            preprocessed[self.public_value_column].len < 1 or
            main.len < self.predecessor_offset + lookup.N_MAIN_COLUMNS or
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
) void {
    for (output, evaluations[start..][0..output.len]) |*value, values|
        value.* = QM31.fromBase(values[row]);
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
