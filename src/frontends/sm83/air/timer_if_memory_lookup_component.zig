//! AIR adapter for timer interrupt writes into authenticated memory.
//!
//! This component owns the FF0F predecessor witness and one shared-memory
//! relation accumulator. It borrows timer binding columns; timer semantics,
//! binding, and global memory-claim cancellation remain separate owners.

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
const timer_binding = @import("timer_binding.zig");
const lookup = @import("timer_if_memory_lookup.zig");
const memory_clock = @import("cartridge_memory_clock.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const runner = @import("../runner/mod.zig");
const timer_runner = @import("../runner/timer.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize = lookup.N_CONSTRAINTS + 1;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    binding_offset: usize,
    predecessor_offset: usize,
    interaction_offset: usize,
    relation: *const memory_lookup.Relation,
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
            self.is_first_column + 1,
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
        return allocator.dupe(usize, &.{self.is_first_column});
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
        binding_values: []const QM31,
        predecessor_values: []const QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
    ) ![N_CONSTRAINTS]QM31 {
        try self.validateConfiguration();
        const timer = try lookup.TimerRow(QM31).fromColumns(
            binding_values,
        );
        const predecessor = try lookup.Row(QM31).fromColumns(
            predecessor_values,
        );
        const semantic = lookup.evaluate(QM31, timer, predecessor);
        var constraints: [N_CONSTRAINTS]QM31 = undefined;
        @memcpy(constraints[0..lookup.N_CONSTRAINTS], &semantic.values);
        const entry = linearizedPair(
            timer,
            predecessor,
            self.relation.*,
        );
        constraints[lookup.N_CONSTRAINTS] = recurrenceConstraint(
            QM31,
            current,
            previous,
            is_first,
            self.claim,
            entry.n1,
            entry.d1,
            entry.n2,
            entry.d2,
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
        var binding_values: [timer_binding.N_MAIN_COLUMNS]QM31 =
            undefined;
        var predecessor_values: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &binding_values,
            main[self.binding_offset..][0..timer_binding.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &predecessor_values,
            main[self.predecessor_offset..][0..lookup.N_MAIN_COLUMNS],
        );
        constraints.* = try self.evaluateRow(
            &binding_values,
            &predecessor_values,
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            preprocessed[self.is_first_column][0],
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
        if (preprocessed.len <= self.is_first_column or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            1 + timer_binding.N_MAIN_COLUMNS +
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
        var at: usize = 1;
        at = try extendRange(
            allocator,
            main[self.binding_offset..][0..timer_binding.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
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
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const binding_start: usize = 1;
        const predecessor_start =
            binding_start + timer_binding.N_MAIN_COLUMNS;
        const interaction_start =
            predecessor_start + lookup.N_MAIN_COLUMNS;
        for (0..evaluation_size) |row| {
            const previous =
                utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var binding_values: [timer_binding.N_MAIN_COLUMNS]QM31 =
                undefined;
            var predecessor_values: [lookup.N_MAIN_COLUMNS]QM31 =
                undefined;
            domainColumns(
                &binding_values,
                evaluations,
                binding_start,
                row,
            );
            domainColumns(
                &predecessor_values,
                evaluations,
                predecessor_start,
                row,
            );
            const constraints = try self.evaluateRow(
                &binding_values,
                &predecessor_values,
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
            var folded = QM31.zero();
            for (constraints, 0..) |constraint, index| {
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

    fn mainEnd(self: *const Self) usize {
        return @max(
            self.binding_offset + timer_binding.N_MAIN_COLUMNS,
            self.predecessor_offset + lookup.N_MAIN_COLUMNS,
        );
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidTimerLogSize;
    }

    fn validateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
    ) !void {
        try self.validateConfiguration();
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1 or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + lookup.N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;
    }
};

pub fn recurrenceConstraint(
    comptime S: type,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    n1: S,
    d1: S,
    n2: S,
    d2: S,
) S {
    const delta = current.sub(previous).add(is_first.mul(claim));
    return delta.mul(d1).mul(d2)
        .sub(n1.mul(d2))
        .sub(n2.mul(d1));
}

/// The leaf constrains each predecessor bit with
/// `bit * (bit - requested) = 0`, so `requested * bit == bit`. This keeps
/// the OR update linear on the constrained surface and the recurrence cubic.
fn linearizedPair(
    timer: lookup.TimerRow(QM31),
    predecessor: lookup.Row(QM31),
    relation: memory_lookup.Relation,
) memory_lookup.RowPair {
    const requested = timer.semantic.interrupt_requested;
    const previous_value = compose(predecessor.previous_value);
    const interrupt = constant(timer_runner.TIMER_INTERRUPT);
    const next_value = previous_value.add(
        interrupt.mul(
            requested.sub(predecessor.previous_value[2]),
        ),
    );
    return .{
        .n1 = requested.neg(),
        .d1 = relation.combine(
            constant(runner.cartridge_memory.INTERRUPT_FLAGS),
            predecessor.previous_clock,
            previous_value,
        ),
        .n2 = requested,
        .d2 = relation.combine(
            constant(runner.cartridge_memory.INTERRUPT_FLAGS),
            phasedClock(timer),
            next_value,
        ),
    };
}

fn phasedClock(timer: lookup.TimerRow(QM31)) QM31 {
    return timer.mcycle
        .mul(constant(memory_clock.PHASES))
        .add(constant(memory_clock.TICK_PHASE + 1));
}

fn compose(bits: anytype) QM31 {
    var result = QM31.zero();
    var power = QM31.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn constant(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
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
