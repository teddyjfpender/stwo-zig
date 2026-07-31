//! Proof component for timer event clocks, ordering, and pre-tick reads.
//!
//! The timer component owns transition semantics, state chaining, activity,
//! and state endpoints. This component binds optional-write-then-tick order,
//! one phase clock, canonical read markers/values, and clock endpoints.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31_MODULUS = core.fields.m31.Modulus;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const binding = @import("timer_binding.zig");
const component_domain = @import("component_domain.zig");
const timer_air = @import("timer.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize = 40;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        semantic: timer_air.Semantics(S).Row,
        mcycle: S,
        read_markers: [4]S,
        read_value: [8]S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != binding.N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            return .{
                .active = values[0],
                .semantic = try timer_air.Semantics(S).Row.fromColumns(
                    values[1..binding.MCYCLE_OFFSET],
                ),
                .mcycle = values[binding.MCYCLE_OFFSET],
                .read_markers = values[binding.READ_MARKER_OFFSET..binding.READ_VALUE_OFFSET].*,
                .read_value = values[binding.READ_VALUE_OFFSET..binding.N_MAIN_COLUMNS].*,
            };
        }
    };
}

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluateRows(
    comptime S: type,
    current_values: []const S,
    next_values: []const S,
    is_first: S,
    is_last: S,
    initial_mcycle: u32,
    final_mcycle: u32,
) !Evaluation(S) {
    try validateBoundaries(initial_mcycle, final_mcycle);
    const current = try Row(S).fromColumns(current_values);
    const next = try Row(S).fromColumns(next_values);
    const one = S.one();
    const not_last = one.sub(is_last);
    const tick = current.semantic.events[0];
    const write = sum(current.semantic.events[1..]);
    const next_write = sum(next.semantic.events[1..]);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    out[at] = one.sub(current.active).mul(current.mcycle);
    at += 1;
    var read_sum = S.zero();
    for (current.read_markers) |marker| {
        out[at] = bit(marker);
        at += 1;
        out[at] = one.sub(current.active).mul(marker);
        at += 1;
        read_sum = read_sum.add(marker);
    }
    for (current.read_value) |value| {
        out[at] = bit(value);
        at += 1;
        out[at] = one.sub(current.active).mul(value);
        at += 1;
    }
    out[at] = bit(read_sum);
    at += 1;
    out[at] = read_sum.mul(one.sub(tick));
    at += 1;

    const reloading = current.semantic.before.reload[
        @intFromEnum(@import("../runner/timer.zig").ReloadState.reloading)
    ];
    for (current.read_value, 0..) |actual, bit_index| {
        const div = current.read_markers[0].mul(
            current.semantic.before.div[8 + bit_index],
        );
        const tima = current.read_markers[1]
            .mul(one.sub(reloading))
            .mul(current.semantic.before.tima[bit_index]);
        const tma = current.read_markers[2].mul(
            current.semantic.before.tma[bit_index],
        );
        const tac_bit = if (bit_index < 3)
            current.semantic.before.tac[bit_index]
        else
            one;
        const tac = current.read_markers[3].mul(tac_bit);
        out[at] = actual.sub(div.add(tima).add(tma).add(tac));
        at += 1;
    }

    const chain = not_last.mul(next.active);
    out[at] = chain.mul(
        next.mcycle.sub(current.mcycle).sub(tick),
    );
    at += 1;
    out[at] = not_last.mul(write).mul(next_write);
    at += 1;
    out[at] = is_first.mul(
        current.mcycle.sub(constant(S, initial_mcycle)),
    );
    at += 1;
    appendFinal(
        S,
        &out,
        &at,
        tick.sub(one),
        current.active,
        next.active,
        is_last,
    );
    appendFinal(
        S,
        &out,
        &at,
        current.mcycle.add(tick).sub(constant(S, final_mcycle)),
        current.active,
        next.active,
        is_last,
    );
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    main_offset: usize,
    initial_mcycle: u32,
    final_mcycle: u32,

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
        const main = try allocator.alloc(
            u32,
            self.main_offset + binding.N_MAIN_COLUMNS,
        );
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
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            @max(self.is_first_column, self.is_last_column) + 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            self.main_offset + binding.N_MAIN_COLUMNS,
            point,
            nextRowPoint(max_log_degree_bound, point),
        );
        errdefer component_domain.freePointColumns(allocator, main);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
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

    pub fn evaluateRow(
        self: *const Self,
        current: []const QM31,
        next: []const QM31,
        is_first: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        try self.validateConfiguration();
        return evaluateRows(
            QM31,
            current,
            next,
            is_first,
            is_last,
            self.initial_mcycle,
            self.final_mcycle,
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
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len != 1 or
            preprocessed[self.is_last_column].len != 1 or
            main.len < self.main_offset + binding.N_MAIN_COLUMNS)
            return error.InvalidProofShape;
        var current: [binding.N_MAIN_COLUMNS]QM31 = undefined;
        var next: [binding.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..binding.N_MAIN_COLUMNS],
        ) |*current_value, *next_value, column| {
            if (column.len != 2) return error.InvalidProofShape;
            current_value.* = column[0];
            next_value.* = column[1];
        }
        const evaluation = try self.evaluateRow(
            &current,
            &next,
            preprocessed[self.is_first_column][0],
            preprocessed[self.is_last_column][0],
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 2) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            main.len < self.main_offset + binding.N_MAIN_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + binding.N_MAIN_COLUMNS,
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
        for (
            main[self.main_offset..][0..binding.N_MAIN_COLUMNS],
            evaluations[2..],
        ) |polynomial, *values| {
            values.* = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        }
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
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..evaluation_size) |row| {
            const next_row = core.utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current: [binding.N_MAIN_COLUMNS]QM31 = undefined;
            var next: [binding.N_MAIN_COLUMNS]QM31 = undefined;
            for (&current, &next, evaluations[2..]) |
                *current_value,
                *next_value,
                values,
            | {
                current_value.* = QM31.fromBase(values[row]);
                next_value.* = QM31.fromBase(values[next_row]);
            }
            const evaluation = try self.evaluateRow(
                &current,
                &next,
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
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

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidTimerBindingLogSize;
        try validateBoundaries(
            self.initial_mcycle,
            self.final_mcycle,
        );
    }
};

fn appendFinal(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    difference: S,
    active: S,
    next_active: S,
    is_last: S,
) void {
    const not_last = S.one().sub(is_last);
    out[at.*] = is_last.mul(active).mul(difference).add(
        not_last.mul(active.sub(next_active)).mul(difference),
    );
    at.* += 1;
}

fn bit(value: anytype) @TypeOf(value) {
    return value.mul(value.sub(@TypeOf(value).one()));
}

fn sum(values: anytype) @TypeOf(values[0]) {
    var result = @TypeOf(values[0]).zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn constant(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

fn validateBoundaries(initial: u32, final: u32) !void {
    if (initial >= M31_MODULUS or final >= M31_MODULUS)
        return error.NonCanonicalTimerClock;
    if (initial >= final) return error.InvalidTimerClockBoundary;
}

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
