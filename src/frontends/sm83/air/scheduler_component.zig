//! Standalone component for a non-empty scheduler-event prefix.
//!
//! The component binds scheduler-owned IME/pending/HALT state, absolute
//! M-cycle continuity, and exact public endpoints. IE and IF remain
//! unauthenticated witness inputs until their memory relations are attached.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const circle = core.circle;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const M31_MODULUS = core.fields.m31.Modulus;
const canonic = core.poly.circle.canonic;
const utils = core.utils;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("component_domain.zig");
const scheduler = @import("scheduler.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const N_STATE_COLUMNS: usize = 4;

pub const N_MAIN_COLUMNS: usize = scheduler.N_MAIN_COLUMNS + 2;
pub const N_CONSTRAINTS: usize = scheduler.N_CONSTRAINTS + 18;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Boundary = struct {
    mcycle: u32,
    ime: bool,
    ime_enable_pending: bool,
    halted: bool,
    halt_bug: bool = false,
};

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        mcycle: S,
        scheduler: scheduler.Semantics(S).Row,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            return .{
                .active = values[0],
                .mcycle = values[1],
                .scheduler = try scheduler.Semantics(S).Row.fromColumns(values[2..]),
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
    initial: Boundary,
    final: Boundary,
) !Evaluation(S) {
    try validateBoundaries(initial, final);
    const current = try Row(S).fromColumns(current_values);
    const next = try Row(S).fromColumns(next_values);
    const semantic =
        scheduler.Semantics(S).evaluate(current.scheduler, current.active);
    var out: [N_CONSTRAINTS]S = undefined;
    @memcpy(out[0..scheduler.N_CONSTRAINTS], &semantic.values);

    var at: usize = scheduler.N_CONSTRAINTS;
    const one = S.one();
    const not_last = one.sub(is_last);
    out[at] = one.sub(current.active).mul(current.mcycle);
    at += 1;
    out[at] = not_last.mul(one.sub(current.active)).mul(next.active);
    at += 1;

    const chain_selector = not_last.mul(next.active);
    for (stateAfter(current.scheduler), stateBefore(next.scheduler)) |
        after,
        before,
    | {
        out[at] = chain_selector.mul(after.sub(before));
        at += 1;
    }
    const mcycles = compose(current.scheduler.mcycle_bits);
    out[at] = chain_selector.mul(
        next.mcycle.sub(current.mcycle).sub(mcycles),
    );
    at += 1;

    out[at] = is_first.mul(current.active.sub(one));
    at += 1;
    out[at] = is_first.mul(
        current.mcycle.sub(constant(S, initial.mcycle)),
    );
    at += 1;
    const initial_state = boundaryState(S, initial);
    for (stateBefore(current.scheduler), initial_state) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }

    const final_clock =
        current.mcycle.add(mcycles).sub(constant(S, final.mcycle));
    appendFinalConstraint(
        S,
        &out,
        &at,
        final_clock,
        current.active,
        next.active,
        is_last,
    );
    const final_state = boundaryState(S, final);
    for (stateAfter(current.scheduler), final_state) |actual, expected| {
        appendFinalConstraint(
            S,
            &out,
            &at,
            actual.sub(expected),
            current.active,
            next.active,
            is_last,
        );
    }
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    step: scheduler.ValidatedStep,
    mcycle_before: u32,
) ![N_MAIN_COLUMNS]M31 {
    const mcycle_after = std.math.add(
        u32,
        mcycle_before,
        step.result.m_cycles,
    ) catch return error.SchedulerClockOverflow;
    if (mcycle_before >= M31_MODULUS or mcycle_after >= M31_MODULUS)
        return error.NonCanonicalSchedulerClock;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[0] = M31.one();
    out[1] = M31.fromCanonical(mcycle_before);
    const direct = scheduler.columns(step);
    @memcpy(out[2..], &direct);
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    main_offset: usize,
    initial: Boundary,
    final: Boundary,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
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
            self.main_offset + N_MAIN_COLUMNS,
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
            self.main_offset + N_MAIN_COLUMNS,
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
        current_values: []const QM31,
        next_values: []const QM31,
        is_first: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        try self.validateConfiguration();
        return evaluateRows(
            QM31,
            current_values,
            next_values,
            is_first,
            is_last,
            self.initial,
            self.final,
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
            main.len < self.main_offset + N_MAIN_COLUMNS)
            return error.InvalidProofShape;
        var current: [N_MAIN_COLUMNS]QM31 = undefined;
        var next: [N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..N_MAIN_COLUMNS],
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
            main.len < self.main_offset + N_MAIN_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + N_MAIN_COLUMNS,
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
            main[self.main_offset..][0..N_MAIN_COLUMNS],
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
            const next_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current: [N_MAIN_COLUMNS]QM31 = undefined;
            var next: [N_MAIN_COLUMNS]QM31 = undefined;
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
            return error.InvalidSchedulerLogSize;
        try validateBoundaries(self.initial, self.final);
    }
};

fn appendFinalConstraint(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    difference: S,
    current_active: S,
    next_active: S,
    is_last: S,
) void {
    const not_last = S.one().sub(is_last);
    out[at.*] = is_last.mul(current_active).mul(difference).add(
        not_last.mul(current_active.sub(next_active)).mul(difference),
    );
    at.* += 1;
}

fn stateBefore(row: anytype) [N_STATE_COLUMNS]@TypeOf(row.before_ime) {
    return .{
        row.before_ime,
        row.before_pending,
        row.before_halted,
        row.before_halt_bug,
    };
}

fn stateAfter(row: anytype) [N_STATE_COLUMNS]@TypeOf(row.after_ime) {
    return .{
        row.after_ime,
        row.after_pending,
        row.after_halted,
        row.after_halt_bug,
    };
}

fn boundaryState(comptime S: type, boundary: Boundary) [N_STATE_COLUMNS]S {
    return .{
        booleanConstant(S, boundary.ime),
        booleanConstant(S, boundary.ime_enable_pending),
        booleanConstant(S, boundary.halted),
        booleanConstant(S, boundary.halt_bug),
    };
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    const S = @TypeOf(bits[0]);
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn constant(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

fn booleanConstant(comptime S: type, value: bool) S {
    return if (value) S.one() else S.zero();
}

fn validateBoundaries(initial: Boundary, final: Boundary) !void {
    if (initial.mcycle >= M31_MODULUS or final.mcycle >= M31_MODULUS)
        return error.NonCanonicalSchedulerClock;
    if (final.mcycle < initial.mcycle)
        return error.InvalidSchedulerClockBoundary;
}

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
