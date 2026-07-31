//! Standalone proof component for an ordered prefix of timer events.
//!
//! This binds the cubic timer leaf, consecutive complete timer state, one
//! non-empty active prefix, and public initial/final timer states. Execution
//! cycle scheduling, FF04..FF07 MMIO, and IF remain separate relations.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("component_domain.zig");
const timer_air = @import("timer.zig");
const timer_runner = @import("../runner/timer.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_MAIN_COLUMNS: usize = timer_air.N_MAIN_COLUMNS + 1;
pub const N_CONSTRAINTS: usize =
    timer_air.N_CONSTRAINTS +
    timer_air.N_CHAIN_CONSTRAINTS +
    2 * timer_air.N_STATE_COLUMNS +
    2;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

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
    current_active: S,
    next_active: S,
    is_first: S,
    is_last: S,
    initial: timer_runner.Timer,
    final: timer_runner.Timer,
) !Evaluation(S) {
    const current =
        try timer_air.Semantics(S).Row.fromColumns(current_values);
    const next =
        try timer_air.Semantics(S).Row.fromColumns(next_values);
    const semantic = timer_air.Semantics(S).evaluate(
        current,
        current_active,
    );
    const chain = timer_air.Semantics(S).evaluateChain(current, next);
    var out: [N_CONSTRAINTS]S = undefined;
    @memcpy(out[0..timer_air.N_CONSTRAINTS], &semantic.values);

    var at: usize = timer_air.N_CONSTRAINTS;
    const one = S.one();
    const not_last = one.sub(is_last);
    const chain_active = not_last.mul(next_active);
    for (chain.values) |constraint| {
        out[at] = chain_active.mul(constraint);
        at += 1;
    }
    out[at] = not_last.mul(one.sub(current_active)).mul(next_active);
    at += 1;
    out[at] = is_first.mul(current_active.sub(one));
    at += 1;

    const initial_values = timer_air.stateConstants(S, initial);
    for (current.before.values, initial_values) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    const final_values = timer_air.stateConstants(S, final);
    for (current.after.values, final_values) |actual, expected| {
        const difference = actual.sub(expected);
        out[at] = is_last.mul(current_active).mul(difference).add(
            not_last.mul(current_active.sub(next_active)).mul(difference),
        );
        at += 1;
    }
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    step: timer_air.ValidatedStep,
) [N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[0] = M31.one();
    const direct = timer_air.columns(step);
    @memcpy(out[1..], &direct);
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
    initial: timer_runner.Timer,
    final: timer_runner.Timer,

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
        current_active: QM31,
        next_active: QM31,
        is_first: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        try self.validateConfiguration();
        return evaluateRows(
            QM31,
            current_values,
            next_values,
            current_active,
            next_active,
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
        const active = main[self.main_offset];
        if (active.len != 2) return error.InvalidProofShape;

        var current: [timer_air.N_MAIN_COLUMNS]QM31 = undefined;
        var next: [timer_air.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset + 1 ..][0..timer_air.N_MAIN_COLUMNS],
        ) |*current_value, *next_value, column| {
            if (column.len != 2) return error.InvalidProofShape;
            current_value.* = column[0];
            next_value.* = column[1];
        }
        const evaluation = try self.evaluateRow(
            &current,
            &next,
            active[0],
            active[1],
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
            const next_row = core.utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current: [timer_air.N_MAIN_COLUMNS]QM31 = undefined;
            var next: [timer_air.N_MAIN_COLUMNS]QM31 = undefined;
            for (&current, &next, evaluations[3..]) |
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
                QM31.fromBase(evaluations[2][row]),
                QM31.fromBase(evaluations[2][next_row]),
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
            return error.InvalidTimerLogSize;
    }
};

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
