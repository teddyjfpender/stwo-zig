//! Component adapter for chained deterministic DMG-B PPU timing rows.
//!
//! This component binds the direct timing AIR and consecutive active-state
//! equality. It inherits the fixed empty-line mode-3 ceiling: rendering,
//! scrolling/object/window stalls, first-line sub-dot skew, VRAM/OAM
//! contention and corruption, palettes, and pixel FIFOs are not proved here.
//! Nor does this leaf bind MMIO accesses or public initial/final PPU state.

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
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("component_domain.zig");
const ppu_air = @import("ppu_timing.zig");
const ppu_runner = @import("../runner/ppu_timing.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const N_MAIN_COLUMNS: usize = ppu_air.N_MAIN_COLUMNS + 1;
pub const N_CONSTRAINTS: usize =
    ppu_air.N_CONSTRAINTS + ppu_air.N_CHAIN_CONSTRAINTS + 1;
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
    is_last: S,
) !Evaluation(S) {
    const current =
        try ppu_air.Semantics(S).Row.fromColumns(current_values);
    const next =
        try ppu_air.Semantics(S).Row.fromColumns(next_values);
    const semantic =
        ppu_air.Semantics(S).evaluate(current, current_active);
    const chain =
        ppu_air.Semantics(S).evaluateChain(current, next);
    var out: [N_CONSTRAINTS]S = undefined;
    @memcpy(out[0..ppu_air.N_CONSTRAINTS], &semantic.values);

    var at: usize = ppu_air.N_CONSTRAINTS;
    const chain_active = S.one().sub(is_last).mul(next_active);
    for (chain.values) |constraint| {
        out[at] = chain_active.mul(constraint);
        at += 1;
    }
    out[at] = chain_active.mul(S.one().sub(current_active));
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(step: ppu_air.ValidatedStep) [N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[0] = M31.one();
    const direct = ppu_air.columns(step);
    @memcpy(out[1..], &direct);
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub const Component = struct {
    log_size: u32,
    is_last_column: usize,
    is_active_main_column: usize,
    main_offset: usize,

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
        // The lowered leaf and next-active state chaining are exactly cubic.
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(
            u32,
            self.is_last_column + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            @max(
                self.is_active_main_column + 1,
                self.main_offset + ppu_air.N_MAIN_COLUMNS,
            ),
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
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            self.is_last_column + 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            @max(
                self.is_active_main_column + 1,
                self.main_offset + ppu_air.N_MAIN_COLUMNS,
            ),
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
        return allocator.dupe(usize, &.{self.is_last_column});
    }

    pub fn evaluateRow(
        _: *const Self,
        current_values: []const QM31,
        next_values: []const QM31,
        current_active: QM31,
        next_active: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        return evaluateRows(
            QM31,
            current_values,
            next_values,
            current_active,
            next_active,
            is_last,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        if (preprocessed.len <= self.is_last_column or
            main.len <= self.is_active_main_column or
            main.len < self.main_offset + ppu_air.N_MAIN_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        if (preprocessed[self.is_last_column].len < 1)
            return error.InvalidProofShape;
        const active = main[self.is_active_main_column];
        if (active.len != 2) return error.InvalidProofShape;

        var current: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
        var next: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..ppu_air.N_MAIN_COLUMNS],
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
            preprocessed[self.is_last_column][0],
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(
                max_log_degree_bound - self.log_size,
            ),
        ).inv();
        for (evaluation.values) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_last_column or
            main.len <= self.is_active_main_column or
            main.len < self.main_offset + ppu_air.N_MAIN_COLUMNS)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const evaluation_log_size =
            self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + ppu_air.N_MAIN_COLUMNS,
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }

        evaluations[0] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_last_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        evaluations[1] = try component_domain.evaluationValues(
            allocator,
            main[self.is_active_main_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        for (
            main[self.main_offset..][0..ppu_air.N_MAIN_COLUMNS],
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
        const shift: std.math.Log2Int(usize) =
            @intCast(self.log_size);

        for (0..evaluation_size) |row| {
            const next_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
            var next: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &current,
                &next,
                evaluations[2..],
            ) |*current_value, *next_value, values| {
                current_value.* = QM31.fromBase(values[row]);
                next_value.* = QM31.fromBase(values[next_row]);
            }
            const evaluation = try self.evaluateRow(
                &current,
                &next,
                QM31.fromBase(evaluations[1][row]),
                QM31.fromBase(evaluations[1][next_row]),
                QM31.fromBase(evaluations[0][row]),
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
};

const Degree = struct {
    value: u32,

    fn variable() Degree {
        return .{ .value = 1 };
    }

    pub fn zero() Degree {
        return .{ .value = 0 };
    }

    pub fn one() Degree {
        return .{ .value = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .value = 0 };
    }

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .value = @max(left.value, right.value) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .value = left.value + right.value };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};

fn auditedMaxConstraintDegree() !u32 {
    const variable = Degree.variable();
    const values =
        [_]Degree{variable} ** ppu_air.N_MAIN_COLUMNS;
    const row = try ppu_air.Semantics(Degree).Row.fromColumns(&values);
    const direct =
        ppu_air.Semantics(Degree).evaluate(row, variable);
    var maximum: u32 = 0;
    for (direct.values) |constraint|
        maximum = @max(maximum, constraint.value);

    const chained = try evaluateRows(
        Degree,
        &values,
        &values,
        variable,
        variable,
        variable,
    );
    for (chained.values) |constraint|
        maximum = @max(maximum, constraint.value);
    return maximum;
}

fn nextRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

test "PPU timing component owns offset geometry and exact degree" {
    const allocator = std.testing.allocator;
    const component = Component{
        .log_size = 4,
        .is_last_column = 2,
        .is_active_main_column = 3,
        .main_offset = 7,
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(
        MAX_CONSTRAINT_DEGREE,
        try auditedMaxConstraintDegree(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + ppu_air.N_MAIN_COLUMNS),
        bounds.items[1].len,
    );

    var mask = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), mask.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + ppu_air.N_MAIN_COLUMNS),
        mask.items[1].len,
    );
    for (mask.items[0]) |column|
        try std.testing.expectEqual(@as(usize, 1), column.len);
    for (mask.items[1]) |column|
        try std.testing.expectEqual(@as(usize, 2), column.len);

    const first_transition = try ppu_runner.Transition.apply(
        .{},
        .{ .write_lcdc = 0x80 },
    );
    const second_transition = try ppu_runner.Transition.apply(
        first_transition.after,
        .tick_dot,
    );
    var first: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
    var second: [ppu_air.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &first,
        ppu_air.columns(
            try ppu_air.ValidatedStep.init(first_transition),
        ),
    ) |*value, source| value.* = QM31.fromBase(source);
    for (
        &second,
        ppu_air.columns(
            try ppu_air.ValidatedStep.init(second_transition),
        ),
    ) |*value, source| value.* = QM31.fromBase(source);
    try std.testing.expect(
        (try component.evaluateRow(
            &first,
            &second,
            QM31.one(),
            QM31.one(),
            QM31.zero(),
        )).allZero(),
    );

    second[4] = QM31.one().sub(second[4]);
    try std.testing.expect(
        !(try component.evaluateRow(
            &first,
            &second,
            QM31.one(),
            QM31.one(),
            QM31.zero(),
        )).allZero(),
    );
    try std.testing.expect(
        !(try component.evaluateRow(
            &first,
            &first,
            QM31.zero(),
            QM31.zero(),
            QM31.one(),
        )).allZero(),
    );
}

test "PPU timing domain rejects semantic activity and vacuity mutations" {
    const allocator = std.testing.allocator;
    const component = Component{
        .log_size = 4,
        .is_last_column = 0,
        .is_active_main_column = 0,
        .main_offset = 1,
    };
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;
    try std.testing.expectEqual(
        evaluation_log_size,
        component.maxConstraintLogDegreeBound(),
    );
    const transition = try ppu_runner.Transition.apply(
        .{},
        .{ .write_lcdc = 0x80 },
    );
    const witness = ppu_air.columns(
        try ppu_air.ValidatedStep.init(transition),
    );

    var is_last_values = [_]M31{M31.one()} ** evaluation_size;
    var active_values = [_]M31{M31.one()} ** evaluation_size;
    var air_values: [ppu_air.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var air_polynomials: [ppu_air.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (
        &air_values,
        &air_polynomials,
        witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    const is_last = prover_component.Poly{
        .log_size = evaluation_log_size,
        .values = &is_last_values,
    };
    const active = prover_component.Poly{
        .log_size = evaluation_log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{is_last};
    var main: [N_MAIN_COLUMNS]prover_component.Poly = undefined;
    main[0] = active;
    @memcpy(main[1..], &air_polynomials);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);

    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    @memset(&air_values[1], M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&air_values[1], witness[1]);

    @memset(&active_values, M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );

    for (&air_values) |*values| @memset(values, M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    @memset(&air_values[0], M31.one());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn expectDomainResult(
    allocator: std.mem.Allocator,
    component: *const Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expect_zero: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            challenge,
            evaluation_log_size,
            N_CONSTRAINTS,
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        trace,
        &accumulator,
    );
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    var all_zero = true;
    for (0..result.len()) |row|
        all_zero = all_zero and result.at(row).isZero();
    try std.testing.expectEqual(expect_zero, all_zero);
}
