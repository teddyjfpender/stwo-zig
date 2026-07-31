//! Component adapter for chained DMG-B OAM DMA transition rows.
//!
//! The component proves the direct DMA equations and consecutive active-state
//! equality. It does not authenticate source bytes, FF46 CPU-bus writes, OAM
//! destination writes, or public initial/final hardware state; those remain
//! integration relations rather than claims of this leaf component.

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
const dma = @import("dma.zig");
const dma_runner = @import("../runner/dma.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const N_MAIN_COLUMNS: usize = dma.N_MAIN_COLUMNS + 1;
pub const N_CONSTRAINTS: usize =
    dma.N_CONSTRAINTS + dma.N_CHAIN_CONSTRAINTS + 1;

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
    const current = try dma.Semantics(S).Row.fromColumns(current_values);
    const next = try dma.Semantics(S).Row.fromColumns(next_values);
    const semantic = dma.Semantics(S).evaluate(current, current_active);
    const chain = dma.Semantics(S).evaluateChain(current, next);
    var out: [N_CONSTRAINTS]S = undefined;
    @memcpy(out[0..dma.N_CONSTRAINTS], &semantic.values);

    var at: usize = dma.N_CONSTRAINTS;
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

pub fn columns(step: dma.ValidatedStep) [N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[0] = M31.one();
    const direct = dma.columns(step);
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
                self.main_offset + dma.N_MAIN_COLUMNS,
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
                self.main_offset + dma.N_MAIN_COLUMNS,
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
            main.len < self.main_offset + dma.N_MAIN_COLUMNS)
            return error.InvalidProofShape;
        if (preprocessed[self.is_last_column].len < 1)
            return error.InvalidProofShape;
        const active = main[self.is_active_main_column];
        if (active.len != 2) return error.InvalidProofShape;

        var current: [dma.N_MAIN_COLUMNS]QM31 = undefined;
        var next: [dma.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..dma.N_MAIN_COLUMNS],
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
        if (trace.polys.items.len < 2) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_last_column or
            main.len <= self.is_active_main_column or
            main.len < self.main_offset + dma.N_MAIN_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + dma.N_MAIN_COLUMNS,
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
            main[self.main_offset..][0..dma.N_MAIN_COLUMNS],
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
            var current: [dma.N_MAIN_COLUMNS]QM31 = undefined;
            var next: [dma.N_MAIN_COLUMNS]QM31 = undefined;
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

test "DMA component binds semantic rows activity and chaining" {
    const component = Component{
        .log_size = 4,
        .is_last_column = 0,
        .is_active_main_column = 0,
        .main_offset = 1,
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    const first_transition = try dma_runner.Transition.apply(
        .{
            .clock = 20,
            .page = 0xc0,
            .copied = 4,
            .phase = .transfer,
        },
        .{ .transfer = 0x42 },
    );
    const second_transition = try dma_runner.Transition.apply(
        first_transition.after,
        .{ .transfer = 0x43 },
    );
    var first: [dma.N_MAIN_COLUMNS]QM31 = undefined;
    var second: [dma.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &first,
        dma.columns(try dma.ValidatedStep.init(first_transition)),
    ) |*value, source| value.* = QM31.fromBase(source);
    for (
        &second,
        dma.columns(try dma.ValidatedStep.init(second_transition)),
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

test "DMA component domain rejects semantic activity and vacuity mutations" {
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
    const transition = try dma_runner.Transition.apply(
        .{
            .clock = 30,
            .page = 0xfe,
            .copied = 7,
            .phase = .transfer,
        },
        .{ .transfer = 0xa5 },
    );
    const witness = dma.columns(try dma.ValidatedStep.init(transition));

    var is_last_values = [_]M31{M31.one()} ** evaluation_size;
    var active_values = [_]M31{M31.one()} ** evaluation_size;
    var main_values: [dma.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var main_polynomials: [dma.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &main_values,
        &main_polynomials,
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
    @memcpy(main[1..], &main_polynomials);
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

    @memset(&main_values[2], M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&main_values[2], witness[2]);

    @memset(&active_values, M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );

    for (&main_values) |*values| @memset(values, M31.zero());
    try expectDomainResult(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    @memset(&main_values[0], M31.one());
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
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    var all_zero = true;
    for (0..result.len()) |row|
        all_zero = all_zero and result.at(row).isZero();
    try std.testing.expectEqual(expect_zero, all_zero);
}
