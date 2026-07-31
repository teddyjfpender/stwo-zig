//! Semantic-only AIR owner for one committed opcode-family trace.
//!
//! This component owns the family's raw main columns, aliases the global
//! `IsActive` selector, and declares no interaction columns. Relation placement
//! belongs to the lookup adapters; keeping it out of this component prevents
//! semantic and LogUp ownership from becoming coupled again.

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
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const semantic_eval = @import("semantic_eval.zig");
const trace = @import("../runner/trace.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const SemanticComponent = struct {
    family: trace.OpcodeFamily,
    log_size: u32,
    is_active_col_idx: usize,
    main_col_offset: usize,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn init(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_active_col_idx: usize,
        main_col_offset: usize,
    ) !SemanticComponent {
        if (!semantic_eval.isTraceCompatible(family)) {
            return error.IncompatibleCommittedTrace;
        }
        return .{
            .family = family,
            .log_size = log_size,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn mainColumnCount(self: *const @This()) usize {
        return semantic_eval.mainColumnCount(self.family);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return semantic_eval.constraintCount(self.family);
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return semantic_eval.constraintLogDegreeBound(self.family, self.log_size);
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{self.log_size});
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, self.mainColumnCount());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(u32, 0);
        errdefer allocator.free(interaction);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(allocator, 1, point);
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, self.mainColumnCount(), point);
        errdefer freePointColumns(allocator, main);
        const interaction = try currentPointColumns(allocator, 0, point);
        errdefer freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{self.is_active_col_idx});
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3) {
            return error.InvalidProofShape;
        }
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const n_main = self.mainColumnCount();
        if (preprocessed.len <= self.is_active_col_idx or
            preprocessed[self.is_active_col_idx].len < 1 or
            main.len < self.main_col_offset + n_main)
        {
            return error.InvalidProofShape;
        }

        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], main[self.main_col_offset..][0..n_main]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        const evaluation = try self.evaluateRow(
            sampled[0..n_main],
            preprocessed[self.is_active_col_idx][0],
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values[0..evaluation.len]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const n_main = self.mainColumnCount();
        if (preprocessed.len <= self.is_active_col_idx or
            main.len < self.main_col_offset + n_main)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.maxConstraintLogDegreeBound();
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const evaluations = try allocator.alloc([]const M31, 1 + n_main);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        evaluations[0] = try evaluationValues(
            allocator,
            preprocessed[self.is_active_col_idx],
            self.log_size,
            eval_log_size,
            eval_size,
            &extension_buffers,
        );
        for (main[self.main_col_offset..][0..n_main], evaluations[1..]) |poly, *values| {
            values.* = try evaluationValues(
                allocator,
                poly,
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                eval_domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const denominator_inv = try quotientDenominators(
            allocator,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        defer allocator.free(denominator_inv);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }},
        );
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const powers = column_accumulator.random_coeff_powers;
        for (0..eval_size) |row| {
            var sampled: [trace.MAX_FAMILY_COLUMNS]semantic_eval.BaseScalar = undefined;
            for (sampled[0..n_main], evaluations[1..]) |*value, column| {
                value.* = semantic_eval.BaseScalar.fromBase(column[row]);
            }
            const evaluation = try semantic_eval.BaseEval.evaluate(
                self.family,
                sampled[0..n_main],
                semantic_eval.BaseScalar.fromBase(evaluations[0][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values[0..evaluation.len], 0..) |constraint, index| {
                folded = folded.add(
                    powers[powers.len - 1 - index].mulM31(constraint.value),
                );
            }
            column_accumulator.accumulate(
                row,
                folded.mulM31(denominator_inv[row >> denominator_shift]),
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        main: []const QM31,
        is_active: QM31,
    ) !semantic_eval.Evaluation {
        if (!semantic_eval.isTraceCompatible(self.family)) {
            return error.IncompatibleCommittedTrace;
        }
        return semantic_eval.evaluate(self.family, main, is_active);
    }
};

fn evaluationValues(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
    eval_size: usize,
    extension_buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log_size) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try extension_buffers.append(allocator, values);
    return values;
}

fn quotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![]M31 {
    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    const result = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
