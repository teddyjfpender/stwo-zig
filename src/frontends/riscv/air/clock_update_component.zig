//! Prover/verifier AIR adapter for the canonical unified clock-gap component.

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
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const interaction = @import("clock_update_interaction.zig");
const logup = @import("logup.zig");
const relations_mod = @import("relation_challenges.zig");
const state_chain = @import("../runner/state_chain.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const EMPTY_PREVIOUS: [interaction.N_INTERACTION_COLUMNS][]const M31 =
    .{&.{}} ** interaction.N_INTERACTION_COLUMNS;

pub const Evaluation = struct {
    values: [interaction.N_SUMS + 3]QM31,

    pub fn allZero(self: Evaluation) bool {
        for (self.values) |value| if (!value.isZero()) return false;
        return true;
    }
};

pub const ClockUpdateComponent = struct {
    log_size: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [interaction.N_SUMS]QM31,
    previous: [interaction.N_INTERACTION_COLUMNS][]const M31 = EMPTY_PREVIOUS,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
    ) ClockUpdateComponent {
        return init(
            log_size,
            is_first_col_idx,
            is_active_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
            EMPTY_PREVIOUS,
        );
    }

    pub fn initProver(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
        previous: [interaction.N_INTERACTION_COLUMNS][]const M31,
    ) !ClockUpdateComponent {
        const size = @as(usize, 1) << @intCast(log_size);
        for (previous) |column| {
            if (column.len != size) return error.InvalidTraceShape;
        }
        return init(
            log_size,
            is_first_col_idx,
            is_active_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
            previous,
        );
    }

    fn init(
        log_size: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [interaction.N_SUMS]QM31,
        previous: [interaction.N_INTERACTION_COLUMNS][]const M31,
    ) ClockUpdateComponent {
        return .{
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = claims,
            .previous = previous,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return interaction.N_SUMS + 3;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{ self.log_size, self.log_size });
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, interaction.N_MAIN_COLUMNS);
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const secure = try allocator.alloc(u32, interaction.N_INTERACTION_COLUMNS);
        errdefer allocator.free(secure);
        @memset(secure, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, secure }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(allocator, 2, point);
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, interaction.N_MAIN_COLUMNS, point);
        errdefer freePointColumns(allocator, main);
        const secure = try currentAndPreviousPointColumns(
            allocator,
            interaction.N_INTERACTION_COLUMNS,
            point,
            logup.prevRowPoint(max_log_degree_bound, point),
        );
        errdefer freePointColumns(allocator, secure);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{ self.is_first_col_idx, self.is_active_col_idx });
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
        const secure = mask.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
            main.len < self.main_col_offset + interaction.N_MAIN_COLUMNS or
            secure.len < self.interaction_col_offset + interaction.N_INTERACTION_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
        for (&sampled, main[self.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current: [interaction.N_SUMS]QM31 = undefined;
        var previous: [interaction.N_SUMS]QM31 = undefined;
        for (0..interaction.N_SUMS) |index| {
            const offset = self.interaction_col_offset + index * 4;
            current[index] = try sampledSecure(secure, offset, 0);
            previous[index] = try sampledSecure(secure, offset, 1);
        }
        const evaluation = try self.evaluateRow(
            &sampled,
            current,
            previous,
            preprocessed[self.is_first_col_idx][0],
            preprocessed[self.is_active_col_idx][0],
        );
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values) |constraint| {
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
        const secure = trace_data.polys.items[2];
        if (preprocessed.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or
            main.len < self.main_col_offset + interaction.N_MAIN_COLUMNS or
            secure.len < self.interaction_col_offset + interaction.N_INTERACTION_COLUMNS)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_committed = 2 + interaction.N_MAIN_COLUMNS + interaction.N_INTERACTION_COLUMNS;
        const n_sources = n_committed;
        const evaluations = try allocator.alloc([]const M31, n_sources);
        defer allocator.free(evaluations);
        var source: usize = 0;
        evaluations[source] = try committedValues(preprocessed[self.is_first_col_idx], eval_log_size);
        source += 1;
        evaluations[source] = try committedValues(preprocessed[self.is_active_col_idx], eval_log_size);
        source += 1;
        for (main[self.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }
        for (secure[self.interaction_col_offset..][0..interaction.N_INTERACTION_COLUMNS]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }

        std.debug.assert(source == n_sources);

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
        const main_start: usize = 2;
        const secure_start = main_start + interaction.N_MAIN_COLUMNS;
        const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
            for (&sampled, evaluations[main_start..][0..interaction.N_MAIN_COLUMNS]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            var current: [interaction.N_SUMS]QM31 = undefined;
            var previous: [interaction.N_SUMS]QM31 = undefined;
            for (0..interaction.N_SUMS) |index| {
                const offset = secure_start + index * 4;
                current[index] = secureAt(evaluations[offset..][0..4], row);
                previous[index] = secureAt(evaluations[offset..][0..4], previous_row);
            }
            const evaluation = try self.evaluateRow(
                &sampled,
                current,
                previous,
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = column_accumulator.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
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
        current: [interaction.N_SUMS]QM31,
        previous: [interaction.N_SUMS]QM31,
        is_first: QM31,
        is_active: QM31,
    ) !Evaluation {
        const row = try interaction.Row.fromMain(main);
        const pairs = try interaction.pairs(row, self.relations);
        var result: Evaluation = undefined;
        for (0..interaction.N_SUMS) |index| {
            result.values[index] = logup.pairConstraint(
                current[index],
                previous[index],
                is_first,
                self.claims[index],
                pairs[index],
            );
        }
        result.values[interaction.N_SUMS] =
            row.enabler.mul(QM31.one().sub(row.enabler));
        result.values[interaction.N_SUMS + 1] = row.enabler.sub(is_active);
        result.values[interaction.N_SUMS + 2] = row.enabler.mul(
            row.clock_prev.sub(
                row.clock_prev_low20.add(
                    row.clock_prev_high4.mul(
                        QM31.fromBase(M31.fromU64(
                            @as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS,
                        )),
                    ),
                ),
            ),
        );
        return result;
    }
};

fn committedValues(poly: prover_component.Poly, expected_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != expected_log_size) return error.InvalidProofShape;
    return poly.values;
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
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

fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
