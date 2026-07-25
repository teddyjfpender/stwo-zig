//! Exact scheduler relation component for the pinned Blake AIR.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const support = @import("component_support.zig");
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");
const logup = @import("logup_constraints.zig");
const statement_mod = @import("statement.zig");

pub const Component = struct {
    log_size: u32,
    main_offset: usize,
    interaction_offset: usize,
    elements: statement_mod.AllElements,
    claimed_sum: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return geometry.SCHEDULER_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        return support.traceBounds(
            allocator,
            0,
            geometry.SCHEDULER_MAIN_COLUMNS,
            4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS,
            self.log_size,
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: support.CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        return support.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
            0,
            geometry.SCHEDULER_MAIN_COLUMNS,
            geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS,
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: support.CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or
            mask.items[1].len < self.main_offset + geometry.SCHEDULER_MAIN_COLUMNS or
            mask.items[2].len <
                self.interaction_offset +
                    4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        var main: [geometry.SCHEDULER_MAIN_COLUMNS]QM31 = undefined;
        for (&main, mask.items[1][self.main_offset..][0..main.len]) |*out, column| {
            if (column.len != 1) return error.InvalidProofShape;
            out.* = column[0];
        }
        var current: [geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS]QM31 = undefined;
        const previous = try support.pointSecureColumns(
            mask.items[2],
            self.interaction_offset,
            current.len,
            &current,
        );
        var constraints: [geometry.SCHEDULER_CONSTRAINTS]QM31 = undefined;
        try self.evaluateRow(main, current, previous, &constraints);
        const denominator_inverse = try support.pointDenominatorInverse(
            point,
            self.log_size,
            max_log_degree_bound,
        );
        for (constraints) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3 or
            trace.polys.items[1].len <
                self.main_offset + geometry.SCHEDULER_MAIN_COLUMNS or
            trace.polys.items[2].len <
                self.interaction_offset +
                    4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const source_count = geometry.SCHEDULER_MAIN_COLUMNS +
            4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS;
        const evaluations = try allocator.alloc([]const M31, source_count);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        for (0..geometry.SCHEDULER_MAIN_COLUMNS) |index| {
            evaluations[index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[1][self.main_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        const interaction_start = geometry.SCHEDULER_MAIN_COLUMNS;
        for (0..4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS) |index| {
            evaluations[interaction_start + index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[2][self.interaction_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        try support.extendEvaluations(
            allocator,
            eval_domain,
            extension_buffers.items,
        );

        const denominator_inverses =
            try support.domainDenominatorInverses(self.log_size, eval_domain);
        var accumulator_columns = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = geometry.SCHEDULER_CONSTRAINTS,
        }});
        defer allocator.free(accumulator_columns);
        const column = &accumulator_columns[0];

        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            var main: [geometry.SCHEDULER_MAIN_COLUMNS]QM31 = undefined;
            for (&main, evaluations[0..geometry.SCHEDULER_MAIN_COLUMNS]) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            var current: [geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS]QM31 =
                undefined;
            for (&current, 0..) |*out, secure_index| {
                out.* = support.secureAt(
                    evaluations,
                    interaction_start,
                    secure_index,
                    row,
                );
            }
            const previous = support.secureAt(
                evaluations,
                interaction_start,
                current.len - 1,
                previous_row,
            );
            var constraints: [geometry.SCHEDULER_CONSTRAINTS]QM31 = undefined;
            try self.evaluateRow(main, current, previous, &constraints);
            try accumulate(
                column,
                row,
                constraints,
                denominator_inverses[row >> @intCast(self.log_size)],
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        main: [geometry.SCHEDULER_MAIN_COLUMNS]QM31,
        current: [geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS]QM31,
        previous: QM31,
        constraints: *[geometry.SCHEDULER_CONSTRAINTS]QM31,
    ) !void {
        var entries: [2 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS - 1]logup.Entry =
            undefined;
        for (0..constants.N_ROUNDS) |round_index| {
            var tuple: [constants.N_ROUND_INPUT_FELTS]QM31 = undefined;
            schedulerRoundTuple(main, round_index, &tuple);
            entries[round_index] = .{
                .multiplicity = QM31.one(),
                .denominator = self.elements.round.combineSecure(&tuple),
            };
        }
        var blake_tuple: [constants.N_ROUND_INPUT_FELTS]QM31 = undefined;
        schedulerBlakeTuple(main, &blake_tuple);
        entries[constants.N_ROUNDS] = .{
            .multiplicity = QM31.zero(),
            .denominator = self.elements.blake.combineSecure(&blake_tuple),
        };
        try logup.evaluate(
            &entries,
            &current,
            previous,
            self.claimed_sum,
            self.log_size,
            constraints,
        );
    }
};

fn schedulerRoundTuple(
    main: [geometry.SCHEDULER_MAIN_COLUMNS]QM31,
    round_index: usize,
    tuple: *[constants.N_ROUND_INPUT_FELTS]QM31,
) void {
    var index: usize = 0;
    const state_start = 2 * constants.MESSAGE_SIZE + round_index * 2 * constants.STATE_SIZE;
    @memcpy(tuple[index..][0 .. 2 * constants.STATE_SIZE], main[state_start..][0 .. 2 * constants.STATE_SIZE]);
    index += 2 * constants.STATE_SIZE;
    @memcpy(tuple[index..][0 .. 2 * constants.STATE_SIZE], main[state_start + 2 * constants.STATE_SIZE ..][0 .. 2 * constants.STATE_SIZE]);
    index += 2 * constants.STATE_SIZE;
    for (constants.SIGMA[round_index]) |message_index| {
        tuple[index] = main[2 * @as(usize, message_index)];
        tuple[index + 1] = main[2 * @as(usize, message_index) + 1];
        index += 2;
    }
}

fn schedulerBlakeTuple(
    main: [geometry.SCHEDULER_MAIN_COLUMNS]QM31,
    tuple: *[constants.N_ROUND_INPUT_FELTS]QM31,
) void {
    const message_felts = 2 * constants.MESSAGE_SIZE;
    const state_felts = 2 * constants.STATE_SIZE;
    @memcpy(tuple[0..state_felts], main[message_felts..][0..state_felts]);
    const final_start = message_felts + constants.N_ROUNDS * state_felts;
    @memcpy(tuple[state_felts .. 2 * state_felts], main[final_start..][0..state_felts]);
    @memcpy(tuple[2 * state_felts ..], main[0..message_felts]);
}

fn accumulate(
    column: *prover_air_accumulation.ColumnAccumulator,
    row: usize,
    constraints: [geometry.SCHEDULER_CONSTRAINTS]QM31,
    denominator_inverse: M31,
) !void {
    if (column.random_coeff_powers.len != constraints.len)
        return error.InvalidProofShape;
    var combined = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        combined = combined.add(
            column.random_coeff_powers[constraints.len - 1 - index]
                .mul(constraint),
        );
    }
    column.accumulate(row, combined.mulM31(denominator_inverse));
}

test "exact Blake scheduler exposes six paired relation constraints" {
    const component = Component{
        .log_size = 4,
        .main_offset = 0,
        .interaction_offset = 0,
        .elements = undefined,
        .claimed_sum = QM31.zero(),
    };
    try std.testing.expectEqual(@as(usize, 6), component.nConstraints());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        geometry.SCHEDULER_MAIN_COLUMNS,
        bounds.items[1].len,
    );
    try std.testing.expectEqual(
        4 * geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS,
        bounds.items[2].len,
    );
}
