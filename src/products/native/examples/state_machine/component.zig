//! Exact pinned-Stwo state-transition LogUp AIR component.

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
const prover_circle = @import("stwo_prover_engine").poly.circle;
const secure_column = @import("stwo_prover_engine").secure_column;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const statement_mod = @import("statement.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Component = struct {
    log_size: u32,
    coordinate: usize,
    main_offset: usize,
    interaction_offset: usize,
    lookup_elements: statement_mod.Elements,
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
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, 2, self.log_size);
        errdefer allocator.free(main);
        const interaction = try filledLogs(allocator, 4, self.log_size);
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
        if (self.log_size > max_log_degree_bound) return error.InvalidProofShape;
        const local_point = point;
        const preprocessed = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed);
        const main = try currentPointColumns(allocator, 2, local_point);
        errdefer freeMaskColumns(allocator, main);
        const previous = previousRowPoint(max_log_degree_bound, local_point);
        const interaction = try allocator.alloc([]CirclePointQM31, 4);
        var initialized: usize = 0;
        errdefer {
            for (interaction[0..initialized]) |column| allocator.free(column);
            allocator.free(interaction);
        }
        for (interaction) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ previous, local_point });
            initialized += 1;
        }
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe(
                [][]CirclePointQM31,
                &.{ preprocessed, main, interaction },
            ),
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
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        try self.validate();
        if (mask.items.len < 3 or
            mask.items[0].len != 0 or
            mask.items[1].len != 4 or
            mask.items[2].len != 8)
        {
            return error.InvalidProofShape;
        }
        const main = mask.items[1];
        const interaction = mask.items[2];
        for (main) |column| if (column.len != 1) return error.InvalidProofShape;
        for (interaction) |column| if (column.len != 2) return error.InvalidProofShape;

        const state = [2]QM31{
            main[self.main_offset][0],
            main[self.main_offset + 1][0],
        };
        const previous = try sampledSecure(interaction, self.interaction_offset, 0);
        const current = try sampledSecure(interaction, self.interaction_offset, 1);
        const transition_constraint = try self.constraint(state, current, previous);
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        accumulator.accumulate(transition_constraint.mul(denominator_inv));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validate();
        if (trace.polys.items.len != 3 or
            trace.polys.items[0].len != 0 or
            trace.polys.items[1].len != 4 or
            trace.polys.items[2].len != 8)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        var evaluations: [6][]const M31 = undefined;
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        for (0..2) |index| {
            evaluations[index] = try evaluationOnDomain(
                allocator,
                trace.polys.items[1][self.main_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        for (0..4) |index| {
            evaluations[2 + index] = try evaluationOnDomain(
                allocator,
                trace.polys.items[2][self.interaction_offset + index],
                self.log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                eval_domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            const view = prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover_circle.poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                eval_domain,
                view,
            );
        }

        const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
        const denominator_inv = [_]M31{
            try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(0),
            ).inv(),
            try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(1),
            ).inv(),
        };
        var columns = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = 1,
        }});
        defer allocator.free(columns);
        const column = &columns[0];

        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            const state = [2]QM31{
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            };
            const current = secureAt(evaluations[2..6], row);
            const previous = secureAt(evaluations[2..6], previous_row);
            try accumulateWeighted(
                column,
                row,
                (try self.constraint(state, current, previous)).mulM31(
                    denominator_inv[row >> @intCast(self.log_size)],
                ),
            );
        }
    }

    fn validate(self: *const @This()) !void {
        if (self.coordinate >= 2 or
            self.main_offset + 2 > 4 or
            self.interaction_offset + 4 > 8)
        {
            return error.InvalidProofShape;
        }
    }

    fn constraint(
        self: *const @This(),
        state: [2]QM31,
        current: QM31,
        previous: QM31,
    ) !QM31 {
        var output_state = state;
        output_state[self.coordinate] = output_state[self.coordinate].add(QM31.one());
        const input_denominator = combineSecure(self.lookup_elements, state);
        const output_denominator = combineSecure(self.lookup_elements, output_state);
        const n = M31.fromU64(@as(u64, 1) << @intCast(self.log_size));
        const delta = current.sub(previous).add(try self.claimed_sum.divM31(n));
        return delta.mul(input_denominator).mul(output_denominator)
            .sub(output_denominator.sub(input_denominator));
    }
};

fn combineSecure(elements: statement_mod.Elements, state: [2]QM31) QM31 {
    return state[0].add(elements.alpha.mul(state[1])).sub(elements.z);
}

fn accumulateWeighted(
    column: *prover_air_accumulation.ColumnAccumulator,
    row: usize,
    quotient: QM31,
) !void {
    if (column.random_coeff_powers.len != 1) return error.InvalidProofShape;
    column.accumulate(row, column.random_coeff_powers[0].mul(quotient));
}

fn sampledSecure(columns: [][]QM31, base: usize, point_index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |coordinate| {
        const column = columns[base + coordinate];
        if (column.len <= point_index) return error.InvalidProofShape;
        coordinates[coordinate] = column[point_index];
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

fn evaluationOnDomain(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
    eval_size: usize,
    buffers: *std.ArrayList([]M31),
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
    try buffers.append(allocator, values);
    return values;
}

fn filledLogs(allocator: std.mem.Allocator, n: usize, log_size: u32) ![]u32 {
    const values = try allocator.alloc(u32, n);
    @memset(values, log_size);
    return values;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    n: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, n);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return columns;
}

fn freeMaskColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

test "State Machine component owns and releases its exact trace geometry" {
    const component = Component{
        .log_size = 5,
        .coordinate = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .lookup_elements = .{ .z = QM31.one(), .alpha = QM31.one() },
        .claimed_sum = QM31.zero(),
    };
    try std.testing.expectEqual(@as(usize, 1), component.nConstraints());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[2].len);
}

test "State Machine components concatenate the exact mixed-height geometry" {
    const allocator = std.testing.allocator;
    const elements = statement_mod.Elements{
        .z = QM31.one(),
        .alpha = QM31.one(),
    };
    const component0 = Component{
        .log_size = 5,
        .coordinate = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .lookup_elements = elements,
        .claimed_sum = QM31.zero(),
    };
    const component1 = Component{
        .log_size = 4,
        .coordinate = 1,
        .main_offset = 2,
        .interaction_offset = 4,
        .lookup_elements = elements,
        .claimed_sum = QM31.zero(),
    };
    const component_values = [_]core_air_components.Component{
        component0.asVerifierComponent(),
        component1.asVerifierComponent(),
    };
    const components = core_air_components.Components{
        .components = component_values[0..],
        .n_preprocessed_columns = 0,
    };

    var bounds = try components.columnLogSizes(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqualSlices(u32, &.{}, bounds.items[0]);
    try std.testing.expectEqualSlices(u32, &.{ 5, 5, 4, 4 }, bounds.items[1]);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 5, 5, 5, 5, 4, 4, 4, 4 },
        bounds.items[2],
    );
}

test "State Machine component consumes its assigned composition power" {
    const allocator = std.testing.allocator;
    var values = try secure_column.SecureColumnByCoords.zeros(allocator, 2);
    defer values.deinit(allocator);
    const power = QM31.fromU32Unchecked(2, 3, 5, 7);
    const quotient = QM31.fromU32Unchecked(11, 13, 17, 19);
    var accumulator = prover_air_accumulation.ColumnAccumulator{
        .random_coeff_powers = &.{power},
        .col = &values,
        .next_fresh_index = 0,
    };

    try accumulateWeighted(&accumulator, 0, quotient);
    try std.testing.expect(values.at(0).eql(power.mul(quotient)));
}
