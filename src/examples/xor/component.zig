//! Exact Native XOR algebraic and truth-table LogUp AIR.

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
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const input = @import("input.zig");
const interaction = @import("interaction.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const N_CONSTRAINTS: usize = 14;

pub const DomainRowInput = struct {
    log_size: u32,
    preprocessed: [input.PREPROCESSED_COLUMNS]M31,
    main: [input.MAIN_COLUMNS]M31,
    current: QM31,
    previous: QM31,
    lookup_elements: interaction.LookupElements,
    claimed_sum: QM31,
    random_powers: [N_CONSTRAINTS]QM31,
    denominator_inverse: M31,
};

pub const Component = struct {
    log_size: u32,
    lookup_elements: interaction.LookupElements,
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
        return N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(
            allocator,
            input.PREPROCESSED_COLUMNS,
            self.log_size,
        );
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, input.MAIN_COLUMNS, self.log_size);
        errdefer allocator.free(main);
        const interaction_logs = try filledLogs(
            allocator,
            interaction.N_COLUMNS,
            self.log_size,
        );
        errdefer allocator.free(interaction_logs);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction_logs }),
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try currentPointColumns(
            allocator,
            input.PREPROCESSED_COLUMNS,
            point,
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, input.MAIN_COLUMNS, point);
        errdefer freePointColumns(allocator, main);

        const previous = previousRowPoint(max_log_degree_bound, point);
        const secure = try allocator.alloc([]CirclePointQM31, interaction.N_COLUMNS);
        var initialized: usize = 0;
        errdefer {
            for (secure[0..initialized]) |column| allocator.free(column);
            allocator.free(secure);
        }
        for (secure) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
            initialized += 1;
        }
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const indices = try allocator.alloc(usize, input.PREPROCESSED_COLUMNS);
        for (indices, 0..) |*value, index| value.* = index;
        return indices;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        try validatePointMask(preprocessed, main, secure);

        var pre_values: [input.PREPROCESSED_COLUMNS]QM31 = undefined;
        for (&pre_values, preprocessed) |*out, column| out.* = column[0];
        var main_values: [input.MAIN_COLUMNS]QM31 = undefined;
        for (&main_values, main) |*out, column| out.* = column[0];
        const current = try sampledSecure(secure, 0);
        const previous = try sampledSecure(secure, 1);
        const row_constraints = self.evaluateRow(
            pre_values,
            main_values,
            current,
            previous,
        );

        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        for (row_constraints) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len != 3 or
            trace.polys.items[0].len != input.PREPROCESSED_COLUMNS or
            trace.polys.items[1].len != input.MAIN_COLUMNS or
            trace.polys.items[2].len != interaction.N_COLUMNS)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_sources = input.PREPROCESSED_COLUMNS +
            input.MAIN_COLUMNS + interaction.N_COLUMNS;
        const evaluations = try allocator.alloc([]const M31, n_sources);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        var source: usize = 0;
        for (trace.polys.items) |tree| {
            for (tree) |poly| {
                evaluations[source] = try evaluationOnDomain(
                    allocator,
                    poly,
                    self.log_size,
                    eval_log_size,
                    eval_size,
                    &extension_buffers,
                );
                source += 1;
            }
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
        var accumulators = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = N_CONSTRAINTS,
        }});
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const main_start = input.PREPROCESSED_COLUMNS;
        const secure_start = main_start + input.MAIN_COLUMNS;

        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            var pre_values: [input.PREPROCESSED_COLUMNS]QM31 = undefined;
            for (&pre_values, evaluations[0..input.PREPROCESSED_COLUMNS]) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            var main_values: [input.MAIN_COLUMNS]QM31 = undefined;
            for (
                &main_values,
                evaluations[main_start .. main_start + input.MAIN_COLUMNS],
            ) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            const row_constraints = self.evaluateRow(
                pre_values,
                main_values,
                secureAt(evaluations[secure_start..], row),
                secureAt(evaluations[secure_start..], previous_row),
            );
            var combined = QM31.zero();
            for (row_constraints, 0..) |constraint, constraint_index| {
                const power_index = N_CONSTRAINTS - 1 - constraint_index;
                combined = combined.add(
                    column_accumulator.random_coeff_powers[power_index].mul(constraint),
                );
            }
            column_accumulator.accumulate(
                row,
                combined.mulM31(
                    denominator_inv[row >> @intCast(self.log_size)],
                ),
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        preprocessed: [input.PREPROCESSED_COLUMNS]QM31,
        main: [input.MAIN_COLUMNS]QM31,
        current: QM31,
        previous: QM31,
    ) [N_CONSTRAINTS]QM31 {
        const is_first = preprocessed[@intFromEnum(input.Preprocessed.is_first)];
        const is_step = preprocessed[@intFromEnum(input.Preprocessed.is_step)];
        const row_bit = preprocessed[@intFromEnum(input.Preprocessed.row_bit)];
        const table_selector =
            preprocessed[@intFromEnum(input.Preprocessed.table_selector)];
        const table_a = preprocessed[@intFromEnum(input.Preprocessed.table_a)];
        const table_b = preprocessed[@intFromEnum(input.Preprocessed.table_b)];
        const table_c = preprocessed[@intFromEnum(input.Preprocessed.table_c)];
        const a = main[@intFromEnum(input.Main.a)];
        const b = main[@intFromEnum(input.Main.b)];
        const c = main[@intFromEnum(input.Main.c)];
        const multiplicity = main[@intFromEnum(input.Main.multiplicity)];

        const table_denominator = self.lookup_elements.combineSecure(
            table_a,
            table_b,
            table_c,
        );
        const execution_denominator = self.lookup_elements.combineSecure(a, b, c);
        const delta = current.sub(previous).add(is_first.mul(self.claimed_sum));
        const logup = delta.mul(table_denominator).mul(execution_denominator)
            .sub(multiplicity.mul(execution_denominator))
            .add(table_denominator);

        return .{
            booleanConstraint(is_first),
            booleanConstraint(a),
            booleanConstraint(b),
            booleanConstraint(c),
            xorConstraint(a, b, c),
            a.sub(row_bit),
            b.sub(is_step),
            booleanConstraint(table_selector),
            booleanConstraint(table_a),
            booleanConstraint(table_b),
            booleanConstraint(table_c),
            xorConstraint(table_a, table_b, table_c),
            multiplicity.mul(QM31.one().sub(table_selector)),
            logup,
        };
    }
};

pub fn evaluateDomainRow(domain: DomainRowInput) QM31 {
    var preprocessed: [input.PREPROCESSED_COLUMNS]QM31 = undefined;
    for (&preprocessed, domain.preprocessed) |*out, value| {
        out.* = QM31.fromBase(value);
    }
    var main: [input.MAIN_COLUMNS]QM31 = undefined;
    for (&main, domain.main) |*out, value| {
        out.* = QM31.fromBase(value);
    }
    const component = Component{
        .log_size = domain.log_size,
        .lookup_elements = domain.lookup_elements,
        .claimed_sum = domain.claimed_sum,
    };
    const constraints = component.evaluateRow(
        preprocessed,
        main,
        domain.current,
        domain.previous,
    );
    var combined = QM31.zero();
    for (constraints, 0..) |constraint, constraint_index| {
        const power_index = N_CONSTRAINTS - 1 - constraint_index;
        combined = combined.add(
            domain.random_powers[power_index].mul(constraint),
        );
    }
    return combined.mulM31(domain.denominator_inverse);
}

fn booleanConstraint(value: QM31) QM31 {
    return value.mul(value.sub(QM31.one()));
}

fn xorConstraint(a: QM31, b: QM31, c: QM31) QM31 {
    return c.sub(a).sub(b).add(a.mul(b).mulM31(M31.fromCanonical(2)));
}

fn sampledSecure(columns: [][]QM31, point_index: usize) !QM31 {
    if (columns.len != interaction.N_COLUMNS) return error.InvalidProofShape;
    var coordinates: [interaction.N_COLUMNS]QM31 = undefined;
    for (columns, &coordinates) |column, *coordinate| {
        if (column.len <= point_index) return error.InvalidProofShape;
        coordinate.* = column[point_index];
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

fn validatePointMask(
    preprocessed: [][]QM31,
    main: [][]QM31,
    secure: [][]QM31,
) !void {
    if (preprocessed.len != input.PREPROCESSED_COLUMNS or
        main.len != input.MAIN_COLUMNS or
        secure.len != interaction.N_COLUMNS)
    {
        return error.InvalidProofShape;
    }
    for (preprocessed) |column| if (column.len != 1) return error.InvalidProofShape;
    for (main) |column| if (column.len != 1) return error.InvalidProofShape;
    for (secure) |column| if (column.len != 2) return error.InvalidProofShape;
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

fn filledLogs(allocator: std.mem.Allocator, n: usize, value: u32) ![]u32 {
    const result = try allocator.alloc(u32, n);
    @memset(result, value);
    return result;
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

fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
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

test "Native XOR row rejects a false XOR tuple" {
    const component = Component{
        .log_size = 4,
        .lookup_elements = .{ .z = QM31.fromU32Unchecked(7, 8, 9, 10), .alpha = QM31.one() },
        .claimed_sum = QM31.zero(),
    };
    var preprocessed = [_]QM31{QM31.zero()} ** input.PREPROCESSED_COLUMNS;
    preprocessed[@intFromEnum(input.Preprocessed.is_first)] = QM31.one();
    preprocessed[@intFromEnum(input.Preprocessed.row_bit)] = QM31.one();
    preprocessed[@intFromEnum(input.Preprocessed.table_selector)] = QM31.one();
    preprocessed[@intFromEnum(input.Preprocessed.table_a)] = QM31.one();
    preprocessed[@intFromEnum(input.Preprocessed.table_c)] = QM31.one();
    var main = [_]QM31{QM31.zero()} ** input.MAIN_COLUMNS;
    main[@intFromEnum(input.Main.a)] = QM31.one();
    main[@intFromEnum(input.Main.c)] = QM31.zero();

    const constraints = component.evaluateRow(
        preprocessed,
        main,
        QM31.zero(),
        QM31.zero(),
    );
    try std.testing.expect(!constraints[4].isZero());
}

test "Native XOR storage order previous row matches the circle-domain mask" {
    const log_size: u32 = 5;
    const n = @as(usize, 1) << @intCast(log_size);
    for (0..n) |row| {
        const storage = input.storageIndex(row, log_size);
        const previous_storage = utils.previousBitReversedCircleDomainIndex(
            storage,
            log_size,
            log_size,
        );
        const expected = input.storageIndex((row + n - 1) % n, log_size);
        try std.testing.expectEqual(expected, previous_storage);
    }
}
