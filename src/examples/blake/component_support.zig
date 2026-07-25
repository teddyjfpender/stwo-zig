//! Shared allocation, sampling, and quotient helpers for Blake AIR components.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_circle = @import("stwo_prover_impl").poly.circle;
const prover_twiddles = @import("stwo_prover_impl").poly.twiddles;

pub const CirclePointQM31 = circle.CirclePointQM31;

pub fn traceBounds(
    allocator: std.mem.Allocator,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    log_size: u32,
) !core_air_components.TraceLogDegreeBounds {
    const preprocessed = try filledLogs(allocator, preprocessed_columns, log_size);
    errdefer allocator.free(preprocessed);
    const main = try filledLogs(allocator, main_columns, log_size);
    errdefer allocator.free(main);
    const interaction = try filledLogs(allocator, interaction_columns, log_size);
    errdefer allocator.free(interaction);
    return core_air_components.TraceLogDegreeBounds.initOwned(
        try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
    );
}

pub fn maskPoints(
    allocator: std.mem.Allocator,
    point: CirclePointQM31,
    max_log_degree_bound: u32,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_secure_columns: usize,
) !core_air_components.MaskPoints {
    const preprocessed = try currentPointColumns(
        allocator,
        preprocessed_columns,
        point,
    );
    errdefer freePointColumns(allocator, preprocessed);
    const main = try currentPointColumns(allocator, main_columns, point);
    errdefer freePointColumns(allocator, main);

    const interaction_count = interaction_secure_columns * 4;
    const interaction = try allocator.alloc([]CirclePointQM31, interaction_count);
    var initialized: usize = 0;
    errdefer {
        for (interaction[0..initialized]) |column| allocator.free(column);
        allocator.free(interaction);
    }
    const previous = previousRowPoint(max_log_degree_bound, point);
    for (interaction, 0..) |*column, index| {
        column.* = if (index + 4 >= interaction_count)
            try allocator.dupe(CirclePointQM31, &.{ previous, point })
        else
            try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return core_air_components.MaskPoints.initOwned(
        try allocator.dupe(
            [][]CirclePointQM31,
            &.{ preprocessed, main, interaction },
        ),
    );
}

pub fn pointDenominatorInverse(
    point: CirclePointQM31,
    log_size: u32,
    max_log_degree_bound: u32,
) !QM31 {
    if (log_size > max_log_degree_bound) return error.InvalidProofShape;
    const fold = max_log_degree_bound - log_size;
    return (try core_constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(log_size).coset(),
        point.repeatedDouble(fold),
    ).inv());
}

pub fn domainDenominatorInverses(
    log_size: u32,
    eval_domain: anytype,
) ![2]M31 {
    const trace_coset = canonic.CanonicCoset.new(log_size).coset();
    return .{
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
}

pub fn evaluateOnDomain(
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
    if (coefficients.logSize() != trace_log_size)
        return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn extendEvaluations(
    allocator: std.mem.Allocator,
    eval_domain: anytype,
    buffers: []const []M31,
) !void {
    if (buffers.len == 0) return;
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
        buffers,
        eval_domain,
        view,
    );
}

pub fn pointSecureColumns(
    interaction: [][]QM31,
    base: usize,
    secure_columns: usize,
    current: []QM31,
) !QM31 {
    if (current.len != secure_columns) return error.InvalidProofShape;
    for (0..secure_columns) |secure_index| {
        var coordinates: [4]QM31 = undefined;
        for (0..4) |coordinate| {
            const column = interaction[base + 4 * secure_index + coordinate];
            const expected: usize = if (secure_index + 1 == secure_columns) 2 else 1;
            if (column.len != expected) return error.InvalidProofShape;
            coordinates[coordinate] = column[expected - 1];
        }
        current[secure_index] = QM31.fromPartialEvals(coordinates);
    }
    var previous_coordinates: [4]QM31 = undefined;
    const last_base = base + 4 * (secure_columns - 1);
    for (0..4) |coordinate| {
        previous_coordinates[coordinate] = interaction[last_base + coordinate][0];
    }
    return QM31.fromPartialEvals(previous_coordinates);
}

pub fn secureAt(
    columns: []const []const M31,
    base: usize,
    secure_index: usize,
    row: usize,
) QM31 {
    const offset = base + 4 * secure_index;
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
}

pub fn accumulateDomainConstraints(
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    eval_log_size: u32,
    row: usize,
    denominator_inverse: M31,
    constraints: []const QM31,
    column: *prover_air_accumulation.ColumnAccumulator,
) !void {
    _ = accumulator;
    if (column.random_coeff_powers.len != constraints.len)
        return error.InvalidProofShape;
    var combined = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        const power_index = constraints.len - 1 - index;
        combined = combined.add(
            column.random_coeff_powers[power_index].mul(constraint),
        );
    }
    _ = eval_log_size;
    column.accumulate(row, combined.mulM31(denominator_inverse));
}

fn filledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    value: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, value);
    return result;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, count);
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

fn previousRowPoint(
    max_log_degree_bound: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
