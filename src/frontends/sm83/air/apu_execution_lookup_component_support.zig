//! Shared sampling and order helpers for the APU execution lookup components.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const component_domain = @import("component_domain.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const lookup = @import("apu_execution_lookup.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;
const N_MAX_CONSTRAINTS: usize = @max(
    lookup.N_EXECUTION_CONSTRAINTS,
    lookup.N_APU_CONSTRAINTS,
);

pub fn appendExecutionOrder(
    access: cartridge_access.PackedRow(QM31),
    order: QM31,
    next_order: QM31,
    is_first: QM31,
    is_last: QM31,
    total: usize,
    constraints: *[N_MAX_CONSTRAINTS]QM31,
) usize {
    const values = lookup.executionOrderConstraints(
        QM31,
        order,
        next_order,
        lookup.executionSelectors(QM31, access),
        is_first,
        is_last,
        countConstant(total),
    );
    @memcpy(
        constraints[lookup.N_EXECUTION_SUMS..lookup.N_EXECUTION_CONSTRAINTS],
        &values,
    );
    return lookup.N_EXECUTION_CONSTRAINTS;
}

pub fn appendApuOrder(
    active: QM31,
    next_active: QM31,
    clock: QM31,
    order: QM31,
    next_order: QM31,
    is_first: QM31,
    is_last: QM31,
    total: usize,
    constraints: *[N_MAX_CONSTRAINTS]QM31,
) usize {
    const values = lookup.apuOrderConstraints(
        QM31,
        active,
        next_active,
        clock,
        order,
        next_order,
        is_first,
        is_last,
        countConstant(total),
        if (total == 0) QM31.zero() else QM31.one(),
    );
    @memcpy(constraints[1..lookup.N_APU_CONSTRAINTS], &values);
    return lookup.N_APU_CONSTRAINTS;
}

fn countConstant(value: usize) QM31 {
    return QM31.fromBase(M31.fromCanonical(@intCast(value)));
}

pub fn extendRange(
    allocator: std.mem.Allocator,
    polynomials: []const prover_component.Poly,
    evaluations: [][]const M31,
    start: usize,
    source_log_size: u32,
    evaluation_log_size: u32,
    evaluation_size: usize,
    extensions: *std.ArrayList([]M31),
) !usize {
    var at = start;
    for (polynomials) |polynomial| {
        evaluations[at] = try component_domain.evaluationValues(
            allocator,
            polynomial,
            source_log_size,
            evaluation_log_size,
            evaluation_size,
            extensions,
        );
        at += 1;
    }
    return at;
}

pub fn sampledCurrentColumns(output: []QM31, columns: [][]QM31) !void {
    if (output.len != columns.len) return error.InvalidProofShape;
    for (output, columns) |*value, column| {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
}

pub fn sampledCurrentNextColumns(
    current: []QM31,
    next: []QM31,
    columns: [][]QM31,
) !void {
    if (current.len != columns.len or next.len != columns.len)
        return error.InvalidProofShape;
    for (current, next, columns) |*current_value, *next_value, column| {
        if (column.len < 2) return error.InvalidProofShape;
        current_value.* = column[0];
        next_value.* = column[1];
    }
}

pub fn domainColumns(
    output: []QM31,
    evaluations: []const []const M31,
    start: usize,
    row: usize,
) usize {
    for (output, evaluations[start..][0..output.len]) |*value, values|
        value.* = QM31.fromBase(values[row]);
    return start + output.len;
}

pub fn domainCurrentNextColumns(
    current: []QM31,
    next: []QM31,
    evaluations: []const []const M31,
    start: usize,
    row: usize,
    next_row: usize,
) usize {
    for (
        current,
        next,
        evaluations[start..][0..current.len],
    ) |*current_value, *next_value, values| {
        current_value.* = QM31.fromBase(values[row]);
        next_value.* = QM31.fromBase(values[next_row]);
    }
    return start + current.len;
}

pub fn nextRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

pub fn previousRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

pub fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point: usize,
) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns.len <= offset + index or
            columns[offset + index].len <= point)
            return error.InvalidProofShape;
        coordinate.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

pub fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}
