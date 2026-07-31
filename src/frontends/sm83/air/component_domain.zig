//! Shared circle-domain sampling and quotient helpers for SM83 components.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_component = @import("stwo_prover_engine").air.component_prover;

const CirclePointQM31 = circle.CirclePointQM31;

pub fn evaluationValues(
    allocator: std.mem.Allocator,
    polynomial: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
    evaluation_size: usize,
    extension_buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try polynomial.validate();
    if (polynomial.log_size == evaluation_log_size) return polynomial.values;
    const coefficients = polynomial.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M31, evaluation_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try extension_buffers.append(allocator, values);
    return values;
}

pub fn quotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    evaluation_log_size: u32,
    evaluation_domain: anytype,
) ![]M31 {
    const extension_bits: u5 = @intCast(evaluation_log_size - log_size);
    const result = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            evaluation_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

pub fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    return repeatedPointColumns(allocator, count, &.{point});
}

pub fn currentAndNextPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    next: CirclePointQM31,
) ![][]CirclePointQM31 {
    return repeatedPointColumns(allocator, count, &.{ point, next });
}

pub fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    return repeatedPointColumns(allocator, count, &.{ point, previous });
}

pub fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn repeatedPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    points: []const CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}

test "quotient denominators match every bit-reversed evaluation row" {
    const allocator = std.testing.allocator;
    const trace_log_size: u32 = 4;
    const coset = canonic.CanonicCoset.new(trace_log_size).coset();
    for (trace_log_size + 1..trace_log_size + 6) |evaluation_log_usize| {
        const evaluation_log_size: u32 = @intCast(evaluation_log_usize);
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const inverses = try quotientDenominators(
            allocator,
            trace_log_size,
            evaluation_log_size,
            domain,
        );
        defer allocator.free(inverses);
        const shift: std.math.Log2Int(usize) =
            @intCast(trace_log_size);
        for (0..domain.size()) |row| {
            const point = domain.at(
                utils.bitReverseIndex(row, evaluation_log_size),
            );
            const expected = try core_constraints.cosetVanishing(
                M31,
                coset,
                point,
            ).inv();
            try std.testing.expect(
                expected.eql(inverses[row >> shift]),
            );
        }
    }
}
