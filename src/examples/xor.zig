const std = @import("std");
const m31 = @import("../core/fields/m31.zig");
const utils = @import("../core/utils.zig");

const M31 = m31.M31;

pub const Error = error{
    InvalidLogSize,
    InvalidStep,
};

/// Generates `IsFirst` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/mod.rs::IsFirst::gen_column_simd`.
pub fn genIsFirstColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![]M31 {
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());
    values[0] = M31.one();
    return values;
}

/// Generates `IsStepWithOffset` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/preprocessed_columns.rs`.
pub fn genIsStepWithOffsetColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
    log_step: u32,
    offset: usize,
) (std.mem.Allocator.Error || Error)![]M31 {
    if (log_step > log_size) return Error.InvalidStep;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const step = checkedPow2(log_step) catch return Error.InvalidLogSize;

    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());

    var i = offset % step;
    while (i < n) : (i += step) {
        const circle_domain_index = utils.cosetIndexToCircleDomainIndex(i, log_size);
        const bit_rev_index = utils.bitReverseIndex(circle_domain_index, log_size);
        values[bit_rev_index] = M31.one();
    }

    return values;
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "examples xor: is_first has exactly one leading one" {
    const alloc = std.testing.allocator;
    const values = try genIsFirstColumn(alloc, 5);
    defer alloc.free(values);

    try std.testing.expect(values[0].eql(M31.one()));
    for (values[1..]) |value| {
        try std.testing.expect(value.eql(M31.zero()));
    }
}

test "examples xor: is_step_with_offset rejects invalid step" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidStep,
        genIsStepWithOffsetColumn(alloc, 4, 5, 0),
    );
}
