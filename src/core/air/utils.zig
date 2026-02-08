const std = @import("std");
const m31_mod = @import("../fields/m31.zig");
const core_utils = @import("../utils.zig");

const M31 = m31_mod.M31;

pub const Error = error{
    InvalidLogSize,
    InvalidStep,
    PositionOutOfRange,
};

pub const ColumnError = error{
    InvalidLogSize,
    InvalidStep,
};

pub fn checkedPow2(log_size: u32) ColumnError!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn circleBitReversedIndex(log_size: u32, coset_index: usize) Error!usize {
    const n = try checkedPow2(log_size);
    if (coset_index >= n) return Error.PositionOutOfRange;

    const circle_domain_index = core_utils.cosetIndexToCircleDomainIndex(coset_index, log_size);
    return core_utils.bitReverseIndex(circle_domain_index, log_size);
}

/// Generates a bit-reversed `IsFirst` indicator column.
pub fn genIsFirstColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || ColumnError)![]M31 {
    const n = try checkedPow2(log_size);
    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());
    values[0] = M31.one();
    return values;
}

/// Generates a bit-reversed periodic indicator with period `2^log_step` and row `offset`.
pub fn genPeriodicIndicatorColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
    log_step: u32,
    offset: usize,
) (std.mem.Allocator.Error || ColumnError)![]M31 {
    if (log_step > log_size) return Error.InvalidStep;

    const n = try checkedPow2(log_size);
    const step = try checkedPow2(log_step);

    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());

    var i = offset % step;
    while (i < n) : (i += step) {
        const bit_rev_index = circleBitReversedIndex(log_size, i) catch unreachable;
        values[bit_rev_index] = M31.one();
    }

    return values;
}

test "air utils: is-first column" {
    const alloc = std.testing.allocator;

    const values = try genIsFirstColumn(alloc, 5);
    defer alloc.free(values);

    try std.testing.expect(values[0].isOne());
    var i: usize = 1;
    while (i < values.len) : (i += 1) {
        try std.testing.expect(values[i].isZero());
    }
}

test "air utils: periodic indicator bit-reversed positions" {
    const alloc = std.testing.allocator;

    const log_size: u32 = 5;
    const log_step: u32 = 2;
    const offset: usize = 3;

    const values = try genPeriodicIndicatorColumn(alloc, log_size, log_step, offset);
    defer alloc.free(values);

    const n = try checkedPow2(log_size);
    const step = try checkedPow2(log_step);

    var ones: usize = 0;
    var coset_index: usize = 0;
    while (coset_index < n) : (coset_index += 1) {
        const bit_rev_index = try circleBitReversedIndex(log_size, coset_index);
        const should_be_one = (coset_index % step) == (offset % step);
        if (should_be_one) {
            try std.testing.expect(values[bit_rev_index].isOne());
            ones += 1;
        } else {
            try std.testing.expect(values[bit_rev_index].isZero());
        }
    }
    try std.testing.expectEqual(n / step, ones);
}

test "air utils: invalid periodic parameters" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(
        Error.InvalidStep,
        genPeriodicIndicatorColumn(alloc, 4, 5, 0),
    );
    try std.testing.expectError(
        Error.PositionOutOfRange,
        circleBitReversedIndex(4, 16),
    );
}
