//! Exact resident-slot extent and alias checks shared by Cairo PCS binders.

const std = @import("std");
const column = @import("../../../backends/cuda/runtime/column.zig");
const quotient_stage = @import(
    "../../../backends/cuda/runtime/stages/quotient.zig",
);
const resident_plan = @import("resident_plan.zig");

pub const Words = column.DeviceSlice(u32);

pub fn exact(
    provider: anytype,
    plan: anytype,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !Words {
    const slot = plan.slot(kind, ordinal) orelse
        return error.InvalidKernelDescriptor;
    return exactWords(provider, plan, kind, ordinal, slot.words);
}

pub fn exactWords(
    provider: anytype,
    plan: anytype,
    kind: resident_plan.SlotKind,
    ordinal: u32,
    expected: usize,
) !Words {
    const descriptor = plan.slot(kind, ordinal) orelse
        return error.InvalidKernelDescriptor;
    if (descriptor.words != expected)
        return error.InvalidKernelDescriptor;
    const value = try provider.slot(descriptor.id);
    if (value.len != expected)
        return error.InvalidKernelDescriptor;
    return value;
}

pub fn coordinateStorage(
    coordinates: quotient_stage.CoordinateColumns,
) !Words {
    if (!contiguous(coordinates.c0, coordinates.c1) or
        !contiguous(coordinates.c1, coordinates.c2) or
        !contiguous(coordinates.c2, coordinates.c3))
    {
        return error.InvalidKernelDescriptor;
    }
    return .{
        .address = coordinates.c0.address,
        .len = try mul(coordinates.c0.len, 4),
        .owner = coordinates.c0.owner,
        .generation = coordinates.c0.generation,
    };
}

pub fn sameWords(left: Words, right: Words) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

fn contiguous(left: Words, right: Words) bool {
    const bytes = std.math.mul(
        usize,
        left.len,
        @sizeOf(u32),
    ) catch return false;
    const end = std.math.add(usize, left.address, bytes) catch
        return false;
    return end == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

pub fn pow2(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

pub fn add(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

pub fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}
