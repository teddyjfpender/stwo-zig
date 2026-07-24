//! Shared checked layouts for contiguous resident proof data.

const std = @import("std");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");

pub const DeviceRange = struct {
    start: usize,
    end: usize,
};

pub fn Resident(comptime F: type) type {
    return struct {
        pointer: [*]F,
        range: DeviceRange,
    };
}

pub const WordMatrix = struct {
    pointer: [*]u32,
    stride_words: usize,
    column_count: u32,
    range: DeviceRange,
};

pub fn resident(
    session: anytype,
    comptime F: type,
    slice: anytype,
    minimum_elements: usize,
) runtime_error.Error!Resident(F) {
    return .{
        .pointer = try session.context.deviceSlicePointer(
            F,
            slice,
            minimum_elements,
        ),
        .range = try elementRange(
            slice.address,
            minimum_elements,
            @sizeOf(F),
        ),
    };
}

pub fn wordMatrix(
    session: anytype,
    descriptor: common.WordMatrix,
    minimum_words_per_column: usize,
) runtime_error.Error!WordMatrix {
    if (descriptor.column_stride_words < minimum_words_per_column or
        descriptor.storage.len == 0 or
        descriptor.storage.len % descriptor.column_stride_words != 0)
    {
        return error.InvalidKernelDescriptor;
    }
    const column_count_usize =
        descriptor.storage.len / descriptor.column_stride_words;
    const column_count = try common.count(column_count_usize);
    if (column_count == 0) return error.InvalidKernelDescriptor;
    const final_offset = std.math.mul(
        usize,
        column_count_usize - 1,
        descriptor.column_stride_words,
    ) catch return error.SizeOverflow;
    const required_words = std.math.add(
        usize,
        final_offset,
        minimum_words_per_column,
    ) catch return error.SizeOverflow;
    const values = try resident(
        session,
        u32,
        descriptor.storage,
        required_words,
    );
    return .{
        .pointer = values.pointer,
        .stride_words = descriptor.column_stride_words,
        .column_count = column_count,
        .range = values.range,
    };
}

pub fn elementRange(
    address: usize,
    count: usize,
    element_size: usize,
) runtime_error.Error!DeviceRange {
    if (count == 0 or element_size == 0)
        return error.InvalidKernelDescriptor;
    const bytes = std.math.mul(usize, count, element_size) catch
        return error.SizeOverflow;
    return .{
        .start = address,
        .end = std.math.add(usize, address, bytes) catch
            return error.SizeOverflow,
    };
}

pub fn overlap(left: DeviceRange, right: DeviceRange) bool {
    return left.start < right.end and right.start < left.end;
}

pub fn requireDisjoint(
    writes: []const DeviceRange,
    reads: []const DeviceRange,
) runtime_error.Error!void {
    for (writes, 0..) |write, index| {
        for (writes[index + 1 ..]) |other_write| {
            if (overlap(write, other_write))
                return error.OverlappingDeviceRange;
        }
        for (reads) |read| {
            if (overlap(write, read))
                return error.OverlappingDeviceRange;
        }
    }
}
