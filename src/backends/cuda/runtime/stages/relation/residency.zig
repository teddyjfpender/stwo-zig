//! Resident address and pointer-table validation for relation plans.

const std = @import("std");
const column = @import("../../column.zig");
const layout = @import("../resident_layout.zig");
const runtime_error = @import("../../error.zig");

pub const DeviceIdentity = struct {
    owner: usize,
    generation: u64,

    pub fn from(slice: anytype) DeviceIdentity {
        return .{
            .owner = slice.owner,
            .generation = slice.generation,
        };
    }
};

pub fn checkedRange(
    comptime F: type,
    slice: column.DeviceSlice(F),
    minimum: usize,
    alignment: usize,
    identity: DeviceIdentity,
) runtime_error.Error!layout.DeviceRange {
    if (slice.address == 0 or slice.address % alignment != 0 or
        slice.len < minimum or slice.owner != identity.owner or
        slice.generation != identity.generation)
    {
        return error.InvalidDeviceAddress;
    }
    return layout.elementRange(slice.address, minimum, @sizeOf(F));
}

pub fn validatePointerTableAlignment(
    buffers: anytype,
) runtime_error.Error!void {
    const pointer_tables = [_]usize{
        buffers.source_tables.address,
        buffers.descriptors.address,
        buffers.output_tables.address,
        buffers.denominator_slabs.address,
        buffers.claimed_sums.address,
    };
    for (pointer_tables) |address| {
        if (address % @alignOf(usize) != 0)
            return error.InvalidDeviceAddress;
    }
}
