//! Fail-atomic destination and opening alias admission, before any row writes.

const Root = @import("fri_merkle_anchor_witness.zig");
const std = @import("std");
const direct = @import("stwo_riscv_air_lang").direct_witness_executor;
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const MAIN_COLUMN_COUNT = Root.MAIN_COLUMN_COUNT;
const OpeningWitness = Root.OpeningWitness;
const OpeningSet = Root.OpeningSet;
const Executor = Root.Executor;
const Row = Root.Row;
const Preprocessed = Root.Preprocessed;

const AddressRange = struct {
    start: usize,
    end: usize,
    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn preflightMain(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    witness: OpeningWitness,
    executor: *const Executor,
) direct.Error!usize {
    if (preprocessing.log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    var destinations: [MAIN_COLUMN_COUNT]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = try sliceRange(M31, column);
        for (destinations[0..index]) |previous| if (destinations[index].overlaps(previous))
            return error.AliasedDestination;
    }
    const objects = [_]AddressRange{
        try objectRange(columns),
        try objectRange(preprocessing),
        try objectRange(executor),
    };
    const rows = try sliceRange(Row, preprocessing.rows);
    for (destinations) |destination| {
        for (objects) |object| if (destination.overlaps(object)) return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
        switch (witness) {
            .segment_leaf => |opening| try rejectOpeningAlias(destination, opening),
            .binary_node => |opening| {
                try rejectOpeningAlias(destination, opening.left);
                try rejectOpeningAlias(destination, opening.right);
            },
            .empty_leaf => {},
        }
    }
    return size;
}

pub fn rejectOpeningAlias(destination: AddressRange, opening: OpeningSet) direct.Error!void {
    if (destination.overlaps(try sliceRange(M31, opening.raw_queries)))
        return error.AliasedInput;
    for (opening.layers) |layer| if (destination.overlaps(try sliceRange(M31, layer.values)))
        return error.AliasedInput;
}

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{ .start = start, .end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow };
}

pub fn objectRange(value: anytype) direct.Error!AddressRange {
    const T = @TypeOf(value.*);
    const start = @intFromPtr(value);
    return .{ .start = start, .end = std.math.add(usize, start, @sizeOf(T)) catch
        return error.AddressOverflow };
}
