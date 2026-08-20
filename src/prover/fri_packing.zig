//! Packed secure-column geometry shared by FRI commitment and decommitment.

const std = @import("std");
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const secure_column = @import("secure_column.zig");

const M31 = m31.M31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const PACKED_LEAF_SIZE: usize = @as(usize, 1) << @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
const PACKED_COLUMN_COUNT: usize = PACKED_LEAF_SIZE * qm31.SECURE_EXTENSION_DEGREE;

pub const PackedSecureColumns = struct {
    columns: [PACKED_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        column: SecureColumnByCoords,
    ) !PackedSecureColumns {
        if (column.len() < PACKED_LEAF_SIZE or column.len() % PACKED_LEAF_SIZE != 0) {
            return error.InvalidColumnSize;
        }

        const packed_len = column.len() / PACKED_LEAF_SIZE;
        var result: PackedSecureColumns = undefined;
        var initialized: usize = 0;
        errdefer {
            for (result.columns[0..initialized]) |values| allocator.free(values);
        }
        while (initialized < result.columns.len) : (initialized += 1) {
            result.columns[initialized] = try allocator.alloc(M31, packed_len);
        }

        for (0..packed_len) |leaf| {
            inline for (0..PACKED_LEAF_SIZE) |offset| {
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    result.columns[
                        offset * qm31.SECURE_EXTENSION_DEGREE + coordinate
                    ][leaf] = column.columns[coordinate][leaf * PACKED_LEAF_SIZE + offset];
                }
            }
        }
        return result;
    }

    pub fn deinit(self: *PackedSecureColumns, allocator: std.mem.Allocator) void {
        for (self.columns) |values| allocator.free(values);
        self.* = undefined;
    }

    pub fn refs(self: *const PackedSecureColumns) [PACKED_COLUMN_COUNT][]const M31 {
        var result: [PACKED_COLUMN_COUNT][]const M31 = undefined;
        for (&result, self.columns) |*out, values| out.* = values;
        return result;
    }
};

pub fn shouldPack(column_len: usize, fold_step: u32) bool {
    return fold_step > 1 and
        column_len >= PACKED_LEAF_SIZE and
        std.math.isPowerOfTwo(column_len);
}

/// Maps sorted evaluation positions to the sorted, unique packed-leaf
/// positions consumed by the Merkle prover.
pub fn packedQueryPositions(
    allocator: std.mem.Allocator,
    evaluation_positions: []const usize,
) ![]usize {
    var positions = std.ArrayList(usize).empty;
    defer positions.deinit(allocator);

    var previous: ?usize = null;
    for (evaluation_positions) |evaluation_position| {
        const packed_position = evaluation_position >> @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
        if (previous == null or previous.? != packed_position) {
            try positions.append(allocator, packed_position);
            previous = packed_position;
        }
    }
    return positions.toOwnedSlice(allocator);
}
