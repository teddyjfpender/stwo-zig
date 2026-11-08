//! FRI Merkle query materialization and packed-leaf ordering checks.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const LOG_PACKED_LEAF_SIZE = @import("config.zig").LOG_PACKED_LEAF_SIZE;

const M31 = m31.M31;

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        const folding = @import("folding.zig").ForField(Secure);
        const SparseEvaluation = folding.SparseEvaluation;
        pub const MerkleVerificationInputs = struct {
            positions: []usize,
            columns: [][]M31,

            pub fn deinit(self: *MerkleVerificationInputs, allocator: std.mem.Allocator) void {
                allocator.free(self.positions);
                for (self.columns) |column| allocator.free(column);
                allocator.free(self.columns);
                self.* = undefined;
            }
        };

        /// Converts reconstructed FRI evaluations into the leaf layout committed by
        /// STWO. With packed leaves, four consecutive QM31 values become one Merkle
        /// row with coordinates ordered by value first, then extension coordinate.
        pub fn build(
            allocator: std.mem.Allocator,
            decommitment_positions: []const usize,
            sparse: SparseEvaluation,
            leaf_log_size: u32,
        ) !MerkleVerificationInputs {
            if (leaf_log_size >= @bitSizeOf(usize)) return error.ShapeMismatch;
            const leaf_size: usize = @as(usize, 1) << @intCast(leaf_log_size);

            var value_count: usize = 0;
            for (sparse.subset_evals) |subset| value_count += subset.len;
            if (value_count != decommitment_positions.len or
                decommitment_positions.len % leaf_size != 0)
            {
                return error.ShapeMismatch;
            }

            const merkle_position_count = decommitment_positions.len / leaf_size;
            const positions = try allocator.alloc(usize, merkle_position_count);
            errdefer allocator.free(positions);

            var leaf_index: usize = 0;
            while (leaf_index < merkle_position_count) : (leaf_index += 1) {
                const first_index = leaf_index * leaf_size;
                const merkle_position = decommitment_positions[first_index] >> @intCast(leaf_log_size);
                positions[leaf_index] = merkle_position;
                var offset: usize = 0;
                while (offset < leaf_size) : (offset += 1) {
                    const position = decommitment_positions[first_index + offset];
                    if ((position >> @intCast(leaf_log_size)) != merkle_position or
                        (position & (leaf_size - 1)) != offset)
                    {
                        return error.ShapeMismatch;
                    }
                }
                if (leaf_index > 0 and positions[leaf_index - 1] >= merkle_position) {
                    return error.ShapeMismatch;
                }
            }

            const flattened_values = try allocator.alloc(QM31, value_count);
            defer allocator.free(flattened_values);
            var value_index: usize = 0;
            for (sparse.subset_evals) |subset| {
                @memcpy(flattened_values[value_index..][0..subset.len], subset);
                value_index += subset.len;
            }

            const column_count = DEGREE * leaf_size;
            const columns = try allocator.alloc([]M31, column_count);
            errdefer allocator.free(columns);
            var initialized_columns: usize = 0;
            errdefer {
                for (columns[0..initialized_columns]) |column| allocator.free(column);
            }
            while (initialized_columns < columns.len) : (initialized_columns += 1) {
                columns[initialized_columns] = try allocator.alloc(M31, merkle_position_count);
            }

            leaf_index = 0;
            while (leaf_index < merkle_position_count) : (leaf_index += 1) {
                var offset: usize = 0;
                while (offset < leaf_size) : (offset += 1) {
                    const coords = flattened_values[leaf_index * leaf_size + offset].toM31Array();
                    inline for (coords, 0..) |coord, coordinate| {
                        columns[offset * DEGREE + coordinate][leaf_index] = coord;
                    }
                }
            }

            return .{
                .positions = positions,
                .columns = columns,
            };
        }

        pub fn findSubsetIndex(
            decommitment_positions: []const usize,
            fold_width: usize,
            subset_start: usize,
        ) ?usize {
            if (fold_width == 0) return null;
            var index: usize = 0;
            while (index * fold_width < decommitment_positions.len) : (index += 1) {
                const at = index * fold_width;
                if (decommitment_positions[at] == subset_start) return index;
                if (decommitment_positions[at] > subset_start) return null;
            }
            return null;
        }

        pub fn findPosition(positions: []const usize, target: usize) ?usize {
            var left: usize = 0;
            var right: usize = positions.len;
            while (left < right) {
                const middle = left + (right - left) / 2;
                if (positions[middle] < target) {
                    left = middle + 1;
                } else {
                    right = middle;
                }
            }
            if (left < positions.len and positions[left] == target) return left;
            return null;
        }
    };
}
