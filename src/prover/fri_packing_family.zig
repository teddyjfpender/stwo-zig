//! Packed secure-column geometry shared by FRI commitment and decommitment.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;

const M31 = m31.M31;
pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        const core_fri = @import("stwo_core").fri.ForField(Secure);
        const secure_column = struct {
            pub const SecureColumnByCoords = @import("secure_column.zig").SecureColumnByCoordsFor(Secure);
        };
        const SecureColumnByCoords = secure_column.SecureColumnByCoords;
        const PACKED_LEAF_SIZE: usize = @as(usize, 1) << @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
        const PACKED_COLUMN_COUNT: usize = PACKED_LEAF_SIZE * DEGREE;

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

                const Context = struct {
                    source: SecureColumnByCoords,
                    target: *PackedSecureColumns,
                    pub fn runRange(self: *@This(), _: usize, start: usize, end: usize) void {
                        for (start..end) |leaf| inline for (0..PACKED_LEAF_SIZE) |offset| inline for (0..DEGREE) |coordinate| {
                            self.target.columns[offset * DEGREE + coordinate][leaf] = self.source.columns[coordinate][leaf * PACKED_LEAF_SIZE + offset];
                        };
                    }
                };
                var context = Context{ .source = column, .target = &result };
                if (comptime Secure == @import("stwo_core").fields.om31.OM31) {
                    _ = @import("lookups/row_work.zig").forEachRange(packed_len, &context, .{});
                } else context.runRange(0, 0, packed_len);
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
    };
}
