//! Poseidon2 row materialization and scalar helper kernel.

pub fn Runtime(comptime context: anytype) type {
    return struct {
        const equation_kernel = @import("poseidon2_wide_equation_kernel.zig").Kernel(context);
        const std = context.std;
        const M31 = context.M31;
        const QM31 = context.QM31;
        const lookup_entry = context.lookup_entry;
        const WIDTH = context.WIDTH;
        const N_MAIN_COLUMNS = context.N_MAIN_COLUMNS;
        const N_CONSTRAINTS = context.N_CONSTRAINTS;
        const FIRST_FULL_ROUND_WIDTH = context.FIRST_FULL_ROUND_WIDTH;
        const MATERIALIZED_FULL_ROUND_WIDTH = context.MATERIALIZED_FULL_ROUND_WIDTH;
        const PARTIAL_ROUND_WIDTH = context.PARTIAL_ROUND_WIDTH;
        const constants = @import("poseidon2_constants.zig");

        /// Symbolic permutation for verifier arithmetic. Reuses this AIR's matrix
        /// operations and round constants; the native memory-hashing path is unchanged.
        pub const permuteGeneric = equation_kernel.permuteGeneric;

        pub fn fillFirstFullRound(
            row: *[N_MAIN_COLUMNS]M31,
            cursor: *usize,
            state: *[WIDTH]M31,
            round: [WIDTH]u32,
        ) void {
            var sboxed: [WIDTH]M31 = undefined;
            for (state, round, 0..) |value, constant, lane| {
                const x = value.add(M31.fromCanonical(constant));
                const x2 = x.square();
                const x4 = x2.square();
                row[cursor.* + 2 * lane] = x2;
                row[cursor.* + 2 * lane + 1] = x4;
                sboxed[lane] = x.mul(x4);
            }
            externalMatrixM31(&sboxed);
            state.* = sboxed;
            cursor.* += FIRST_FULL_ROUND_WIDTH;
        }

        pub fn fillMaterializedFullRound(
            row: *[N_MAIN_COLUMNS]M31,
            cursor: *usize,
            state: *[WIDTH]M31,
            round: [WIDTH]u32,
        ) void {
            for (state, round, 0..) |*value, constant, lane| {
                const x = value.add(M31.fromCanonical(constant));
                const x2 = x.square();
                const x4 = x2.square();
                row[cursor.* + 3 * lane] = x;
                row[cursor.* + 3 * lane + 1] = x2;
                row[cursor.* + 3 * lane + 2] = x4;
                value.* = x.mul(x4);
            }
            externalMatrixM31(state);
            cursor.* += MATERIALIZED_FULL_ROUND_WIDTH;
        }

        pub fn fillMaterializedPartialRound(
            row: *[N_MAIN_COLUMNS]M31,
            cursor: *usize,
            state: *[WIDTH]M31,
            round_constant: u32,
            diagonal: [WIDTH]u32,
        ) void {
            const x = state[0].add(M31.fromCanonical(round_constant));
            const x2 = x.square();
            const x4 = x2.square();
            row[cursor.*] = x;
            row[cursor.* + 1] = x2;
            row[cursor.* + 2] = x4;
            state[0] = x.mul(x4);
            internalMatrixM31(state, diagonal);
            cursor.* += PARTIAL_ROUND_WIDTH;
        }

        pub const evaluateFirstFullRound = equation_kernel.evaluateFirstFullRound;

        pub const evaluateMaterializedFullRound = equation_kernel.evaluateMaterializedFullRound;

        pub const evaluateMaterializedPartialRound = equation_kernel.evaluateMaterializedPartialRound;

        const matrix = @import("poseidon2_matrix.zig");
        pub const externalMatrixM31 = matrix.externalMatrixM31;
        pub const externalMatrixSecure = matrix.externalMatrixSecure;
        pub const m4M31 = matrix.m4M31;
        pub const m4Secure = matrix.m4Secure;
        pub const internalMatrixM31 = matrix.internalMatrixM31;
        pub const internalMatrixSecure = matrix.internalMatrixSecure;

        pub fn allocateColumns(allocator: std.mem.Allocator, comptime n: usize, len: usize) ![n][]M31 {
            var columns: [n][]M31 = undefined;
            var initialized: usize = 0;
            errdefer for (columns[0..initialized]) |column| allocator.free(column);
            for (&columns) |*column| {
                column.* = try allocator.alloc(M31, len);
                initialized += 1;
            }
            return columns;
        }

        pub fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
            for (columns) |column| allocator.free(column);
        }

        pub const baseSecure = equation_kernel.baseSecure;

        pub const append = equation_kernel.append;

        pub const appendGeneric = equation_kernel.appendGeneric;

        pub fn secureRow(row: [N_MAIN_COLUMNS]M31) [N_MAIN_COLUMNS]QM31 {
            var result: [N_MAIN_COLUMNS]QM31 = undefined;
            for (&result, row) |*dst, value| dst.* = QM31.fromBase(value);
            return result;
        }

        pub fn expectAllZero(values: []const QM31) !void {
            for (values) |value| try std.testing.expect(value.isZero());
        }
    };
}
