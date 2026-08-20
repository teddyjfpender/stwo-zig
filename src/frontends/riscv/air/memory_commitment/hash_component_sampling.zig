//! Circle-domain sampling and secure-column helpers for hash components.

pub fn Namespace(comptime context: anytype) type {
    return struct {
        const std = context.std;
        const M31 = context.M31;
        const QM31 = context.QM31;
        const CirclePointQM31 = context.CirclePointQM31;

        pub fn currentPointColumns(
            allocator: std.mem.Allocator,
            count: usize,
            point: CirclePointQM31,
        ) ![][]CirclePointQM31 {
            const result = try allocator.alloc([]CirclePointQM31, count);
            var initialized: usize = 0;
            errdefer {
                for (result[0..initialized]) |column| allocator.free(column);
                allocator.free(result);
            }
            for (result) |*column| {
                column.* = try allocator.dupe(CirclePointQM31, &.{point});
                initialized += 1;
            }
            return result;
        }

        pub fn currentAndPreviousPointColumns(
            allocator: std.mem.Allocator,
            count: usize,
            point: CirclePointQM31,
            previous: CirclePointQM31,
        ) ![][]CirclePointQM31 {
            const result = try allocator.alloc([]CirclePointQM31, count);
            var initialized: usize = 0;
            errdefer {
                for (result[0..initialized]) |column| allocator.free(column);
                allocator.free(result);
            }
            for (result) |*column| {
                column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
                initialized += 1;
            }
            return result;
        }

        pub fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
            for (columns) |column| allocator.free(column);
            allocator.free(columns);
        }

        pub fn sampleMain(
            comptime n: usize,
            columns: [][]QM31,
            offset: usize,
        ) ![n]QM31 {
            if (columns.len < offset + n) return error.InvalidProofShape;
            var result: [n]QM31 = undefined;
            for (&result, columns[offset..][0..n]) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            return result;
        }

        pub fn sampleInteraction(
            comptime n: usize,
            columns: [][]QM31,
            offset: usize,
            sums: *[n]QM31,
            previous: *[n]QM31,
        ) !void {
            for (0..n) |index| {
                sums[index] = try sampledSecure(columns, offset + 4 * index, 0);
                previous[index] = try sampledSecure(columns, offset + 4 * index, 1);
            }
        }

        pub fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
            var coordinates: [4]QM31 = undefined;
            for (&coordinates, 0..) |*value, index| {
                if (columns[offset + index].len <= point) return error.InvalidProofShape;
                value.* = columns[offset + index][point];
            }
            return QM31.fromPartialEvals(coordinates);
        }

        pub fn readMain(comptime n: usize, columns: []const []const M31, row: usize) [n]QM31 {
            var result: [n]QM31 = undefined;
            for (&result, columns) |*value, column| value.* = QM31.fromBase(column[row]);
            return result;
        }

        pub fn readInteraction(
            comptime n: usize,
            evaluations: []const []const M31,
            interaction_start: usize,
            row: usize,
            previous_row: usize,
            sums: *[n]QM31,
            previous: *[n]QM31,
        ) void {
            for (0..n) |index| {
                sums[index] = secureAt(evaluations[interaction_start + 4 * index ..][0..4], row);
                previous[index] = secureAt(
                    evaluations[interaction_start + 4 * index ..][0..4],
                    previous_row,
                );
            }
        }

        pub fn secureAt(columns: []const []const M31, row: usize) QM31 {
            return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
        }

        pub fn combineConstraints(powers: []const QM31, constraints: []const QM31) QM31 {
            var result = QM31.zero();
            for (constraints, 0..) |constraint, index| {
                result = result.add(powers[powers.len - 1 - index].mul(constraint));
            }
            return result;
        }
    };
}
