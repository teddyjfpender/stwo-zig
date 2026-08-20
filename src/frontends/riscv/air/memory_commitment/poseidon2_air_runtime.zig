//! Poseidon2 row materialization and scalar helper kernel.

pub fn Runtime(comptime context: anytype) type {
    return struct {
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

        pub fn evaluateFirstFullRound(
            comptime S: type,
            main: [N_MAIN_COLUMNS]S,
            cursor: *usize,
            state: *[WIDTH]S,
            round: [WIDTH]u32,
            enabler: S,
            result: *[N_CONSTRAINTS]S,
            constraint: *usize,
        ) void {
            var sboxed: [WIDTH]S = undefined;
            for (state, round, 0..) |value, constant, lane| {
                const x = value.add(baseSecure(S, constant));
                const x2 = main[cursor.* + 2 * lane];
                const x4 = main[cursor.* + 2 * lane + 1];
                result[constraint.*] = enabler.mul(x2.sub(x.square()));
                constraint.* += 1;
                result[constraint.*] = enabler.mul(x4.sub(x2.square()));
                constraint.* += 1;
                sboxed[lane] = x.mul(x4);
            }
            externalMatrixSecure(S, &sboxed);
            state.* = sboxed;
            cursor.* += FIRST_FULL_ROUND_WIDTH;
        }

        pub fn evaluateMaterializedFullRound(
            comptime S: type,
            main: [N_MAIN_COLUMNS]S,
            cursor: *usize,
            state: *[WIDTH]S,
            round: [WIDTH]u32,
            enabler: S,
            result: *[N_CONSTRAINTS]S,
            constraint: *usize,
        ) void {
            for (state, round, 0..) |*value, constant, lane| {
                const x = main[cursor.* + 3 * lane];
                const x2 = main[cursor.* + 3 * lane + 1];
                const x4 = main[cursor.* + 3 * lane + 2];
                result[constraint.*] = enabler.mul(x.sub(value.add(baseSecure(S, constant))));
                constraint.* += 1;
                result[constraint.*] = enabler.mul(x2.sub(x.square()));
                constraint.* += 1;
                result[constraint.*] = enabler.mul(x4.sub(x2.square()));
                constraint.* += 1;
                value.* = x.mul(x4);
            }
            externalMatrixSecure(S, state);
            cursor.* += MATERIALIZED_FULL_ROUND_WIDTH;
        }

        pub fn evaluateMaterializedPartialRound(
            comptime S: type,
            main: [N_MAIN_COLUMNS]S,
            cursor: *usize,
            state: *[WIDTH]S,
            round_constant: u32,
            diagonal: [WIDTH]u32,
            enabler: S,
            result: *[N_CONSTRAINTS]S,
            constraint: *usize,
        ) void {
            const x = main[cursor.*];
            const x2 = main[cursor.* + 1];
            const x4 = main[cursor.* + 2];
            result[constraint.*] = enabler.mul(x.sub(state[0].add(baseSecure(S, round_constant))));
            constraint.* += 1;
            result[constraint.*] = enabler.mul(x2.sub(x.square()));
            constraint.* += 1;
            result[constraint.*] = enabler.mul(x4.sub(x2.square()));
            constraint.* += 1;
            state[0] = x.mul(x4);
            internalMatrixSecure(S, state, diagonal);
            cursor.* += PARTIAL_ROUND_WIDTH;
        }

        pub fn externalMatrixM31(state: *[WIDTH]M31) void {
            for (0..4) |block| {
                const start = 4 * block;
                const mixed = m4M31(state[start..][0..4].*);
                @memcpy(state[start..][0..4], &mixed);
            }
            for (0..4) |lane| {
                const sum = state[lane].add(state[lane + 4]).add(state[lane + 8]).add(state[lane + 12]);
                for (0..4) |block| {
                    const index = 4 * block + lane;
                    state[index] = state[index].add(sum);
                }
            }
        }

        pub fn externalMatrixSecure(comptime S: type, state: *[WIDTH]S) void {
            for (0..4) |block| {
                const start = 4 * block;
                const mixed = m4Secure(S, state[start..][0..4].*);
                @memcpy(state[start..][0..4], &mixed);
            }
            for (0..4) |lane| {
                const sum = state[lane].add(state[lane + 4]).add(state[lane + 8]).add(state[lane + 12]);
                for (0..4) |block| {
                    const index = 4 * block + lane;
                    state[index] = state[index].add(sum);
                }
            }
        }

        pub fn m4M31(input: [4]M31) [4]M31 {
            const t0 = input[0].add(input[1]);
            const t1 = input[2].add(input[3]);
            const t2 = input[1].add(input[1]).add(t1);
            const t3 = input[3].add(input[3]).add(t0);
            const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
            const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
            return .{ t3.add(t5), t5, t2.add(t4), t4 };
        }

        pub fn m4Secure(comptime S: type, input: [4]S) [4]S {
            const t0 = input[0].add(input[1]);
            const t1 = input[2].add(input[3]);
            const t2 = input[1].add(input[1]).add(t1);
            const t3 = input[3].add(input[3]).add(t0);
            const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
            const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
            return .{ t3.add(t5), t5, t2.add(t4), t4 };
        }

        pub fn internalMatrixM31(state: *[WIDTH]M31, diagonal: [WIDTH]u32) void {
            var sum = M31.zero();
            for (state) |value| sum = sum.add(value);
            for (state, diagonal) |*value, coefficient| {
                value.* = value.mul(M31.fromCanonical(coefficient)).add(sum);
            }
        }

        pub fn internalMatrixSecure(comptime S: type, state: *[WIDTH]S, diagonal: [WIDTH]u32) void {
            var sum = S.zero();
            for (state) |value| sum = sum.add(value);
            for (state, diagonal) |*value, coefficient| {
                value.* = if (S == QM31)
                    value.mulM31(M31.fromCanonical(coefficient)).add(sum)
                else
                    value.mul(S.fromBase(M31.fromCanonical(coefficient))).add(sum);
            }
        }

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

        pub fn baseSecure(comptime S: type, value: u32) S {
            return S.fromBase(M31.fromCanonical(value));
        }

        pub fn append(list: *lookup_entry.List, domain: lookup_entry.Domain, numerator: QM31, values: anytype) void {
            return appendGeneric(QM31, list, domain, numerator, values);
        }

        pub fn appendGeneric(comptime S: type, list: *lookup_entry.Builder(S).List, domain: lookup_entry.Domain, numerator: S, values: anytype) void {
            var item = lookup_entry.Builder(S).Entry{ .domain = domain, .numerator = numerator, .arity = values.len };
            inline for (values, 0..) |value, index| item.values[index] = value;
            list.append(item);
        }

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
