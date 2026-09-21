//! Scalar wide-Poseidon equations, independent of witness materialization.
pub fn Kernel(comptime context: anytype) type {
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
        const constants = @import("poseidon2_constants.zig");

        const matrix = @import("poseidon2_matrix.zig");
        const externalMatrixSecure = matrix.externalMatrixSecure;
        const internalMatrixSecure = matrix.internalMatrixSecure;
        pub fn permuteGeneric(comptime S: type, state: *[WIDTH]S) void {
            externalMatrixSecure(S, state);
            for (constants.EXTERNAL_ROUND[0..4]) |round| fullRoundGeneric(S, state, round);
            for (constants.INTERNAL_ROUND) |round_constant| {
                const value = state[0].add(S.fromBase(M31.fromCanonical(round_constant)));
                state[0] = value.square().square().mul(value);
                internalMatrixSecure(S, state, constants.INTERNAL_MATRIX);
            }
            for (constants.EXTERNAL_ROUND[4..8]) |round| fullRoundGeneric(S, state, round);
        }

        fn fullRoundGeneric(comptime S: type, state: *[WIDTH]S, round: [WIDTH]u32) void {
            for (state, round) |*value, constant| {
                const shifted = value.add(S.fromBase(M31.fromCanonical(constant)));
                value.* = shifted.square().square().mul(shifted);
            }
            externalMatrixSecure(S, state);
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
    };
}
