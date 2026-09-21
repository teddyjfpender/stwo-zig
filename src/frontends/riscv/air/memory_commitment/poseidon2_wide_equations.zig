//! Pinned wide Poseidon AIR equations and lookups; no witness allocation.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup_equations.zig");
const relations_mod = @import("../relation_challenges.zig");
const constants = @import("poseidon2_constants.zig");
const layout = @import("poseidon2_layout.zig");
pub const WIDTH = layout.WIDTH;
pub const N_TEMPORARIES = layout.N_TEMPORARIES;
pub const N_MAIN_COLUMNS = layout.N_MAIN_COLUMNS;
pub const N_MATERIALIZATION_CONSTRAINTS = layout.N_MATERIALIZATION_CONSTRAINTS;
pub const N_PERMUTATION_CONSTRAINTS = layout.N_PERMUTATION_CONSTRAINTS;
pub const N_FLAG_CONSTRAINTS = layout.N_FLAG_CONSTRAINTS;
pub const N_CONSTRAINTS = layout.N_CONSTRAINTS;
pub const N_SUMS = layout.N_SUMS;
pub const N_INTERACTION_COLUMNS = layout.N_INTERACTION_COLUMNS;
pub const MAXIMUM_CONSTRAINT_DEGREE = layout.MAXIMUM_CONSTRAINT_DEGREE;
pub const INPUT_START = layout.INPUT_START;
pub const TEMP_START = layout.TEMP_START;
pub const WIDE_COLUMN = layout.WIDE_COLUMN;
pub const IO_COLUMN = layout.IO_COLUMN;
pub const FIRST_FULL_ROUND_WIDTH = layout.FIRST_FULL_ROUND_WIDTH;
pub const MATERIALIZED_FULL_ROUND_WIDTH = layout.MATERIALIZED_FULL_ROUND_WIDTH;
pub const PARTIAL_ROUND_WIDTH = layout.PARTIAL_ROUND_WIDTH;
pub const OUTPUT_START = layout.OUTPUT_START;
// The shared universal provider omits the separate memory activity shell.
pub const BINDS_ACTIVE_SELECTOR = false;
const kernel = @import("poseidon2_wide_equation_kernel.zig").Kernel(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .lookup_entry = lookup_entry,
    .WIDTH = WIDTH,
    .N_MAIN_COLUMNS = N_MAIN_COLUMNS,
    .N_CONSTRAINTS = N_CONSTRAINTS,
    .FIRST_FULL_ROUND_WIDTH = FIRST_FULL_ROUND_WIDTH,
    .MATERIALIZED_FULL_ROUND_WIDTH = MATERIALIZED_FULL_ROUND_WIDTH,
    .PARTIAL_ROUND_WIDTH = PARTIAL_ROUND_WIDTH,
});
const externalMatrixSecure = @import("poseidon2_matrix.zig").externalMatrixSecure;
const evaluateFirstFullRound = kernel.evaluateFirstFullRound;
const evaluateMaterializedFullRound = kernel.evaluateMaterializedFullRound;
const evaluateMaterializedPartialRound = kernel.evaluateMaterializedPartialRound;
const appendGeneric = kernel.appendGeneric;

pub fn output(row: [N_MAIN_COLUMNS]M31) [WIDTH]M31 {
    return row[OUTPUT_START..][0..WIDTH].*;
}

pub fn evaluate(main: [N_MAIN_COLUMNS]QM31) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(QM31, main);
}

pub fn evaluateGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [N_CONSTRAINTS]S {
    const enabler = main[0];
    var state = main[INPUT_START..][0..WIDTH].*;
    externalMatrixSecure(S, &state);
    var result: [N_CONSTRAINTS]S = undefined;
    var constraint: usize = 1;
    var cursor: usize = TEMP_START;
    const one = S.one();
    result[0] = enabler.mul(one.sub(enabler));

    evaluateFirstFullRound(
        S,
        main,
        &cursor,
        &state,
        constants.EXTERNAL_ROUND[0],
        enabler,
        &result,
        &constraint,
    );
    for (constants.EXTERNAL_ROUND[1..4]) |round| {
        evaluateMaterializedFullRound(
            S,
            main,
            &cursor,
            &state,
            round,
            enabler,
            &result,
            &constraint,
        );
    }
    for (constants.INTERNAL_ROUND) |round_constant| {
        evaluateMaterializedPartialRound(
            S,
            main,
            &cursor,
            &state,
            round_constant,
            constants.INTERNAL_MATRIX,
            enabler,
            &result,
            &constraint,
        );
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| {
        evaluateMaterializedFullRound(
            S,
            main,
            &cursor,
            &state,
            round,
            enabler,
            &result,
            &constraint,
        );
    }
    for (state, 0..) |expected, lane| {
        const actual = main[cursor + lane];
        result[constraint] = enabler.mul(actual.sub(expected));
        constraint += 1;
    }
    cursor += WIDTH;
    std.debug.assert(cursor == WIDE_COLUMN);
    std.debug.assert(constraint == N_PERMUTATION_CONSTRAINTS);

    const wide = main[WIDE_COLUMN];
    const io = main[IO_COLUMN];
    result[constraint] = wide.mul(one.sub(wide));
    result[constraint + 1] = io.mul(one.sub(io));
    result[constraint + 2] = wide.mul(io);
    return result;
}

pub fn narrowModeConstraints(main: [N_MAIN_COLUMNS]QM31) [2]QM31 {
    return narrowModeConstraintsGeneric(QM31, main);
}

pub fn narrowModeConstraintsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [2]S {
    return .{ main[WIDE_COLUMN], main[IO_COLUMN] };
}

pub fn interactionConstraints(
    main: [N_MAIN_COLUMNS]QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_SUMS]QM31 {
    return interactionConstraintsGeneric(QM31, main, is_first, sums, previous, claims, relations);
}

pub fn interactionConstraintsGeneric(
    comptime S: type,
    main: [N_MAIN_COLUMNS]S,
    is_first: S,
    sums: [N_SUMS]S,
    previous: [N_SUMS]S,
    claims: [N_SUMS]S,
    relations: anytype,
) [N_SUMS]S {
    const pairs = rowPairsGeneric(S, main, relations);
    var result: [N_SUMS]S = undefined;
    for (&result, 0..) |*value, index| {
        value.* = logup.pairConstraintGeneric(
            S,
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    return result;
}

pub fn rowPairs(main: [N_MAIN_COLUMNS]QM31, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    return rowPairsGeneric(QM31, main, relations);
}

pub fn rowPairsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, relations: anytype) [N_SUMS]logup.RowPairFor(S) {
    const list = entriesGeneric(S, main);
    return .{
        list.pairWith(0, relations) catch unreachable,
        list.pairWith(1, relations) catch unreachable,
    };
}

pub fn entries(main: [N_MAIN_COLUMNS]QM31) lookup_entry.List {
    return entriesGeneric(QM31, main);
}

pub fn entriesGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) lookup_entry.Builder(S).List {
    const EntryBuilder = lookup_entry.Builder(S);
    const enabler = main[0];
    const wide = main[WIDE_COLUMN];
    const io = main[IO_COLUMN];
    const one = S.one();
    const input = main[INPUT_START..][0..WIDTH].*;
    const out = main[OUTPUT_START..][0..WIDTH].*;
    var narrow = [_]S{S.zero()} ** WIDTH;
    narrow[0] = out[0];
    var wide_output = [_]S{S.zero()} ** WIDTH;
    @memcpy(wide_output[0..8], out[0..8]);
    var io_tuple: [2 * WIDTH]S = undefined;
    @memcpy(io_tuple[0..WIDTH], &input);
    @memcpy(io_tuple[WIDTH..], &out);
    var list = EntryBuilder.List{};
    appendGeneric(S, &list, .poseidon2, enabler.mul(one.sub(io)).neg(), input);
    appendGeneric(S, &list, .poseidon2, enabler.mul(one.sub(wide).sub(io)), narrow);
    appendGeneric(S, &list, .poseidon2, enabler.mul(wide), wide_output);
    appendGeneric(S, &list, .poseidon2_io, enabler.mul(io), io_tuple);
    return list;
}

pub fn paddingPairs() [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}
