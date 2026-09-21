//! Executable compact-Poseidon specialization for native and recursive verification.
//! Admission authenticates these exact polynomials against the physical AIR lowered
//! from `typed_poseidon2` by `typed_poseidon2_compact`; this is not an independent
//! semantic authority. Witness allocation and scheduling remain outside this owner.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entries = @import("../lookups/entry.zig");
const logup = @import("../logup_equations.zig");

const layout = @import("poseidon2_universal_layout_v1.zig");
pub const SCHEMA_VERSION = layout.SCHEMA_VERSION;
pub const STABLE_NAME = layout.STABLE_NAME;
pub const WIDTH = layout.WIDTH;
pub const N_SBOXES = layout.N_SBOXES;
pub const N_MAIN_COLUMNS = layout.N_MAIN_COLUMNS;
pub const WIDE_COLUMN = layout.WIDE_COLUMN;
pub const IO_COLUMN = layout.IO_COLUMN;
pub const BINDS_ACTIVE_SELECTOR = layout.BINDS_ACTIVE_SELECTOR;
pub const N_CONSTRAINTS = layout.N_CONSTRAINTS;
pub const N_SUMS = layout.N_SUMS;
pub const N_INTERACTION_COLUMNS = layout.N_INTERACTION_COLUMNS;
pub const MAX_CONSTRAINT_DEGREE = layout.MAX_CONSTRAINT_DEGREE;
pub const Row = layout.Row;

pub fn evaluateGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [N_CONSTRAINTS]S {
    var constraints: [N_CONSTRAINTS]S = undefined;
    constraints[0] = main[0].mul(S.one().sub(main[0]));
    constraints[1] = main[WIDE_COLUMN].mul(S.one().sub(main[WIDE_COLUMN]));
    constraints[2] = main[IO_COLUMN].mul(S.one().sub(main[IO_COLUMN]));
    constraints[3] = main[WIDE_COLUMN].mul(main[IO_COLUMN]);
    var state = main[1..17].*;
    var context = Evaluate(S){ .main = main, .constraints = &constraints };
    walk(S, &state, &context);
    std.debug.assert(context.cursor == WIDE_COLUMN and context.constraint == N_CONSTRAINTS);
    return constraints;
}

pub fn outputGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [WIDTH]S {
    var state: [WIDTH]S = undefined;
    const last_round = WIDE_COLUMN - 2 * WIDTH;
    for (&state, 0..) |*value, lane| value.* = main[last_round + 2 * lane + 1];
    external(S, &state);
    return state;
}

/// Reads only the final S-box outputs needed by the linear output matrix.
/// Columns are the actual committed witness, never cached host outputs.
pub fn outputFromColumns(comptime S: type, columns: anytype, row: usize) [WIDTH]S {
    var state: [WIDTH]S = undefined;
    const last_round = WIDE_COLUMN - 2 * WIDTH;
    for (&state, 0..) |*value, lane| value.* = lift(S, columns[last_round + 2 * lane + 1][row]);
    external(S, &state);
    return state;
}

pub fn entriesFromColumns(comptime S: type, columns: anytype, row: usize) entries.Builder(S).List {
    var input: [WIDTH]S = undefined;
    for (&input, 0..) |*word, lane| word.* = lift(S, columns[1 + lane][row]);
    return entriesForIo(S, lift(S, columns[0][row]), lift(S, columns[WIDE_COLUMN][row]), lift(S, columns[IO_COLUMN][row]), input, outputFromColumns(S, columns, row));
}

fn lift(comptime S: type, value: M31) S {
    return if (S == M31) value else S.fromBase(value);
}

/// Preserve the exact four relation entries and two-claim layout in every mode.
pub fn entriesGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) entries.Builder(S).List {
    return entriesForIo(S, main[0], main[WIDE_COLUMN], main[IO_COLUMN], main[1..17].*, outputGeneric(S, main));
}

fn entriesForIo(comptime S: type, enabler: S, wide_flag: S, io_flag: S, input: [WIDTH]S, output: [WIDTH]S) entries.Builder(S).List {
    var narrow = [_]S{S.zero()} ** WIDTH;
    narrow[0] = output[0];
    var wide = [_]S{S.zero()} ** WIDTH;
    @memcpy(wide[0..8], output[0..8]);
    var io: [2 * WIDTH]S = undefined;
    @memcpy(io[0..WIDTH], &input);
    @memcpy(io[WIDTH..], &output);
    var list = entries.Builder(S).List{};
    append(S, &list, .poseidon2, enabler.mul(S.one().sub(io_flag)).neg(), input);
    append(S, &list, .poseidon2, enabler.mul(S.one().sub(wide_flag).sub(io_flag)), narrow);
    append(S, &list, .poseidon2, enabler.mul(wide_flag), wide);
    append(S, &list, .poseidon2_io, enabler.mul(io_flag), io);
    return list;
}

pub fn rowPairsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, relations: anytype) [N_SUMS]logup.RowPairFor(S) {
    var list = entriesGeneric(S, main);
    return .{ list.pairWith(0, relations) catch unreachable, list.pairWith(1, relations) catch unreachable };
}

pub fn interactionConstraintsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, is_first: S, sums: [N_SUMS]S, previous: [N_SUMS]S, claims: [N_SUMS]S, relations: anytype) [N_SUMS]S {
    const pairs = rowPairsGeneric(S, main, relations);
    var result: [N_SUMS]S = undefined;
    for (&result, 0..) |*value, index| value.* = logup.pairConstraintGeneric(S, sums[index], previous[index], is_first, claims[index], pairs[index]);
    return result;
}

const walk = @import("poseidon2_degree3_schedule.zig").walk;
const external = @import("poseidon2_degree3_schedule.zig").external;

fn Evaluate(comptime S: type) type {
    return struct {
        main: [N_MAIN_COLUMNS]S,
        constraints: *[N_CONSTRAINTS]S,
        cursor: usize = 17,
        constraint: usize = 4,
        pub fn sbox(self: *@This(), x: S) S {
            const square = self.main[self.cursor];
            const fifth = self.main[self.cursor + 1];
            self.constraints[self.constraint] = square.sub(x.square());
            self.constraints[self.constraint + 1] = fifth.sub(x.mul(square.square()));
            self.cursor += 2;
            self.constraint += 2;
            return fifth;
        }
    };
}

fn append(comptime S: type, list: *entries.Builder(S).List, domain: entries.Domain, numerator: S, tuple: anytype) void {
    var entry = entries.Builder(S).Entry{ .domain = domain, .numerator = numerator, .arity = tuple.len };
    inline for (tuple, 0..) |value, index| entry.values[index] = value;
    list.append(entry);
}

comptime {
    if (N_SBOXES != 142 or N_MAIN_COLUMNS != 303 or N_CONSTRAINTS != 288)
        @compileError("Versioned recursive universal degree-three Poseidon geometry changed");
}
