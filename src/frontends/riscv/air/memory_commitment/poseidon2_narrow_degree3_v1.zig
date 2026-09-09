//! Ethereum-only narrow Poseidon2 layout. Every row, including padding,
//! satisfies the permutation. Only lookup multiplicities use the enabler.
//! Each S-box stores x² and x⁵: y=x², z=x*y², with maximum degree three.
//! The existing Stark-V wide/IO layout and all default dispatch are unchanged.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constants = @import("poseidon2_constants.zig");
const legacy = @import("poseidon2_air.zig");
const entries = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");

pub const SCHEMA_VERSION: u16 = 1;
pub const STABLE_NAME = "stwo.ethereum.poseidon2-narrow-degree3.v1";
pub const WIDTH: usize = 16;
pub const N_SBOXES = WIDTH * constants.EXTERNAL_ROUND.len + constants.INTERNAL_ROUND.len;
pub const N_MAIN_COLUMNS = 3 + 2 * N_SBOXES;
pub const N_CONSTRAINTS = 2 + 2 * N_SBOXES;
pub const N_SUMS: usize = legacy.N_SUMS;
pub const N_INTERACTION_COLUMNS: usize = legacy.N_INTERACTION_COLUMNS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;
pub const Row = [N_MAIN_COLUMNS]M31;

pub fn fill(call: legacy.Call) !Row {
    if (call.wide or call.io) return error.UnsupportedPoseidonNarrowModeV1;
    for (call.input, 0..) |word, lane| {
        if (word >= @import("stwo_core").fields.m31.Modulus or (lane >= 2 and word != 0))
            return error.InvalidPoseidonNarrowInputV1;
    }
    var row: Row = undefined;
    row[0] = M31.one();
    row[1] = M31.fromCanonical(call.input[0]);
    row[2] = M31.fromCanonical(call.input[1]);
    var state = initialState(M31, row[1], row[2]);
    var context = Fill{ .row = &row };
    walk(M31, &state, &context);
    std.debug.assert(context.cursor == N_MAIN_COLUMNS);
    if (call.narrow_output) |expected| {
        if (state[0].toU32() != expected) return error.PoseidonNarrowOutputMismatchV1;
    }
    return row;
}

/// Padding remains a valid permutation, with zero lookup multiplicity.
/// Column writers can broadcast this one row rather than recompute padding.
pub fn paddingRow() Row {
    var row = fill(legacy.Call.narrow(0, 0)) catch unreachable;
    row[0] = M31.zero();
    return row;
}

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,
    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        for (self.values) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateMain(allocator: std.mem.Allocator, calls: []const legacy.Call, log_size: u32) !Columns {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log_size);
    var columns: Columns = undefined;
    var initialized: usize = 0;
    errdefer for (columns.values[0..initialized]) |column| allocator.free(column);
    for (&columns.values) |*column| {
        column.* = try allocator.alloc(M31, size);
        initialized += 1;
    }
    try generateMainInto(allocator, &columns.values, calls, log_size);
    return columns;
}

pub fn generateMainInto(allocator: std.mem.Allocator, columns: *[N_MAIN_COLUMNS][]M31, calls: []const legacy.Call, log_size: u32) !void {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    const padding = paddingRow();
    for (columns, padding) |column, value| {
        if (column.len != size) return error.InvalidTraceShape;
        @memset(column, value);
    }
    const placement = try @import("../../infra_trace.zig").BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (calls, 0..) |call, logical_row| {
        const row = try fill(call);
        for (columns, row) |column, value| column[placement.mapping[logical_row]] = value;
    }
}

pub fn evaluateGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, is_active: S) [N_CONSTRAINTS]S {
    var constraints: [N_CONSTRAINTS]S = undefined;
    constraints[0] = main[0].sub(is_active);
    constraints[1] = main[0].mul(S.one().sub(main[0]));
    var state = initialState(S, main[1], main[2]);
    var context = Evaluate(S){ .main = main, .constraints = &constraints };
    walk(S, &state, &context);
    std.debug.assert(context.cursor == N_MAIN_COLUMNS and context.constraint == N_CONSTRAINTS);
    return constraints;
}

pub fn outputGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [WIDTH]S {
    var state: [WIDTH]S = undefined;
    const last_round = N_MAIN_COLUMNS - 2 * WIDTH;
    for (&state, 0..) |*value, lane| value.* = main[last_round + 2 * lane + 1];
    external(S, &state);
    return state;
}

/// Preserve the exact legacy narrow relation entries and two-claim layout.
/// Zero-multiplicity wide/IO entries are retained to avoid claim-layout drift.
pub fn entriesGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) entries.Builder(S).List {
    const input = initialState(S, main[1], main[2]);
    const output = outputGeneric(S, main);
    var narrow = [_]S{S.zero()} ** WIDTH;
    narrow[0] = output[0];
    var wide = [_]S{S.zero()} ** WIDTH;
    @memcpy(wide[0..8], output[0..8]);
    var io: [2 * WIDTH]S = undefined;
    @memcpy(io[0..WIDTH], &input);
    @memcpy(io[WIDTH..], &output);
    var list = entries.Builder(S).List{};
    append(S, &list, .poseidon2, main[0].neg(), input);
    append(S, &list, .poseidon2, main[0], narrow);
    append(S, &list, .poseidon2, S.zero(), wide);
    append(S, &list, .poseidon2_io, S.zero(), io);
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

fn initialState(comptime S: type, left: S, right: S) [WIDTH]S {
    var result = [_]S{S.zero()} ** WIDTH;
    result[0] = left;
    result[1] = right;
    return result;
}

const walk = @import("poseidon2_degree3_schedule.zig").walk;
const external = @import("poseidon2_degree3_schedule.zig").external;

const Fill = struct {
    row: *Row,
    cursor: usize = 3,
    pub fn sbox(self: *@This(), x: M31) M31 {
        const square = x.square();
        const fifth = x.mul(square.square());
        self.row[self.cursor] = square;
        self.row[self.cursor + 1] = fifth;
        self.cursor += 2;
        return fifth;
    }
};

fn Evaluate(comptime S: type) type {
    return struct {
        main: [N_MAIN_COLUMNS]S,
        constraints: *[N_CONSTRAINTS]S,
        cursor: usize = 3,
        constraint: usize = 2,
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
    if (N_SBOXES != 142 or N_MAIN_COLUMNS != 287 or N_CONSTRAINTS != 286)
        @compileError("Versioned Ethereum narrow degree-three Poseidon geometry changed");
}
