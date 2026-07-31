//! Exact pinned Stark-V Poseidon2-M31 AIR for sparse Merkle hashes.
//!
//! The 445-column layout matches the generated Rust component:
//! enabler, 16 inputs, 426 degree-reduction temporaries, wide, and io.
//! RV32IM sparse trees use narrow mode (`wide = io = 0`).

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const constants = @import("poseidon2_constants.zig");
const permutation = @import("poseidon2.zig");

pub const WIDTH: usize = 16;
pub const N_TEMPORARIES: usize = 426;
pub const N_MAIN_COLUMNS: usize = 1 + WIDTH + N_TEMPORARIES + 2;
pub const N_MATERIALIZATION_CONSTRAINTS: usize = N_TEMPORARIES;
pub const N_PERMUTATION_CONSTRAINTS: usize = 1 + N_MATERIALIZATION_CONSTRAINTS;
pub const N_FLAG_CONSTRAINTS: usize = 3;
pub const N_CONSTRAINTS: usize = N_PERMUTATION_CONSTRAINTS + N_FLAG_CONSTRAINTS;
pub const N_SUMS: usize = 2;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
const INPUT_START: usize = 1;
const TEMP_START: usize = INPUT_START + WIDTH;
const WIDE_COLUMN: usize = TEMP_START + N_TEMPORARIES;
const IO_COLUMN: usize = WIDE_COLUMN + 1;
const FIRST_FULL_ROUND_WIDTH: usize = 2 * WIDTH;
const MATERIALIZED_FULL_ROUND_WIDTH: usize = 3 * WIDTH;
const PARTIAL_ROUND_WIDTH: usize = 3;
const OUTPUT_START: usize = TEMP_START + N_TEMPORARIES - WIDTH;

pub const Call = struct {
    input: [WIDTH]u32,
    wide: bool = false,
    io: bool = false,

    pub fn narrow(left: u32, right: u32) Call {
        var input = [_]u32{0} ** WIDTH;
        input[0] = left;
        input[1] = right;
        return .{ .input = input };
    }
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.values);
        self.* = undefined;
    }
};

pub const Claims = struct {
    sums: [N_SUMS]QM31,

    pub fn total(self: Claims) QM31 {
        return self.sums[0].add(self.sums[1]);
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn generateMain(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    var columns = try allocateColumns(allocator, N_MAIN_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    for (&columns) |column| @memset(column, M31.zero());
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (calls, 0..) |call, row_index| {
        const row = fill(call);
        const dst = table.map(row_index);
        for (row, 0..) |value, column| columns[column][dst] = value;
    }
    return .{ .values = columns };
}

/// Fill exactly the generated Rust witness row, including degree-reduction
/// temporaries. The final permutation state occupies temporaries 410..425.
pub fn fill(call: Call) [N_MAIN_COLUMNS]M31 {
    var row = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    row[0] = M31.one();
    var state: [WIDTH]M31 = undefined;
    for (&state, call.input, 0..) |*value, input, lane| {
        value.* = M31.fromU64(input);
        row[INPUT_START + lane] = value.*;
    }

    externalMatrixM31(&state);
    var cursor: usize = TEMP_START;
    fillFirstFullRound(&row, &cursor, &state, constants.EXTERNAL_ROUND[0]);
    for (constants.EXTERNAL_ROUND[1..4]) |round| {
        fillMaterializedFullRound(&row, &cursor, &state, round);
    }
    for (constants.INTERNAL_ROUND) |round_constant| {
        fillMaterializedPartialRound(
            &row,
            &cursor,
            &state,
            round_constant,
            constants.INTERNAL_MATRIX,
        );
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| {
        fillMaterializedFullRound(&row, &cursor, &state, round);
    }
    for (state) |value| {
        row[cursor] = value;
        cursor += 1;
    }
    std.debug.assert(cursor == WIDE_COLUMN);
    row[WIDE_COLUMN] = M31.fromU64(@intFromBool(call.wide));
    row[IO_COLUMN] = M31.fromU64(@intFromBool(call.io));
    return row;
}

pub fn output(row: [N_MAIN_COLUMNS]M31) [WIDTH]M31 {
    return row[OUTPUT_START..][0..WIDTH].*;
}

/// Exact degree-three constraint order emitted by pinned Stark-V's felt AIR
/// compiler: enabler boolean, 426 materializations, then three flag checks.
pub fn evaluate(main: [N_MAIN_COLUMNS]QM31) [N_CONSTRAINTS]QM31 {
    const enabler = main[0];
    var state = main[INPUT_START..][0..WIDTH].*;
    externalMatrixSecure(&state);
    var result: [N_CONSTRAINTS]QM31 = undefined;
    var constraint: usize = 1;
    var cursor: usize = TEMP_START;
    const one = QM31.one();
    result[0] = enabler.mul(one.sub(enabler));

    evaluateFirstFullRound(
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

/// Protocol-shell constraints for callers that admit only the narrow
/// permutation mode. The generic pinned evaluator deliberately continues to
/// support wide and atomic-I/O rows.
pub fn narrowModeConstraints(main: [N_MAIN_COLUMNS]QM31) [2]QM31 {
    return .{ main[WIDE_COLUMN], main[IO_COLUMN] };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| pairs[index] = if (index < calls.len)
        rowPairsFromCall(calls[index], relations)
    else
        paddingPairs();

    var cumulative: [N_SUMS]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, sum_index| {
        const row_pairs = try allocator.alloc(logup.RowPair, size);
        defer allocator.free(row_pairs);
        for (pairs, row_pairs) |row, *pair| pair.* = row[sum_index];
        column.* = try logup.cumulativeColumn(allocator, row_pairs);
        initialized += 1;
    }

    var columns = try allocateColumns(allocator, N_INTERACTION_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (0..size) |row| {
        const dst = table.map(row);
        for (0..N_SUMS) |sum_index| {
            const current = cumulative[sum_index].sums[row].toM31Array();
            for (0..4) |coordinate| {
                columns[sum_index * 4 + coordinate][dst] = current[coordinate];
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{ cumulative[0].claimed, cumulative[1].claimed } },
    };
}

pub fn interactionConstraints(
    main: [N_MAIN_COLUMNS]QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_SUMS]QM31 {
    const pairs = rowPairs(main, relations);
    var result: [N_SUMS]QM31 = undefined;
    for (&result, 0..) |*value, index| {
        value.* = logup.pairConstraint(
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    return result;
}

pub fn rowPairsFromCall(call: Call, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const main = fill(call);
    var secure: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&secure, main) |*dst, value| dst.* = QM31.fromBase(value);
    return rowPairs(secure, relations);
}

pub fn rowPairs(main: [N_MAIN_COLUMNS]QM31, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const list = entries(main);
    return .{
        list.pair(0, relations) catch unreachable,
        list.pair(1, relations) catch unreachable,
    };
}

pub fn entries(main: [N_MAIN_COLUMNS]QM31) lookup_entry.List {
    const enabler = main[0];
    const wide = main[WIDE_COLUMN];
    const io = main[IO_COLUMN];
    const one = QM31.one();
    const input = main[INPUT_START..][0..WIDTH].*;
    const out = main[OUTPUT_START..][0..WIDTH].*;
    var narrow = [_]QM31{QM31.zero()} ** WIDTH;
    narrow[0] = out[0];
    var wide_output = [_]QM31{QM31.zero()} ** WIDTH;
    @memcpy(wide_output[0..8], out[0..8]);
    var io_tuple: [2 * WIDTH]QM31 = undefined;
    @memcpy(io_tuple[0..WIDTH], &input);
    @memcpy(io_tuple[WIDTH..], &out);
    var list = lookup_entry.List{};
    append(&list, .poseidon2, enabler.mul(one.sub(io)).neg(), input);
    append(&list, .poseidon2, enabler.mul(one.sub(wide).sub(io)), narrow);
    append(&list, .poseidon2, enabler.mul(wide), wide_output);
    append(&list, .poseidon2_io, enabler.mul(io), io_tuple);
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

fn fillFirstFullRound(
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

fn fillMaterializedFullRound(
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

fn fillMaterializedPartialRound(
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

fn evaluateFirstFullRound(
    main: [N_MAIN_COLUMNS]QM31,
    cursor: *usize,
    state: *[WIDTH]QM31,
    round: [WIDTH]u32,
    enabler: QM31,
    result: *[N_CONSTRAINTS]QM31,
    constraint: *usize,
) void {
    var sboxed: [WIDTH]QM31 = undefined;
    for (state, round, 0..) |value, constant, lane| {
        const x = value.add(baseSecure(constant));
        const x2 = main[cursor.* + 2 * lane];
        const x4 = main[cursor.* + 2 * lane + 1];
        result[constraint.*] = enabler.mul(x2.sub(x.square()));
        constraint.* += 1;
        result[constraint.*] = enabler.mul(x4.sub(x2.square()));
        constraint.* += 1;
        sboxed[lane] = x.mul(x4);
    }
    externalMatrixSecure(&sboxed);
    state.* = sboxed;
    cursor.* += FIRST_FULL_ROUND_WIDTH;
}

fn evaluateMaterializedFullRound(
    main: [N_MAIN_COLUMNS]QM31,
    cursor: *usize,
    state: *[WIDTH]QM31,
    round: [WIDTH]u32,
    enabler: QM31,
    result: *[N_CONSTRAINTS]QM31,
    constraint: *usize,
) void {
    for (state, round, 0..) |*value, constant, lane| {
        const x = main[cursor.* + 3 * lane];
        const x2 = main[cursor.* + 3 * lane + 1];
        const x4 = main[cursor.* + 3 * lane + 2];
        result[constraint.*] = enabler.mul(x.sub(value.add(baseSecure(constant))));
        constraint.* += 1;
        result[constraint.*] = enabler.mul(x2.sub(x.square()));
        constraint.* += 1;
        result[constraint.*] = enabler.mul(x4.sub(x2.square()));
        constraint.* += 1;
        value.* = x.mul(x4);
    }
    externalMatrixSecure(state);
    cursor.* += MATERIALIZED_FULL_ROUND_WIDTH;
}

fn evaluateMaterializedPartialRound(
    main: [N_MAIN_COLUMNS]QM31,
    cursor: *usize,
    state: *[WIDTH]QM31,
    round_constant: u32,
    diagonal: [WIDTH]u32,
    enabler: QM31,
    result: *[N_CONSTRAINTS]QM31,
    constraint: *usize,
) void {
    const x = main[cursor.*];
    const x2 = main[cursor.* + 1];
    const x4 = main[cursor.* + 2];
    result[constraint.*] = enabler.mul(x.sub(state[0].add(baseSecure(round_constant))));
    constraint.* += 1;
    result[constraint.*] = enabler.mul(x2.sub(x.square()));
    constraint.* += 1;
    result[constraint.*] = enabler.mul(x4.sub(x2.square()));
    constraint.* += 1;
    state[0] = x.mul(x4);
    internalMatrixSecure(state, diagonal);
    cursor.* += PARTIAL_ROUND_WIDTH;
}

fn externalMatrixM31(state: *[WIDTH]M31) void {
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

fn externalMatrixSecure(state: *[WIDTH]QM31) void {
    for (0..4) |block| {
        const start = 4 * block;
        const mixed = m4Secure(state[start..][0..4].*);
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

fn m4M31(input: [4]M31) [4]M31 {
    const t0 = input[0].add(input[1]);
    const t1 = input[2].add(input[3]);
    const t2 = input[1].add(input[1]).add(t1);
    const t3 = input[3].add(input[3]).add(t0);
    const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
    const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
    return .{ t3.add(t5), t5, t2.add(t4), t4 };
}

fn m4Secure(input: [4]QM31) [4]QM31 {
    const t0 = input[0].add(input[1]);
    const t1 = input[2].add(input[3]);
    const t2 = input[1].add(input[1]).add(t1);
    const t3 = input[3].add(input[3]).add(t0);
    const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
    const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
    return .{ t3.add(t5), t5, t2.add(t4), t4 };
}

fn internalMatrixM31(state: *[WIDTH]M31, diagonal: [WIDTH]u32) void {
    var sum = M31.zero();
    for (state) |value| sum = sum.add(value);
    for (state, diagonal) |*value, coefficient| {
        value.* = value.mul(M31.fromCanonical(coefficient)).add(sum);
    }
}

fn internalMatrixSecure(state: *[WIDTH]QM31, diagonal: [WIDTH]u32) void {
    var sum = QM31.zero();
    for (state) |value| sum = sum.add(value);
    for (state, diagonal) |*value, coefficient| {
        value.* = value.mulM31(M31.fromCanonical(coefficient)).add(sum);
    }
}

fn allocateColumns(allocator: std.mem.Allocator, comptime n: usize, len: usize) ![n][]M31 {
    var columns: [n][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, len);
        initialized += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

fn baseSecure(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn append(list: *lookup_entry.List, domain: lookup_entry.Domain, numerator: QM31, values: anytype) void {
    var item = lookup_entry.Entry{ .domain = domain, .numerator = numerator, .arity = values.len };
    inline for (values, 0..) |value, index| item.values[index] = value;
    list.append(item);
}

fn secureRow(row: [N_MAIN_COLUMNS]M31) [N_MAIN_COLUMNS]QM31 {
    var result: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, row) |*dst, value| dst.* = QM31.fromBase(value);
    return result;
}

fn expectAllZero(values: []const QM31) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

test "poseidon2 AIR: exact narrow pair matches the pinned permutation" {
    const row = fill(Call.narrow(1, 2));
    try std.testing.expectEqual(@as(u32, 1975699496), output(row)[0].toU32());
    try std.testing.expectEqual(permutation.hashPair(1, 2), output(row)[0].toU32());
    try expectAllZero(&evaluate(secureRow(row)));
}

test "poseidon2 AIR: generated column schedule matches pinned Rust" {
    const row = fill(Call.narrow(1, 2));
    const expected = [_]struct { column: usize, value: u32 }{
        .{ .column = 0, .value = 1 },
        .{ .column = 16, .value = 0 },
        .{ .column = 17, .value = 888382669 },
        .{ .column = 48, .value = 1245644797 },
        .{ .column = 49, .value = 1900086922 },
        .{ .column = 80, .value = 2142961709 },
        .{ .column = 128, .value = 125143133 },
        .{ .column = 176, .value = 1759109891 },
        .{ .column = 218, .value = 572377586 },
        .{ .column = 266, .value = 1621981814 },
        .{ .column = 314, .value = 1610989476 },
        .{ .column = 362, .value = 738050654 },
        .{ .column = 409, .value = 260539998 },
        .{ .column = 410, .value = 59563392 },
        .{ .column = 425, .value = 1888574172 },
        .{ .column = 426, .value = 1886810401 },
        .{ .column = 441, .value = 23371529 },
        .{ .column = 442, .value = 369091567 },
        .{ .column = 443, .value = 0 },
        .{ .column = 444, .value = 0 },
    };
    for (expected) |item| {
        try std.testing.expectEqual(item.value, row[item.column].toU32());
    }
}

test "poseidon2 AIR: arbitrary canonical narrow pairs satisfy every constraint" {
    var prng = std.Random.DefaultPrng.init(0x506f736569646f6e);
    const random = prng.random();
    for (0..64) |_| {
        const lhs = random.int(u32) % @import("stwo_core").fields.m31.Modulus;
        const rhs = random.int(u32) % @import("stwo_core").fields.m31.Modulus;
        try expectAllZero(&evaluate(secureRow(fill(Call.narrow(lhs, rhs)))));
    }
}

test "poseidon2 AIR: input, intermediate, output, and conflicting flags fail" {
    const honest = fill(Call.narrow(11, 22));
    inline for (.{ INPUT_START, TEMP_START, OUTPUT_START }) |column| {
        var mutated = honest;
        mutated[column] = mutated[column].add(M31.one());
        const constraints = evaluate(secureRow(mutated));
        var nonzero = false;
        for (constraints) |value| nonzero = nonzero or !value.isZero();
        try std.testing.expect(nonzero);
    }
    var conflicting_flags = honest;
    conflicting_flags[WIDE_COLUMN] = M31.one();
    conflicting_flags[IO_COLUMN] = M31.one();
    const flag_constraints = evaluate(secureRow(conflicting_flags));
    try std.testing.expect(!flag_constraints[N_CONSTRAINTS - 1].isZero());
}

test "poseidon2 AIR: padding is zero and the enabler is boolean" {
    const padding = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    try expectAllZero(&evaluate(padding));
    var non_boolean = padding;
    non_boolean[0] = QM31.fromBase(M31.fromU64(2));
    const constraints = evaluate(non_boolean);
    try std.testing.expect(!constraints[0].isZero());
}

test "poseidon2 AIR: Merkle input and narrow output cancel exactly" {
    const relations = relations_mod.Relations.dummy();
    const call = Call.narrow(31, 41);
    const row = secureRow(fill(call));
    const poseidon_pairs = rowPairs(row, &relations);
    var merkle_input = [_]QM31{QM31.zero()} ** WIDTH;
    merkle_input[0] = QM31.fromBase(M31.fromU64(31));
    merkle_input[1] = QM31.fromBase(M31.fromU64(41));
    var merkle_output = [_]QM31{QM31.zero()} ** WIDTH;
    merkle_output[0] = row[OUTPUT_START];
    const merkle_sum = (try relations.poseidon2.combineSecure(merkle_input).inv())
        .sub(try relations.poseidon2.combineSecure(merkle_output).inv());
    const poseidon_sum = try pairSum(poseidon_pairs[0]);
    try std.testing.expect(merkle_sum.add(poseidon_sum).isZero());
}

fn pairSum(pair: logup.RowPair) !QM31 {
    return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
}
