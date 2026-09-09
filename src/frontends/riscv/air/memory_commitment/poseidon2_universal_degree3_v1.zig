//! Versioned universal Poseidon2 provider with two columns per S-box.
//! Every row, including padding, satisfies all permutation rounds. Inputs and
//! outputs retain the legacy narrow, wide and atomic-IO lookup semantics.
//! No production default is changed by this separately admitted AIR.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constants = @import("poseidon2_constants.zig");
const legacy = @import("poseidon2_air.zig");
const entries = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");

pub const SCHEMA_VERSION: u16 = 1;
pub const STABLE_NAME = "stwo.recursion.poseidon2-universal-degree3.v1";
pub const IDENTITY_DIGEST: [32]u8 = blk: {
    @setEvalBranchQuota(20_000_000);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(STABLE_NAME);
    hash.update(@embedFile("poseidon2_universal_degree3_v1.zig"));
    hash.update(@embedFile("poseidon2_degree3_schedule.zig"));
    hash.update(@embedFile("poseidon2_constants.zig"));
    hash.update(@embedFile("poseidon2_air.zig"));
    hash.update(@embedFile("poseidon2_air_runtime.zig"));
    break :blk hash.finalResult();
};
pub const WIDTH: usize = 16;
pub const N_SBOXES = WIDTH * constants.EXTERNAL_ROUND.len + constants.INTERNAL_ROUND.len;
pub const N_MAIN_COLUMNS = 19 + 2 * N_SBOXES;
pub const WIDE_COLUMN = N_MAIN_COLUMNS - 2;
pub const IO_COLUMN = N_MAIN_COLUMNS - 1;
pub const BINDS_ACTIVE_SELECTOR = false;
pub const Call = legacy.Call;
pub const generateInteraction = legacy.generateInteraction;
pub const generateIoInteractionFromOutputs = legacy.generateIoInteractionFromOutputs;
pub const N_CONSTRAINTS = 4 + 2 * N_SBOXES;
pub const N_SUMS: usize = legacy.N_SUMS;
pub const N_INTERACTION_COLUMNS: usize = legacy.N_INTERACTION_COLUMNS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;
pub const Row = [N_MAIN_COLUMNS]M31;

pub fn fill(call: legacy.Call) !Row {
    if (call.wide and call.io) return error.InvalidPoseidonUniversalModeV1;
    var row: Row = undefined;
    row[0] = M31.one();
    for (call.input, 0..) |word, lane| {
        if (word >= @import("stwo_core").fields.m31.Modulus) return error.InvalidPoseidonUniversalInputV1;
        row[1 + lane] = M31.fromCanonical(word);
    }
    row[WIDE_COLUMN] = M31.fromCanonical(@intFromBool(call.wide));
    row[IO_COLUMN] = M31.fromCanonical(@intFromBool(call.io));
    var state = row[1..17].*;
    var context = Fill{ .row = &row };
    walk(M31, &state, &context);
    std.debug.assert(context.cursor == WIDE_COLUMN);
    if (!call.wide and !call.io) if (call.narrow_output) |expected| {
        if (state[0].toU32() != expected) return error.PoseidonUniversalOutputMismatchV1;
    };
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
    const work_pool = @import("stwo_prover_engine").work_pool;
    if (work_pool.getGlobalPool()) |pool| {
        const count = @min(pool.workerCount(), @max(@as(usize, 1), calls.len / 4096));
        if (count > 1) {
            const workers = try allocator.alloc(MainWorker, count);
            defer allocator.free(workers);
            for (workers, 0..) |*worker, index| worker.* = .{ .columns = columns, .calls = calls, .mapping = placement.mapping, .start = calls.len * index / count, .end = calls.len * (index + 1) / count };
            var group = std.Thread.WaitGroup{};
            for (workers[1..]) |*worker| pool.spawnWg(&group, MainWorker.run, .{worker});
            MainWorker.run(&workers[0]);
            group.wait();
            for (workers) |worker| if (worker.failure) |failure| return failure;
            return;
        }
    }
    var worker = MainWorker{ .columns = columns, .calls = calls, .mapping = placement.mapping, .start = 0, .end = calls.len };
    worker.run();
    if (worker.failure) |failure| return failure;
}

const MainWorker = struct {
    columns: *[N_MAIN_COLUMNS][]M31,
    calls: []const Call,
    mapping: []const usize,
    start: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *@This()) void {
        for (self.start..self.end) |logical| {
            const row = fill(self.calls[logical]) catch |failure| {
                self.failure = failure;
                return;
            };
            for (self.columns, row) |column, value| column[self.mapping[logical]] = value;
        }
    }
};

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

const Fill = struct {
    row: *Row,
    cursor: usize = 17,
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
