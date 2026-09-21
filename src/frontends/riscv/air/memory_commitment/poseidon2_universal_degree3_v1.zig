//! Versioned universal Poseidon2 provider with two columns per S-box.
//! Every row, including padding, satisfies all permutation rounds. Inputs and
//! outputs retain the legacy narrow, wide and atomic-IO lookup semantics.
//! No production default is changed by this separately admitted AIR.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const equations = @import("poseidon2_universal_equations_v1.zig");
const legacy = @import("poseidon2_air.zig");

pub const SCHEMA_VERSION = equations.SCHEMA_VERSION;
pub const STABLE_NAME = equations.STABLE_NAME;
/// Protocol identity binds equations and lookup semantics, independent of source
/// formatting, witness helpers and build provenance.
pub const IDENTITY_DIGEST = @import("poseidon2_universal_identity_v2.zig").CANONICAL_DIGEST;
/// Build provenance only. Never use this source hash to admit a proof or key.
pub const SOURCE_PROVENANCE_DIGEST: [32]u8 = blk: {
    @setEvalBranchQuota(20_000_000);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(STABLE_NAME);
    hash.update(@embedFile("poseidon2_universal_degree3_v1.zig"));
    hash.update(@embedFile("poseidon2_degree3_schedule.zig"));
    hash.update(@embedFile("poseidon2_matrix.zig"));
    hash.update(@embedFile("poseidon2_universal_equations_v1.zig"));
    hash.update(@embedFile("poseidon2_universal_layout_v1.zig"));
    hash.update(@embedFile("../lang/typed_poseidon2_compact.zig"));
    hash.update(@embedFile("../lang/polynomial_replay.zig"));
    hash.update(@embedFile("../lang/typed_poseidon2.zig"));
    hash.update(@embedFile("../logup_equations.zig"));
    hash.update(@embedFile("poseidon2_constants.zig"));
    hash.update(@embedFile("poseidon2_air.zig"));
    hash.update(@embedFile("poseidon2_air_runtime.zig"));
    break :blk hash.finalResult();
};
pub const WIDTH = equations.WIDTH;
pub const N_SBOXES = equations.N_SBOXES;
pub const N_MAIN_COLUMNS = equations.N_MAIN_COLUMNS;
pub const WIDE_COLUMN = equations.WIDE_COLUMN;
pub const IO_COLUMN = equations.IO_COLUMN;
pub const BINDS_ACTIVE_SELECTOR = equations.BINDS_ACTIVE_SELECTOR;
pub const Call = legacy.Call;
pub const generateInteraction = legacy.generateInteraction;
pub const generateIoInteractionFromOutputs = legacy.generateIoInteractionFromOutputs;
pub const N_CONSTRAINTS = equations.N_CONSTRAINTS;
pub const N_SUMS = equations.N_SUMS;
pub const N_INTERACTION_COLUMNS = equations.N_INTERACTION_COLUMNS;
pub const MAX_CONSTRAINT_DEGREE = equations.MAX_CONSTRAINT_DEGREE;
pub const Row = equations.Row;

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

pub const evaluateGeneric = equations.evaluateGeneric;
pub const outputGeneric = equations.outputGeneric;
pub const outputFromColumns = equations.outputFromColumns;
pub const entriesFromColumns = equations.entriesFromColumns;
pub const entriesGeneric = equations.entriesGeneric;
pub const rowPairsGeneric = equations.rowPairsGeneric;
pub const interactionConstraintsGeneric = equations.interactionConstraintsGeneric;

const walk = @import("poseidon2_degree3_schedule.zig").walk;

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
