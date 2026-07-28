//! Owned Poseidon trace preparation for backend-neutral proving.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");

const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const N_LOG_INSTANCES_PER_ROW: u32 = 3;
pub const N_INSTANCES_PER_ROW: usize = 1 << N_LOG_INSTANCES_PER_ROW;
pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const N_FULL_ROUNDS: usize = N_HALF_FULL_ROUNDS * 2;
pub const N_COLUMNS_PER_REP: usize = N_STATE * (1 + N_FULL_ROUNDS) + N_PARTIAL_ROUNDS;
pub const N_COLUMNS: usize = N_COLUMNS_PER_REP * N_INSTANCES_PER_ROW;

pub const Statement = struct {
    log_n_instances: u32,
    claimed_sum: QM31 = QM31.zero(),
};

pub const LOOKUP_COLUMNS: usize = N_INSTANCES_PER_ROW * N_STATE;

pub const LookupData = struct {
    initial: [LOOKUP_COLUMNS][]M31,
    final: [LOOKUP_COLUMNS][]M31,

    pub fn deinit(self: *LookupData, allocator: std.mem.Allocator) void {
        for (self.initial) |column| allocator.free(column);
        for (self.final) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub const PreparedInput = struct {
    request: Statement,
    trace: prover_transaction.PreparedTrace,
    lookup_data: LookupData,

    pub fn deinit(self: *PreparedInput, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.lookup_data.deinit(allocator);
        self.* = undefined;
    }
};

pub const Error = prover_transaction.Error || error{
    InvalidLogNInstances,
};

pub fn validate(statement: Statement) Error!void {
    _ = try logNRows(statement);
}

pub fn logNRows(statement: Statement) Error!u32 {
    if (statement.log_n_instances < N_LOG_INSTANCES_PER_ROW)
        return error.InvalidLogNInstances;
    const log_n_rows = statement.log_n_instances - N_LOG_INSTANCES_PER_ROW;
    if (log_n_rows >= 31) return error.InvalidLogNInstances;
    return log_n_rows;
}

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    const log_n_rows = try logNRows(statement);
    const n = try checkedPow2(log_n_rows);

    const trace = try allocator.alloc([]M31, N_COLUMNS);
    errdefer allocator.free(trace);

    var initialized: usize = 0;
    errdefer for (trace[0..initialized]) |column| allocator.free(column);

    for (trace) |*column| {
        column.* = try allocator.alloc(M31, n);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    for (0..n) |row| fillRow(trace, row);
    return trace;
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: [][]M31) void {
    for (trace) |column| allocator.free(column);
    allocator.free(trace);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    const log_n_rows = try logNRows(statement);
    const trace = try genTrace(allocator, statement);
    var trace_moved = false;
    defer if (!trace_moved) deinitTrace(allocator, trace);
    var lookup_data = try cloneLookupData(allocator, trace);
    errdefer lookup_data.deinit(allocator);

    const preprocessed = try allocator.alloc(prover_pcs.ColumnEvaluation, 0);
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);

    const main = try allocator.alloc(prover_pcs.ColumnEvaluation, trace.len);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);
    for (trace, 0..) |values, index| {
        main[index] = .{ .log_size = log_n_rows, .values = values };
    }
    allocator.free(trace);
    trace_moved = true;

    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
        .lookup_data = lookup_data,
    };
}

fn cloneLookupData(allocator: std.mem.Allocator, trace: []const []const M31) !LookupData {
    var result: LookupData = undefined;
    var initial_count: usize = 0;
    var final_count: usize = 0;
    errdefer {
        for (result.initial[0..initial_count]) |column| allocator.free(column);
        for (result.final[0..final_count]) |column| allocator.free(column);
    }
    for (0..N_INSTANCES_PER_ROW) |rep| {
        const base = rep * N_COLUMNS_PER_REP;
        const final_base = base + N_COLUMNS_PER_REP - N_STATE;
        for (0..N_STATE) |i| {
            const lookup_index = rep * N_STATE + i;
            result.initial[lookup_index] = try allocator.dupe(M31, trace[base + i]);
            initial_count += 1;
            result.final[lookup_index] = try allocator.dupe(M31, trace[final_base + i]);
            final_count += 1;
        }
    }
    return result;
}

fn fillRow(trace: [][]M31, row: usize) void {
    var column_index: usize = 0;
    for (0..N_INSTANCES_PER_ROW) |rep_i| {
        var state: [N_STATE]M31 = undefined;
        for (0..N_STATE) |state_i| {
            state[state_i] = M31.fromU64(
                @as(u64, @intCast(row + state_i + rep_i)),
            );
            trace[column_index][row] = state[state_i];
            column_index += 1;
        }

        for (0..N_HALF_FULL_ROUNDS) |round| {
            applyExternalRound(&state, round);
            for (0..N_STATE) |state_i| {
                trace[column_index][row] = state[state_i];
                column_index += 1;
            }
        }

        for (0..N_PARTIAL_ROUNDS) |round| {
            state[0] = state[0].add(internalRoundConst(round));
            applyInternalRoundMatrix(&state);
            state[0] = pow5(state[0]);
            trace[column_index][row] = state[0];
            column_index += 1;
        }

        for (0..N_HALF_FULL_ROUNDS) |half_round| {
            applyExternalRound(&state, half_round + N_HALF_FULL_ROUNDS);
            for (0..N_STATE) |state_i| {
                trace[column_index][row] = state[state_i];
                column_index += 1;
            }
        }
    }
    std.debug.assert(column_index == N_COLUMNS);
}

fn applyExternalRound(state: *[N_STATE]M31, round: usize) void {
    _ = round;
    for (0..N_STATE) |state_i| {
        state[state_i] = state[state_i].add(roundConst());
    }
    applyExternalRoundMatrix(state);
    for (0..N_STATE) |state_i| state[state_i] = pow5(state[state_i]);
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogNInstances;
    return @as(usize, 1) << @intCast(log_size);
}

fn pow5(x: M31) M31 {
    const x2 = x.mul(x);
    const x4 = x2.mul(x2);
    return x4.mul(x);
}

fn internalRoundConst(round: usize) M31 {
    _ = round;
    return roundConst();
}

fn roundConst() M31 {
    return M31.fromCanonical(1234);
}

fn applyM4(x: [4]M31) [4]M31 {
    const t0 = x[0].add(x[1]);
    const t02 = t0.add(t0);
    const t1 = x[2].add(x[3]);
    const t12 = t1.add(t1);
    const t2 = x[1].add(x[1]).add(t1);
    const t3 = x[3].add(x[3]).add(t0);
    const t4 = t12.add(t12).add(t3);
    const t5 = t02.add(t02).add(t2);
    const t6 = t3.add(t5);
    const t7 = t2.add(t4);
    return .{ t6, t5, t7, t4 };
}

fn applyExternalRoundMatrix(state: *[N_STATE]M31) void {
    for (0..4) |i| {
        const offset = i * 4;
        const mixed = applyM4(.{
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        });
        for (0..4) |j| state[offset + j] = mixed[j];
    }

    for (0..4) |j| {
        const sum = state[j].add(state[j + 4]).add(state[j + 8]).add(state[j + 12]);
        for (0..4) |i| {
            const index = i * 4 + j;
            state[index] = state[index].add(sum);
        }
    }
}

fn applyInternalRoundMatrix(state: *[N_STATE]M31) void {
    var sum = state[0];
    for (1..N_STATE) |i| sum = sum.add(state[i]);
    for (0..N_STATE) |i| {
        const coefficient = M31.fromU64(@as(u64, 1) << @intCast(i + 1));
        state[i] = state[i].mul(coefficient).add(sum);
    }
}

test "exact Poseidon trace follows pinned fixed round constants" {
    const allocator = std.testing.allocator;
    const trace = try genTrace(allocator, .{ .log_n_instances = 7 });
    defer deinitTrace(allocator, trace);

    var state: [N_STATE]M31 = undefined;
    for (&state, 0..) |*value, i| value.* = M31.fromU64(i);
    applyExternalRound(&state, 0);
    for (state, 0..) |value, i| {
        try std.testing.expect(value.eql(trace[N_STATE + i][0]));
    }

    var second = [_]M31{M31.zero()} ** N_STATE;
    for (&second) |*value| value.* = M31.fromCanonical(1234);
    applyExternalRoundMatrix(&second);
    for (&second) |*value| value.* = pow5(value.*);
    try std.testing.expect(!second[0].eql(M31.zero()));
}
