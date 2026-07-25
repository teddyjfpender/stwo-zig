//! Owned State Machine trace preparation for backend-neutral proving.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_impl").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");

const M31 = m31.M31;

pub const State = [2]M31;

pub const Request = struct {
    log_n_rows: u32,
    initial_state: State,
};

pub const Trace = struct {
    main: [4][]M31,
};

pub const PreparedInput = prover_transaction.PreparedInput(Request);

pub const Error = prover_transaction.Error || error{
    InvalidIncIndex,
    InvalidLogSize,
};

pub fn validate(request: Request) Error!void {
    if (request.log_n_rows < 5 or request.log_n_rows >= 31)
        return error.InvalidLogSize;
}

/// Generates two trace columns in bit-reversed circle-domain order.
///
/// Semantics match upstream `examples/state_machine/gen.rs::gen_trace`.
pub fn genTrace(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_state: State,
    inc_index: usize,
) (std.mem.Allocator.Error || Error)![2][]M31 {
    if (inc_index >= 2) return error.InvalidIncIndex;
    const n = try checkedPow2(log_size);

    const col0 = try allocator.alloc(M31, n);
    errdefer allocator.free(col0);
    const col1 = try allocator.alloc(M31, n);
    errdefer allocator.free(col1);

    @memset(col0, M31.zero());
    @memset(col1, M31.zero());

    var curr_state = initial_state;
    for (0..n) |i| {
        const bit_rev_index = storageIndex(i, log_size);
        col0[bit_rev_index] = curr_state[0];
        col1[bit_rev_index] = curr_state[1];
        curr_state[inc_index] = curr_state[inc_index].add(M31.one());
    }

    return .{ col0, col1 };
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: *[2][]M31) void {
    allocator.free(trace[0]);
    allocator.free(trace[1]);
    trace.* = undefined;
}

pub fn prepare(
    allocator: std.mem.Allocator,
    request: Request,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    try validate(request);

    var trace0 = try genTrace(
        allocator,
        request.log_n_rows,
        request.initial_state,
        0,
    );
    var trace0_moved = false;
    defer if (!trace0_moved) deinitTrace(allocator, &trace0);

    var intermediate = request.initial_state;
    intermediate[0] = intermediate[0].add(
        M31.fromCanonical(@as(u32, 1) << @intCast(request.log_n_rows)),
    );
    var trace1 = try genTrace(
        allocator,
        request.log_n_rows - 1,
        intermediate,
        1,
    );
    var trace1_moved = false;
    defer if (!trace1_moved) deinitTrace(allocator, &trace1);

    const preprocessed = try allocator.alloc(prover_pcs.ColumnEvaluation, 0);
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);

    const main = try allocator.alloc(prover_pcs.ColumnEvaluation, 4);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);
    main[0] = .{ .log_size = request.log_n_rows, .values = trace0[0] };
    main[1] = .{ .log_size = request.log_n_rows, .values = trace0[1] };
    main[2] = .{ .log_size = request.log_n_rows - 1, .values = trace1[0] };
    main[3] = .{ .log_size = request.log_n_rows - 1, .values = trace1[1] };
    trace0_moved = true;
    trace1_moved = true;

    return .{
        .request = request,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
    };
}

pub fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn storageIndex(coset_index: usize, log_size: u32) usize {
    const circle_index = utils.cosetIndexToCircleDomainIndex(coset_index, log_size);
    return utils.bitReverseIndex(circle_index, log_size);
}
