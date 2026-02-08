const std = @import("std");
const m31 = @import("../core/fields/m31.zig");
const utils = @import("../core/utils.zig");

const M31 = m31.M31;

pub const State = [2]M31;

pub const Error = error{
    InvalidIncIndex,
    InvalidLogSize,
};

/// Generates two trace columns in bit-reversed circle-domain order.
///
/// Semantics match upstream `examples/state_machine/gen.rs::gen_trace`.
pub fn genTrace(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_state: State,
    inc_index: usize,
) (std.mem.Allocator.Error || Error)![2][]M31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    const col0 = try allocator.alloc(M31, n);
    errdefer allocator.free(col0);
    const col1 = try allocator.alloc(M31, n);
    errdefer allocator.free(col1);

    @memset(col0, M31.zero());
    @memset(col1, M31.zero());

    var curr_state = initial_state;
    for (0..n) |i| {
        const bit_rev_index = utils.bitReverseIndex(
            utils.cosetIndexToCircleDomainIndex(i, log_size),
            log_size,
        );
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

pub const TransitionStates = struct {
    intermediate: State,
    final: State,
};

/// Computes intermediate/final public states used by state-machine example.
///
/// Semantics match upstream `examples/state_machine/mod.rs::prove_state_machine`.
pub fn transitionStates(log_n_rows: u32, initial_state: State) Error!TransitionStates {
    if (log_n_rows == 0 or log_n_rows >= 31) return Error.InvalidLogSize;

    var intermediate = initial_state;
    intermediate[0] = intermediate[0].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows)));

    var final = intermediate;
    final[1] = final[1].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows - 1)));

    return .{
        .intermediate = intermediate,
        .final = final,
    };
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "examples state_machine: trace generation increments selected coordinate" {
    const alloc = std.testing.allocator;

    var trace = try genTrace(
        alloc,
        4,
        .{
            M31.fromCanonical(17),
            M31.fromCanonical(16),
        },
        1,
    );
    defer deinitTrace(alloc, &trace);

    try std.testing.expectEqual(@as(usize, 16), trace[0].len);
    try std.testing.expectEqual(@as(usize, 16), trace[1].len);
    try std.testing.expect(trace[0][0].eql(M31.fromCanonical(17)));
}

test "examples state_machine: transition states follow upstream formulas" {
    const initial: State = .{
        M31.fromCanonical(5),
        M31.fromCanonical(9),
    };
    const states = try transitionStates(6, initial);

    try std.testing.expect(states.intermediate[0].eql(M31.fromCanonical(5 + 64)));
    try std.testing.expect(states.intermediate[1].eql(M31.fromCanonical(9)));
    try std.testing.expect(states.final[0].eql(M31.fromCanonical(5 + 64)));
    try std.testing.expect(states.final[1].eql(M31.fromCanonical(9 + 32)));
}

test "examples state_machine: rejects invalid log size and coordinate index" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidLogSize,
        transitionStates(0, .{ M31.zero(), M31.zero() }),
    );
    try std.testing.expectError(
        Error.InvalidLogSize,
        transitionStates(31, .{ M31.zero(), M31.zero() }),
    );
    try std.testing.expectError(
        Error.InvalidIncIndex,
        genTrace(alloc, 4, .{ M31.zero(), M31.zero() }, 2),
    );
}
