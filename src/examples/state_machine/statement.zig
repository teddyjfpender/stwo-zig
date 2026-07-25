//! Transcript-derived public statement for the State Machine example.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const trace_input = @import("input.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const State = trace_input.State;
pub const Channel = channel_blake2s.Blake2sChannel;

pub const Error = error{
    InvalidIncIndex,
    InvalidLogSize,
    DegenerateDenominator,
    DivisionByZero,
    NonBaseField,
    StatementNotSatisfied,
};

pub const TransitionStates = struct {
    intermediate: State,
    final: State,
};

pub const Statement0 = struct {
    n: u32,
    m: u32,
};

pub const Statement1 = struct {
    x_axis_claimed_sum: QM31,
    y_axis_claimed_sum: QM31,
};

pub const PreparedStatement = struct {
    public_input: [2]State,
    stmt0: Statement0,
    stmt1: Statement1,
};

/// State-machine lookup elements (`z`, `alpha`) used for relation combination.
pub const Elements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Elements {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{
            .z = values[0],
            .alpha = values[1],
        };
    }

    /// Combines a state as `state[0] + alpha * state[1] - z`.
    pub fn combine(self: Elements, state: State) QM31 {
        return QM31.fromBase(state[0])
            .add(self.alpha.mul(QM31.fromBase(state[1])))
            .sub(self.z);
    }
};

/// Computes intermediate/final public states used by state-machine example.
pub fn transitionStates(log_n_rows: u32, initial_state: State) Error!TransitionStates {
    if (log_n_rows == 0 or log_n_rows >= 31) return error.InvalidLogSize;

    var intermediate = initial_state;
    intermediate[0] = intermediate[0].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows)));

    var final = intermediate;
    final[1] = final[1].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows - 1)));
    return .{ .intermediate = intermediate, .final = final };
}

/// Computes the interaction claimed sum by direct row-wise accumulation.
pub fn claimedSumFromInitial(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return error.InvalidIncIndex;
    const n = try checkedPow2(log_size);

    var curr_state = initial_state;
    var sum = QM31.zero();
    for (0..n) |_| {
        const input_denom = elements.combine(curr_state);
        curr_state[inc_index] = curr_state[inc_index].add(M31.one());
        const output_denom = elements.combine(curr_state);
        if (input_denom.isZero() or output_denom.isZero())
            return error.DegenerateDenominator;

        sum = sum.add(try output_denom.sub(input_denom).div(input_denom.mul(output_denom)));
    }
    return sum;
}

/// Computes the same claimed sum via telescoping inverse endpoints.
pub fn claimedSumTelescoping(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return error.InvalidIncIndex;
    const n = try checkedPow2(log_size);

    const first = elements.combine(initial_state);
    var last_state = initial_state;
    last_state[inc_index] = last_state[inc_index].add(M31.fromU64(@intCast(n)));
    const last = elements.combine(last_state);
    if (first.isZero() or last.isZero()) return error.DegenerateDenominator;
    return (first.inv() catch unreachable).sub(last.inv() catch unreachable);
}

pub fn claimsSatisfyStatement(
    initial_state: State,
    final_state: State,
    x_axis_claimed_sum: QM31,
    y_axis_claimed_sum: QM31,
    elements: Elements,
) Error!bool {
    const initial_comb = elements.combine(initial_state);
    const final_comb = elements.combine(final_state);
    if (initial_comb.isZero() or final_comb.isZero()) return error.DegenerateDenominator;

    const lhs = x_axis_claimed_sum
        .add(y_axis_claimed_sum)
        .mul(initial_comb)
        .mul(final_comb);
    return lhs.eql(final_comb.sub(initial_comb));
}

pub fn prepare(
    log_n_rows: u32,
    initial_state: State,
    elements: Elements,
) Error!PreparedStatement {
    const transitions = try transitionStates(log_n_rows, initial_state);
    return .{
        .public_input = .{ initial_state, transitions.final },
        .stmt0 = .{ .n = log_n_rows, .m = log_n_rows - 1 },
        .stmt1 = .{
            .x_axis_claimed_sum = try claimedSumTelescoping(
                log_n_rows,
                initial_state,
                0,
                elements,
            ),
            .y_axis_claimed_sum = try claimedSumTelescoping(
                log_n_rows - 1,
                transitions.intermediate,
                1,
                elements,
            ),
        },
    };
}

pub fn verify(statement: PreparedStatement, elements: Elements) Error!void {
    const valid = try claimsSatisfyStatement(
        statement.public_input[0],
        statement.public_input[1],
        statement.stmt1.x_axis_claimed_sum,
        statement.stmt1.y_axis_claimed_sum,
        elements,
    );
    if (!valid) return error.StatementNotSatisfied;
}

pub fn mixStatement0(channel: *Channel, statement: Statement0) void {
    channel.mixU64(statement.n);
    channel.mixU64(statement.m);
}

pub fn mixStatement1(channel: *Channel, statement: Statement1) void {
    channel.mixFelts(&[_]QM31{
        statement.x_axis_claimed_sum,
        statement.y_axis_claimed_sum,
    });
}

test "State Machine lookup elements share one batched transcript draw" {
    const allocator = std.testing.allocator;
    var expected_channel = Channel{};
    const expected = try expected_channel.drawSecureFelts(allocator, 2);
    defer allocator.free(expected);

    var actual_channel = Channel{};
    const actual = try Elements.draw(allocator, &actual_channel);
    try std.testing.expect(actual.z.eql(expected[0]));
    try std.testing.expect(actual.alpha.eql(expected[1]));
    try std.testing.expectEqual(@as(u32, 1), actual_channel.n_draws);
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
