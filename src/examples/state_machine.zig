const std = @import("std");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const utils = @import("../core/utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const State = [2]M31;

pub const Error = error{
    InvalidIncIndex,
    InvalidLogSize,
    DegenerateDenominator,
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

/// State-machine lookup elements (`z`, `alpha`) used for relation combination.
pub const Elements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(channel: anytype) Elements {
        return .{
            .z = channel.drawSecureFelt(),
            .alpha = channel.drawSecureFelt(),
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

/// Computes the interaction claimed sum by direct row-wise accumulation.
///
/// This matches upstream state-machine interaction numerator/denominator terms:
/// `(output_denom - input_denom) / (input_denom * output_denom)`.
pub fn claimedSumFromInitial(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    var curr_state = initial_state;
    var sum = QM31.zero();
    for (0..n) |_| {
        const input_denom = elements.combine(curr_state);
        curr_state[inc_index] = curr_state[inc_index].add(M31.one());
        const output_denom = elements.combine(curr_state);
        if (input_denom.isZero() or output_denom.isZero()) return Error.DegenerateDenominator;

        const numerator = output_denom.sub(input_denom);
        const denominator = input_denom.mul(output_denom);
        sum = sum.add(try numerator.div(denominator));
    }

    return sum;
}

/// Computes the same claimed sum via telescoping:
/// `combine(first)^-1 - combine(last)^-1`.
pub fn claimedSumTelescoping(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    const first = elements.combine(initial_state);

    var last_state = initial_state;
    last_state[inc_index] = last_state[inc_index].add(
        M31.fromU64(@intCast(n)),
    );
    const last = elements.combine(last_state);

    if (first.isZero() or last.isZero()) return Error.DegenerateDenominator;
    return (try first.inv()).sub(try last.inv());
}

/// Validates the upstream state-machine claimed-sum statement:
/// `(x_claim + y_claim) * combine(initial) * combine(final) == combine(final) - combine(initial)`.
pub fn claimsSatisfyStatement(
    initial_state: State,
    final_state: State,
    x_axis_claimed_sum: QM31,
    y_axis_claimed_sum: QM31,
    elements: Elements,
) Error!bool {
    const initial_comb = elements.combine(initial_state);
    const final_comb = elements.combine(final_state);
    if (initial_comb.isZero() or final_comb.isZero()) return Error.DegenerateDenominator;

    const lhs = x_axis_claimed_sum
        .add(y_axis_claimed_sum)
        .mul(initial_comb)
        .mul(final_comb);
    const rhs = final_comb.sub(initial_comb);
    return lhs.eql(rhs);
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

test "examples state_machine: claimed-sum accumulation equals telescoping form" {
    const elements: Elements = .{
        .z = QM31.fromU32Unchecked(41, 17, 9, 3),
        .alpha = QM31.fromU32Unchecked(5, 8, 13, 21),
    };
    const initial: State = .{
        M31.fromCanonical(7),
        M31.fromCanonical(11),
    };

    const direct = try claimedSumFromInitial(6, initial, 1, elements);
    const telescoping = try claimedSumTelescoping(6, initial, 1, elements);
    try std.testing.expect(direct.eql(telescoping));
}

test "examples state_machine: draw yields distinct lookup elements on successive calls" {
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    var channel = Channel{};
    const e0 = Elements.draw(&channel);
    const e1 = Elements.draw(&channel);
    try std.testing.expect(!e0.z.eql(e1.z) or !e0.alpha.eql(e1.alpha));
}

test "examples state_machine: claimed sums satisfy public statement equation" {
    const initial: State = .{
        M31.fromCanonical(3),
        M31.fromCanonical(9),
    };
    const elements: Elements = .{
        .z = QM31.fromU32Unchecked(27, 4, 19, 8),
        .alpha = QM31.fromU32Unchecked(2, 7, 11, 13),
    };
    const log_n_rows: u32 = 7;

    const transitions = try transitionStates(log_n_rows, initial);
    const x_claim = try claimedSumTelescoping(log_n_rows, initial, 0, elements);
    const y_claim = try claimedSumTelescoping(log_n_rows - 1, transitions.intermediate, 1, elements);
    const ok = try claimsSatisfyStatement(
        initial,
        transitions.final,
        x_claim,
        y_claim,
        elements,
    );
    try std.testing.expect(ok);
}
