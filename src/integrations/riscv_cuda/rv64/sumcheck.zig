//! Enqueue a complete native single-LogUp-oracle sumcheck. The CPU handles
//! geometry only: every polynomial, challenge and claim stays on the device.
//! Full GKR batching/PCS/physical admission remain outside this capability.
const std = @import("std");
const runtime = @import("stwo_cuda_backend").runtime;
const R = @import("resident.zig");
const abi = @import("abi.zig");
const Slice = runtime.column.DeviceSlice(u32);
pub const Input = struct {
    fractions: R.Fraction,
    point: Slice,
    lambda: Slice,
    claim: Slice,
    /// Native scoped raw-mod-OM31 digest words + draw counter (nine words).
    seed: Slice,
};
pub const Workspace = struct {
    banks: [2]R.Fraction,
    eq: R.Plane,
    scratch_a: R.Plane,
    scratch_b: R.Plane,
    sums: R.Plane,
    state: Slice,
    records: Slice,
    terminal_mask: Slice,
};
pub const Enqueued = struct {
    terminal: R.Fraction,
    rounds: u32,
    state: Slice,
    records: Slice,
    terminal_mask: Slice,
};

/// All reservations are generation/range/alias checked before init can mutate
/// anything. Inputs remain immutable; no numerical host fallback is possible.
/// The caller joins, checks device status/cursor and freshly verifies the proof
/// before publishing. Every owner remains borrowed through completion/abort.
pub fn enqueue(commands: anytype, input: Input, work: Workspace) !Enqueued {
    if (commands.poisoned) return error.JobPoisoned;
    const tail_count = commands.tail_count;
    if (tail_count != 0 and (tail_count < 4 or tail_count > 256 or !std.math.isPowerOfTwo(tail_count))) return error.InvalidGeometry;
    const n = input.fractions.count;
    if (n < 4 or n > 1 << 28 or !std.math.isPowerOfTwo(n)) return error.InvalidGeometry;
    const variables: u32 = std.math.log2_int(u32, n) - 1;
    var custody = Reservations{};
    try custody.fraction(commands.context, input.fractions, n, false);
    try custody.slice(commands.context, input.point, 8 * variables, false);
    try custody.slice(commands.context, input.lambda, 8, false);
    try custody.slice(commands.context, input.claim, 8, false);
    try custody.slice(commands.context, input.seed, 9, false);
    try custody.fraction(commands.context, work.banks[0], n / 2, true);
    try custody.fraction(commands.context, work.banks[1], n / 4, true);
    try custody.plane(commands.context, work.eq, n / 4, 8, true);
    const groups = (n / 4 + 127) / 128;
    try custody.plane(commands.context, work.scratch_a, 2 * groups, 8, true);
    try custody.plane(commands.context, work.scratch_b, 2 * groups, 8, true);
    try custody.plane(commands.context, work.sums, 2, 8, true);
    try custody.slice(commands.context, work.state, abi.round_state_words, true);
    try custody.slice(commands.context, work.records, variables * abi.round_record_words, true);
    try custody.slice(commands.context, work.terminal_mask, 32, true);

    try commands.initSumcheck(work.state, input.seed, input.claim, variables);
    try commands.eq(input.point, variables, work.eq);
    var current = input.fractions;
    var tail_used = false;
    for (0..variables) |at| {
        if (tail_count != 0 and current.count <= tail_count) {
            // The next bank is disjoint from current, irrespective of how many
            // rounds the tail completes. Final parity need not match baseline.
            var terminal = work.banks[at % 2];
            terminal.count = 2;
            try commands.tail(.{
                .input = current,
                .output = terminal,
                .eq = work.eq,
                .point = input.point,
                .lambda = input.lambda,
                .state = work.state,
                .records = try work.records.sub(at * abi.round_record_words, (variables - at) * abi.round_record_words),
                .mask = work.terminal_mask,
                .variables = variables,
                .first = @intCast(at),
            });
            current = terminal;
            tail_used = true;
            break;
        }
        if (at == 0 or !commands.fused_fold_sum) try commands.sum(current, work.eq, input.lambda, work.scratch_a, work.scratch_b, work.sums);
        const record = try work.records.sub(at * abi.round_record_words, abi.round_record_words);
        try commands.round(work.state, variables, @intCast(at), work.sums, input.point, record);
        const challenge = try record.sub(32, 8);
        var output = work.banks[at % 2];
        output.count = current.count / 2;
        if (commands.fused_fold_sum and at + 1 < variables and (tail_count == 0 or output.count > tail_count)) {
            try commands.foldSum(current, challenge, output, work.eq, input.lambda, work.scratch_a, work.scratch_b, work.sums);
        } else try commands.fold(current, challenge, output);
        current = output;
    }
    if (!tail_used) try commands.packMask(current, work.terminal_mask);
    return .{ .terminal_mask = work.terminal_mask, .terminal = current, .rounds = variables, .state = work.state, .records = work.records };
}

const Reservations = struct {
    const Range = struct { begin: usize, end: usize, write: bool };
    ranges: [20]Range = undefined,
    used: usize = 0,
    fn slice(self: *Reservations, context: anytype, s: Slice, words: usize, write: bool) !void {
        _ = try context.deviceSlicePointer(u32, s, words);
        const bytes = try std.math.mul(usize, words, 4);
        const end = try std.math.add(usize, s.address, bytes);
        for (self.ranges[0..self.used]) |r| {
            if ((write or r.write) and s.address < r.end and r.begin < end) return error.OverlappingWorkspace;
        }
        if (self.used == self.ranges.len) return error.ReservationCapacity;
        self.ranges[self.used] = .{ .begin = s.address, .end = end, .write = write };
        self.used += 1;
    }
    fn plane(self: *Reservations, context: anytype, p: R.Plane, n: u32, coordinates: u32, write: bool) !void {
        if (p.stride < n or p.coordinates != coordinates) return error.InvalidPlane;
        try self.slice(context, p.data, try std.math.mul(usize, p.stride, coordinates), write);
    }
    fn fraction(self: *Reservations, context: anytype, f: R.Fraction, n: u32, write: bool) !void {
        if (f.count != n or (f.n.coordinates != 1 and f.n.coordinates != 8) or (write and f.n.coordinates != 8)) return error.InvalidGeometry;
        try self.plane(context, f.n, n, f.n.coordinates, write);
        try self.plane(context, f.d, n, 8, write);
    }
};
