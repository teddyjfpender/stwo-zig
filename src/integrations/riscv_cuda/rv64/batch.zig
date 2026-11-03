//! Native mixed-height LogUp sumcheck with one device transcript per batch.
//! Geometry is host control metadata; no round polynomial or challenge is read.
const std = @import("std");
const R = @import("resident.zig");
const S = @import("sumcheck.zig");
const abi = @import("abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
pub const Input = struct {
    oracles: []const R.Fraction,
    point: Slice,
    lambda: Slice,
    alpha: Slice,
    claims: Slice,
    seed: Slice,
};
pub const OracleWorkspace = struct {
    banks: [2]R.Fraction,
    scratch_a: R.Plane,
    scratch_b: R.Plane,
    sums: R.Plane,
    terminal_mask: Slice,
};
pub const Workspace = struct {
    oracles: []const OracleWorkspace,
    eq: R.Plane,
    state: Slice,
    records: Slice,
};
pub const Enqueued = struct { rounds: u32, oracles: usize, state: Slice, records: Slice };
/// Terminal metadata is read once after joined completion; it is not round
/// feedback. Proof fields still require independent native verification.
pub const Header = extern struct {
    digest: [8]u32,
    draws: u32,
    next_round: u32,
    status: u32,
    variables: u32,
    claim: [8]u32,
    correction: [8]u32,
    prefix: [8]u32,
    reserved: [4]u32,
    oracles: u32,
    reserved2: [3]u32,
    pub fn validate(self: Header, expected: Enqueued) !void {
        if (self.status != 0 or self.variables != expected.rounds or self.next_round != expected.rounds or self.oracles != expected.oracles or self.draws > 1 << 20 or (expected.rounds != 0 and self.draws != 1)) return error.InvalidBatchTranscript;
        if (!std.mem.allEqual(u32, &self.reserved, 0) or !std.mem.allEqual(u32, &self.reserved2, 0) or self.correction[0] != 1 or !std.mem.allEqual(u32, self.correction[1..], 0) or std.mem.allEqual(u32, &self.prefix, 0)) return error.InvalidBatchTranscript;
        for (self.claim ++ self.prefix) |word| if (word >= 2147483647) return error.InvalidBatchTranscript;
    }
};
comptime {
    if (@sizeOf(Header) != 176 or @offsetOf(Header, "oracles") != 160) @compileError("mixed sumcheck header ABI mismatch");
}
/// All input and workspace ranges, across every oracle, are admitted before the
/// first mutation. Every borrowed owner remains live through joined completion.
pub fn enqueue(commands: anytype, input: Input, work: Workspace) !Enqueued {
    if (commands.poisoned) return error.JobPoisoned;
    if (comptime @hasDecl(@TypeOf(commands.*), "requireBatchedOracles")) {
        if (commands.batched_oracles) try commands.requireBatchedOracles();
    }
    if (input.oracles.len == 0 or input.oracles.len > abi.batch_max_oracles or work.oracles.len != input.oracles.len) return error.InvalidGeometry;
    var variables: [abi.batch_max_oracles]u32 = undefined;
    var largest: u32 = 0;
    var reservations = S.ReservationSet(8 + 10 * abi.batch_max_oracles){};
    for (input.oracles, 0..) |input_oracle, j| {
        const n = input_oracle.count;
        if (n < 2 or n > 1 << 28 or !std.math.isPowerOfTwo(n)) return error.InvalidGeometry;
        variables[j] = std.math.log2_int(u32, n) - 1;
        largest = @max(largest, variables[j]);
        try reservations.fraction(commands.context, input_oracle, n, false);
        const o = work.oracles[j];
        try reservations.slice(commands.context, o.terminal_mask, 32, true);
        if (variables[j] != 0) {
            try reservations.fraction(commands.context, o.banks[0], n / 2, true);
            if (variables[j] > 1) try reservations.fraction(commands.context, o.banks[1], n / 4, true);
            const groups = (n / 4 + 127) / 128;
            try reservations.plane(commands.context, o.scratch_a, 2 * groups, 8, true);
            try reservations.plane(commands.context, o.scratch_b, 2 * groups, 8, true);
            try reservations.plane(commands.context, o.sums, 2, 8, true);
        }
    }
    try reservations.slice(commands.context, input.lambda, 8, false);
    try reservations.slice(commands.context, input.alpha, 8, false);
    try reservations.slice(commands.context, input.claims, 8 * input.oracles.len, false);
    try reservations.slice(commands.context, input.seed, 9, false);
    try reservations.slice(commands.context, work.state, abi.batch_state_words, true);
    if (largest != 0) {
        try reservations.slice(commands.context, input.point, 8 * largest, false);
        try reservations.slice(commands.context, work.records, largest * abi.round_record_words, true);
        try reservations.plane(commands.context, work.eq, @as(u32, 1) << @intCast(largest - 1), 8, true);
    }
    var descriptors: [abi.batch_max_oracles]R.BatchOracle = undefined;
    var current: [abi.batch_max_oracles]R.Fraction = undefined;
    var folds: [abi.batch_max_oracles]u32 = @splat(0);
    for (input.oracles, 0..) |oracle, j| {
        current[j] = oracle;
        descriptors[j] = .{ .variables = variables[j], .raw = if (variables[j] == 0) null else work.oracles[j].sums };
    }
    const active = descriptors[0..input.oracles.len];
    try commands.initBatch(work.state, input.seed, input.claims, input.alpha, active, largest);
    if (largest != 0) try commands.eq(input.point, largest, work.eq);
    for (0..largest) |round| {
        const remaining = largest - @as(u32, @intCast(round));
        if (comptime @hasDecl(@TypeOf(commands.*), "sumBatch")) {
            if (commands.batched_oracles) {
                var jobs: [abi.batch_max_oracles]R.BatchSum = undefined;
                var count: usize = 0;
                for (work.oracles, 0..) |o, j| {
                    if (variables[j] < remaining) continue;
                    jobs[count] = .{ .input = current[j], .a = o.scratch_a, .b = o.scratch_b, .output = o.sums };
                    count += 1;
                }
                try commands.sumBatch(jobs[0..count], work.eq, input.lambda);
            } else for (work.oracles, 0..) |o, j| {
                if (variables[j] < remaining) continue;
                try commands.sum(current[j], work.eq, input.lambda, o.scratch_a, o.scratch_b, o.sums);
            }
        } else for (work.oracles, 0..) |o, j| {
            if (variables[j] < remaining) continue;
            try commands.sum(current[j], work.eq, input.lambda, o.scratch_a, o.scratch_b, o.sums);
        }
        const record = try work.records.sub(round * abi.round_record_words, abi.round_record_words);
        try commands.batchRound(work.state, active, largest, @intCast(round), input.point, record);
        const challenge = try record.sub(32, 8);
        var fold_jobs: [abi.batch_max_oracles]R.BatchFold = undefined;
        var active_folds: usize = 0;
        for (work.oracles, 0..) |o, j| {
            if (variables[j] < remaining) continue;
            var next = o.banks[folds[j] % 2];
            folds[j] += 1;
            next.count = current[j].count / 2;
            fold_jobs[active_folds] = .{ .input = current[j], .output = next };
            active_folds += 1;
            current[j] = next;
        }
        if (comptime @hasDecl(@TypeOf(commands.*), "foldBatch")) {
            if (commands.batched_oracles) try commands.foldBatch(fold_jobs[0..active_folds], challenge) else for (fold_jobs[0..active_folds]) |job| try commands.fold(job.input, challenge, job.output);
        } else for (fold_jobs[0..active_folds]) |job| try commands.fold(job.input, challenge, job.output);
    }
    for (work.oracles, 0..) |o, j| try commands.packBatchMask(current[j], o.terminal_mask);
    return .{ .rounds = largest, .oracles = input.oracles.len, .state = work.state, .records = try work.records.sub(0, largest * abi.round_record_words) };
}
