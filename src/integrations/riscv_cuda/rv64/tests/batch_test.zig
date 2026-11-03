const std = @import("std");
const B = @import("../batch.zig");
const R = @import("../resident.zig");
const Abi = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Context = struct {
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, s: Slice, n: usize) ![*]T {
        if (s.owner != 1 or s.generation != 2 or n > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
const Commands = struct {
    context: *Context,
    poisoned: bool = false,
    batched_oracles: bool = false,
    sum_batches: usize = 0,
    fold_batches: usize = 0,
    calls: usize = 0,
    sums: [16]u32 = undefined,
    sum_count: usize = 0,
    rounds: u32 = 0,
    masks: u32 = 0,
    fail_sum: bool = false,
    pub fn initBatch(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, descriptors: []const R.BatchOracle, variables: u32) !void {
        try std.testing.expectEqual(@as(usize, 3), descriptors.len);
        var largest: u32 = 0;
        for (descriptors) |d| largest = @max(largest, d.variables);
        try std.testing.expectEqual(largest, variables);
        try std.testing.expectEqual(@as(u32, 0), descriptors[2].variables);
        try std.testing.expect(descriptors[2].raw == null);
        s.calls += 1;
    }
    pub fn eq(s: *@This(), _: Slice, _: u32, _: R.Plane) !void {
        s.calls += 1;
    }
    pub fn sum(s: *@This(), input: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, _: R.Plane) !void {
        s.calls += 1;
        if (s.fail_sum) {
            s.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        s.sums[s.sum_count] = input.count;
        s.sum_count += 1;
    }
    pub fn sumBatch(self: *@This(), jobs: []const R.BatchSum, eq_values: R.Plane, lambda: Slice) !void {
        self.sum_batches += 1;
        for (jobs) |job| {
            try std.testing.expectEqual(jobs[0].input.count, job.input.count);
            try self.sum(job.input, eq_values, lambda, job.a, job.b, job.output);
        }
    }
    pub fn foldBatch(self: *@This(), jobs: []const R.BatchFold, challenge: Slice) !void {
        self.fold_batches += 1;
        for (jobs) |job| {
            try std.testing.expectEqual(jobs[0].input.count, job.input.count);
            try self.fold(job.input, challenge, job.output);
        }
    }
    pub fn batchRound(s: *@This(), _: Slice, _: []const R.BatchOracle, _: u32, expected: u32, _: Slice, _: Slice) !void {
        try std.testing.expectEqual(s.rounds, expected);
        s.rounds += 1;
        s.calls += 1;
    }
    pub fn fold(s: *@This(), input: R.Fraction, _: Slice, output: R.Fraction) !void {
        try std.testing.expectEqual(input.count / 2, output.count);
        s.calls += 1;
    }
    pub fn packBatchMask(s: *@This(), input: R.Fraction, _: Slice) !void {
        try std.testing.expectEqual(@as(u32, 2), input.count);
        s.masks += 1;
        s.calls += 1;
    }
};
const Factory = struct {
    address: usize = 4096,
    fn slice(s: *@This(), n: usize) Slice {
        const p = Slice{ .address = s.address, .len = n, .owner = 1, .generation = 2 };
        s.address += (n * 4 + 255) & ~@as(usize, 255);
        return p;
    }
    fn plane(s: *@This(), n: u32, coords: u32) R.Plane {
        return .{ .data = s.slice(@as(usize, n) * coords), .stride = n, .coordinates = coords };
    }
    fn fraction(s: *@This(), n: u32, coords: u32) R.Fraction {
        return .{ .n = s.plane(n, coords), .d = s.plane(n, 8), .count = n };
    }
};
const Fixture = struct {
    inputs: [3]R.Fraction,
    work: [3]B.OracleWorkspace,
    shared: B.Workspace,
    request: B.Input,
    fn init() @This() {
        var f = Factory{};
        var out: @This() = undefined;
        for ([_]u32{ 4, 16, 2 }, 0..) |n, i| {
            out.inputs[i] = f.fraction(n, if (i % 2 == 0) 1 else 8);
            out.work[i] = .{
                .banks = .{ f.fraction(n / 2, 8), f.fraction(@max(1, n / 4), 8) },
                .scratch_a = f.plane(2, 8),
                .scratch_b = f.plane(2, 8),
                .sums = f.plane(2, 8),
                .terminal_mask = f.slice(32),
            };
        }
        // Pointers are rebound after returning this value; no self-referential move.
        out.request = .{ .oracles = &.{}, .point = f.slice(24), .lambda = f.slice(8), .alpha = f.slice(8), .claims = f.slice(24), .seed = f.slice(9) };
        out.shared = .{ .oracles = &.{}, .eq = f.plane(4, 8), .state = f.slice(Abi.batch_state_words), .records = f.slice(3 * Abi.round_record_words) };
        return out;
    }
    fn bind(self: *@This()) void {
        self.request.oracles = &self.inputs;
        self.shared.oracles = &self.work;
    }
};
test "mixed batch preflights late aliases and retired banks before the first GPU mutation" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context };
    const mask = fixture.work[2].terminal_mask;
    fixture.work[2].terminal_mask.address = fixture.inputs[0].n.data.address;
    try std.testing.expectError(error.OverlappingWorkspace, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    fixture.work[2].terminal_mask = mask;
    fixture.work[1].banks[1].d.data.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    fixture.work[1].banks[1].d.data.generation = 2;
    fixture.work[1].banks[0].n.coordinates = 1;
    try std.testing.expectError(error.InvalidGeometry, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
}
test "mixed batch activates oracle suffixes and rejects incomplete terminal transcript metadata" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context };
    const queued = try B.enqueue(&commands, fixture.request, fixture.shared);
    try std.testing.expectEqual(@as(u32, 3), queued.rounds);
    try std.testing.expectEqualSlices(u32, &.{ 16, 8, 4, 4 }, commands.sums[0..commands.sum_count]);
    try std.testing.expectEqual(@as(u32, 3), commands.masks);
    var header = B.Header{ .digest = @splat(0), .draws = 1, .next_round = 3, .status = 0, .variables = 3, .claim = @splat(0), .correction = .{ 1, 0, 0, 0, 0, 0, 0, 0 }, .prefix = .{ 1, 0, 0, 0, 0, 0, 0, 0 }, .reserved = @splat(0), .oracles = 3, .reserved2 = @splat(0) };
    try header.validate(queued);
    header.status = 1;
    try std.testing.expectError(error.InvalidBatchTranscript, header.validate(queued));
    header.status = 0;
    header.oracles = 2;
    try std.testing.expectError(error.InvalidBatchTranscript, header.validate(queued));
    header.oracles = 3;
    header.next_round = 2;
    try std.testing.expectError(error.InvalidBatchTranscript, header.validate(queued));
    header.next_round = 3;
    header.prefix[0] = 2147483647;
    try std.testing.expectError(error.InvalidBatchTranscript, header.validate(queued));
}
test "mixed batch aborts after a failed enqueue and keeps all owners borrowed for joined teardown" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context, .fail_sum = true };
    try std.testing.expectError(error.CudaEnqueueFailed, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expect(commands.poisoned);
    try std.testing.expectEqual(@as(u32, 0), commands.rounds);
    try std.testing.expectEqual(@as(u32, 0), commands.masks);
    const before = commands.calls;
    try std.testing.expectError(error.JobPoisoned, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(before, commands.calls);
}

test "constant mixed batch requires no point, Eq or round workspace" {
    var fixture = Fixture.init();
    fixture.bind();
    for (&fixture.inputs) |*input| input.count = 2;
    fixture.request.point.generation = 0;
    fixture.shared.records.generation = 0;
    fixture.shared.eq.data.generation = 0;
    var context = Context{};
    var commands = Commands{ .context = &context };
    const queued = try B.enqueue(&commands, fixture.request, fixture.shared);
    try std.testing.expectEqual(@as(u32, 0), queued.rounds);
    try std.testing.expectEqual(@as(usize, 0), queued.records.len);
    try std.testing.expectEqual(@as(usize, 4), commands.calls);
    try std.testing.expectEqual(@as(usize, 0), commands.sum_count);
}

test "mixed batch groups only equal-height active oracles without padding or transcript changes" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var serial = Commands{ .context = &context };
    var batched = Commands{ .context = &context, .batched_oracles = true };
    const before = try B.enqueue(&serial, fixture.request, fixture.shared);
    const after = try B.enqueue(&batched, fixture.request, fixture.shared);
    try std.testing.expectEqual(before.rounds, after.rounds);
    try std.testing.expectEqual(serial.rounds, batched.rounds);
    try std.testing.expectEqualSlices(u32, serial.sums[0..serial.sum_count], batched.sums[0..batched.sum_count]);
    try std.testing.expectEqual(@as(usize, 3), batched.sum_batches);
    try std.testing.expectEqual(@as(usize, 3), batched.fold_batches);
    try std.testing.expectEqual(@as(u32, 3), batched.masks);
}
