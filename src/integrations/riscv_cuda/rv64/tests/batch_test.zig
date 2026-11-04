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
    tail_enabled: bool = false,
    fold_sum_enabled: bool = false,
    fold_sum_available: bool = true,
    fail_fold_sum: bool = false,
    fold_sum_batches: usize = 0,
    fused_base_seen: bool = false,
    fused_secure_seen: bool = false,
    raw_addresses: [3]usize = @splat(0),
    raw_ready: [3]bool = @splat(false),
    tail_count: usize = 0,
    tail_first: u32 = 0,
    fail_tail: bool = false,
    sum_batches: usize = 0,
    fold_batches: usize = 0,
    calls: usize = 0,
    sums: [16]u32 = undefined,
    sum_count: usize = 0,
    rounds: u32 = 0,
    masks: u32 = 0,
    fail_sum: bool = false,
    pub fn supportsBatchFoldSum(self: *@This()) bool {
        return self.batched_oracles and self.fold_sum_enabled and self.fold_sum_available;
    }
    fn markRaw(self: *@This(), output: R.Plane) !void {
        for (self.raw_addresses, 0..) |address, i| if (address == output.data.address) {
            try std.testing.expect(!self.raw_ready[i]);
            self.raw_ready[i] = true;
            return;
        };
        return error.UnknownRawOutput;
    }
    pub fn foldSumBatch(self: *@This(), jobs: []const R.BatchFoldSum, _: Slice, _: R.Plane, _: Slice) !void {
        self.calls += 1;
        self.fold_sum_batches += 1;
        if (self.fail_fold_sum) {
            self.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        for (jobs) |job| {
            try std.testing.expect(job.input.count >= 8);
            try std.testing.expectEqual(jobs[0].input.count, job.input.count);
            try std.testing.expectEqual(job.input.count / 2, job.folded.count);
            try std.testing.expectEqual(@as(u32, 8), job.folded.n.coordinates);
            if (job.input.n.coordinates == 1) self.fused_base_seen = true else self.fused_secure_seen = true;
            self.sums[self.sum_count] = job.folded.count;
            self.sum_count += 1;
            try self.markRaw(job.output);
        }
    }
    pub fn supportsBatchTail(self: *@This()) bool {
        return self.batched_oracles and self.tail_enabled;
    }
    pub fn batchTail(self: *@This(), oracles: []const R.BatchTailOracle, job: R.BatchTail) !void {
        self.calls += 1;
        if (self.fail_tail) {
            self.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        try std.testing.expectEqual(@as(usize, 3), oracles.len);
        try std.testing.expectEqual(self.rounds, job.first);
        try std.testing.expect(job.variables - job.first <= 4);
        for (oracles) |oracle| {
            const expected = @as(u32, 2) << @as(u5, @intCast(@min(oracle.variables, job.variables - job.first)));
            try std.testing.expectEqual(expected, oracle.input.count);
            if (oracle.variables == 0) try std.testing.expect(oracle.output == null) else try std.testing.expectEqual(expected / 2, oracle.output.?.count);
        }
        self.tail_count += 1;
        self.tail_first = job.first;
        self.rounds = job.variables;
        self.masks += @intCast(oracles.len);
    }
    pub fn initBatch(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, descriptors: []const R.BatchOracle, variables: u32) !void {
        try std.testing.expectEqual(@as(usize, 3), descriptors.len);
        var largest: u32 = 0;
        s.raw_ready = @splat(false);
        for (descriptors, 0..) |d, i| {
            largest = @max(largest, d.variables);
            s.raw_addresses[i] = if (d.raw) |raw| raw.data.address else 0;
        }
        try std.testing.expectEqual(largest, variables);
        try std.testing.expectEqual(@as(u32, 0), descriptors[2].variables);
        try std.testing.expect(descriptors[2].raw == null);
        s.calls += 1;
    }
    pub fn eq(s: *@This(), _: Slice, _: u32, _: R.Plane) !void {
        s.calls += 1;
    }
    pub fn sum(s: *@This(), input: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, output: R.Plane) !void {
        s.calls += 1;
        if (s.fail_sum) {
            s.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        try s.markRaw(output);
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
    pub fn batchRound(s: *@This(), _: Slice, descriptors: []const R.BatchOracle, largest: u32, expected: u32, _: Slice, _: Slice) !void {
        try std.testing.expectEqual(s.rounds, expected);
        for (descriptors, 0..) |d, i| if (d.variables >= largest - expected) {
            try std.testing.expect(s.raw_ready[i]);
            s.raw_ready[i] = false;
        };
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
        return initSized(.{ 4, 16, 2 });
    }
    fn initSized(counts: [3]u32) @This() {
        var f = Factory{};
        var out: @This() = undefined;
        for (counts, 0..) |n, i| {
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
        const largest: u32 = std.math.log2_int(u32, @max(counts[0], @max(counts[1], counts[2]))) - 1;
        out.request = .{ .oracles = &.{}, .point = f.slice(8 * largest), .lambda = f.slice(8), .alpha = f.slice(8), .claims = f.slice(24), .seed = f.slice(9) };
        out.shared = .{ .oracles = &.{}, .eq = f.plane(@as(u32, 1) << @as(u5, @intCast(largest - 1)), 8), .state = f.slice(Abi.batch_state_words), .records = f.slice(largest * Abi.round_record_words) };
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

test "batched oracle capability is optional and missing symbols fail before enqueue" {
    const Runtime = @import("../runtime_api.zig").Api;
    // Only capability fields are inspected here. No numerical call or handle
    // validation may read the unrelated function pointers in this test.
    var api: Runtime = undefined;
    api.stwo_rv64_batch_sum_on = null;
    api.stwo_rv64_batch_fold_on = null;
    var context = Context{};
    var commands = R.Commands(Context, Runtime){ .context = &context, .api = &api, .lane_index = 1 };
    try std.testing.expectError(error.MissingCudaBatchedOracleSymbol, commands.requireBatchedOracles());
    try std.testing.expect(!commands.poisoned);
    try std.testing.expectEqual(@as(u64, 0), commands.launches);
}

test "mixed persistent tail preserves sleeping oracles and avoids per-round dispatch" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context, .batched_oracles = true, .tail_enabled = true };
    const result = try B.enqueue(&commands, fixture.request, fixture.shared);
    try std.testing.expectEqual(@as(u32, 3), result.rounds);
    try std.testing.expectEqual(@as(usize, 1), commands.tail_count);
    try std.testing.expectEqual(@as(u32, 0), commands.tail_first);
    try std.testing.expectEqual(@as(u32, 3), commands.rounds);
    try std.testing.expectEqual(@as(u32, 3), commands.masks);
    try std.testing.expectEqual(@as(usize, 0), commands.sum_batches);
    try std.testing.expectEqual(@as(usize, 0), commands.fold_batches);
}
test "mixed persistent tail starts after the large round at the original record offset" {
    var fixture = Fixture.initSized(.{ 4, 64, 2 });
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context, .batched_oracles = true, .tail_enabled = true };
    const result = try B.enqueue(&commands, fixture.request, fixture.shared);
    try std.testing.expectEqual(@as(u32, 5), result.rounds);
    try std.testing.expectEqual(@as(u32, 1), commands.tail_first);
    try std.testing.expectEqual(@as(usize, 1), commands.sum_batches);
    try std.testing.expectEqual(@as(usize, 1), commands.fold_batches);
}
test "mixed persistent tail retains all-oracle preflight and poison semantics" {
    var fixture = Fixture.init();
    fixture.bind();
    var context = Context{};
    var commands = Commands{ .context = &context, .batched_oracles = true, .tail_enabled = true };
    fixture.work[2].terminal_mask.address = fixture.inputs[0].n.data.address;
    try std.testing.expectError(error.OverlappingWorkspace, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    fixture = Fixture.init();
    fixture.bind();
    commands.fail_tail = true;
    try std.testing.expectError(error.CudaEnqueueFailed, B.enqueue(&commands, fixture.request, fixture.shared));
    const calls = commands.calls;
    try std.testing.expectError(error.JobPoisoned, B.enqueue(&commands, fixture.request, fixture.shared));
    try std.testing.expectEqual(calls, commands.calls);
}

test "mixed fold-sum prefetch handles newly waking base oracles and terminal count4" {
    var f = Fixture.initSized(.{ 8, 64, 2 });
    f.bind();
    var ctx = Context{};
    var c = Commands{ .context = &ctx, .batched_oracles = true, .fold_sum_enabled = true };
    const out = try B.enqueue(&c, f.request, f.shared);
    try std.testing.expectEqual(@as(u32, 5), out.rounds);
    try std.testing.expectEqual(@as(usize, 4), c.fold_sum_batches);
    try std.testing.expectEqual(@as(usize, 2), c.sum_batches);
    try std.testing.expectEqual(@as(usize, 1), c.fold_batches);
    try std.testing.expect(c.fused_base_seen and c.fused_secure_seen);
    try std.testing.expectEqualSlices(u32, &.{ 64, 32, 16, 8, 8, 4, 4 }, c.sums[0..c.sum_count]);
    try std.testing.expectEqual(@as(u32, 3), c.masks);
}
test "mixed fold-sum missing capability preserves the original scheduling" {
    var f = Fixture.init();
    f.bind();
    var ctx = Context{};
    var c = Commands{ .context = &ctx, .batched_oracles = true, .fold_sum_enabled = true, .fold_sum_available = false };
    _ = try B.enqueue(&c, f.request, f.shared);
    try std.testing.expectEqual(@as(usize, 0), c.fold_sum_batches);
    try std.testing.expectEqual(@as(usize, 3), c.sum_batches);
    try std.testing.expectEqual(@as(usize, 3), c.fold_batches);
    try std.testing.expectEqualSlices(u32, &.{ 16, 8, 4, 4 }, c.sums[0..c.sum_count]);
}
test "mixed fold-sum retains all-oracle preflight and poisons failed submission" {
    var f = Fixture.init();
    f.bind();
    var ctx = Context{};
    var c = Commands{ .context = &ctx, .batched_oracles = true, .fold_sum_enabled = true };
    f.work[1].banks[1].d.data.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, B.enqueue(&c, f.request, f.shared));
    try std.testing.expectEqual(@as(usize, 0), c.calls);
    f = Fixture.init();
    f.bind();
    c.fail_fold_sum = true;
    try std.testing.expectError(error.CudaEnqueueFailed, B.enqueue(&c, f.request, f.shared));
    const before = c.calls;
    try std.testing.expectError(error.JobPoisoned, B.enqueue(&c, f.request, f.shared));
    try std.testing.expectEqual(before, c.calls);
}

test "batched fold-sum ABI is optional and unavailable kernels reject before enqueue" {
    const Runtime = @import("../runtime_api.zig").Api;
    var api: Runtime = undefined;
    api.stwo_rv64_batch_fold_sum_on = null;
    var ctx = Context{};
    var c = R.Commands(Context, Runtime){ .context = &ctx, .api = &api, .lane_index = 1, .batched_oracles = true, .batched_fold_sum = true };
    try std.testing.expect(!c.supportsBatchFoldSum());
    try std.testing.expectError(error.MissingCudaBatchedFoldSumSymbol, c.requireBatchedFoldSum());
    try std.testing.expect(!c.poisoned);
    try std.testing.expectEqual(@as(u64, 0), c.launches);
}
