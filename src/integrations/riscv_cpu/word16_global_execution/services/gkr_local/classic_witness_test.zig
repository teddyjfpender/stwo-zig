const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("classic_witness.zig");
const P = @import("classic_witness_parallel.zig");
const Numeric = @import("classic_witness_numeric.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn dense(i: usize) O {
    var coords: [8]M = undefined;
    for (&coords, 0..) |*v, c| v.* = M.fromCanonical(@intCast((i * 7919 + c * 997 + 3) % 1048573));
    return O.fromM31Array(coords);
}
const Provider = struct {
    pub const PARALLEL_SAFE = true;
    metadata: []const M,
    zero_weight: bool = false,
    pole: ?usize = null,
    failure: ?usize = null,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []C.Numerator) !void {
        if (self.failure == logical) return error.InjectedProviderFailure;
        for (d, n, 0..) |*den, *num, q| {
            den.* = if (self.pole == logical and q == 0) O.zero() else dense(logical * 997 + q);
            num.* = if (self.zero_weight) .{ .base = M.zero() } else switch (q % 3) {
                0 => .{ .base = self.metadata[logical % self.metadata.len] },
                1 => .{ .base = M.one().neg() },
                else => .{ .secure = dense(logical * 31 + q + 7) },
            };
        }
    }
};
const Serial = struct {
    value: Provider,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []C.Numerator) !void {
        return self.value.fill(logical, d, n);
    }
};
fn parity(log: u32, groups: []const C.Group, workers: usize, zero: bool) !void {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var scope = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scope.deinit();
    var metadata = [_]M{ M.zero(), M.one(), M.one().neg(), M.fromCanonical(19) };
    const before = metadata;
    const provider = Provider{ .metadata = &metadata, .zero_weight = zero };
    var expected = try C.Witness.initTruth(a, log, groups, Serial{ .value = provider }, 1 << 30);
    defer expected.deinit();
    var actual = try C.Witness.initTruth(a, log, groups, provider, 1 << 30);
    defer actual.deinit();
    try std.testing.expectEqualDeep(expected.claimSlice(), actual.claimSlice());
    try std.testing.expectEqualSlices(M, expected.data, actual.data);
    try std.testing.expectEqualDeep(before, metadata);
}
test "classic parallel physical scatter and two-wave prefix preserve all cells claims and immutable input" {
    for ([_]usize{ 1, 3, 7, 16 }) |workers| {
        try parity(10, &.{ .{ .inverses = 1 }, .{ .inverses = 2 }, .{ .inverses = 3 }, .{ .inverses = 5 } }, workers, false);
        try parity(7, &.{.{ .inverses = 640 }}, workers, false);
    }
    try parity(8, &.{ .{ .inverses = 3 }, .{ .inverses = 7 } }, 3, true);
}
test "classic witness plan counts every tile and adapts to exact legacy scratch cap" {
    const groups = [_]C.Group{.{ .inverses = 640 }};
    const output = (@as(usize, 1) << 18) * 8 * 641 * @sizeOf(M);
    const old_scratch = 256 * 640 * (2 * @sizeOf(O) + @sizeOf(C.Numerator));
    const plan = try P.Plan.init(18, &groups, output + old_scratch, 16);
    try std.testing.expectEqual(@as(usize, 16), plan.jobs);
    try std.testing.expect(plan.output_bytes + plan.scratch_bytes <= output + old_scratch);
    try std.testing.expect(plan.scratch_bytes <= P.MAX_SCRATCH_BYTES);
    try std.testing.expectEqual(@as(usize, 0), plan.chunk_rows % core.fields.m31.PACK_WIDTH);
    try std.testing.expect(plan.scratch_bytes <= try C.scratchByteUpperBound(18, 640));
    try std.testing.expectError(error.ClassicWitnessBudgetExceeded, P.Plan.init(18, &groups, output + 1, 16));
    try std.testing.expectError(error.InvalidClassicWitnessShape, P.Plan.init(64, &groups, 1 << 30, 16));
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var scope = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scope.deinit();
    const small_output = (@as(usize, 1) << 10) * 8 * 641 * @sizeOf(M);
    const limit = small_output + try C.scratchByteUpperBound(10, 640);
    var tracker = engine.host_budget_allocator.HostBudgetAllocator.init(a, limit);
    var metadata = [_]M{M.one()};
    var actual = try C.Witness.initTruth(tracker.allocator(), 10, &groups, Provider{ .metadata = &metadata }, limit);
    try std.testing.expect(tracker.peak_live_bytes <= limit);
    actual.deinit();
    try std.testing.expectEqual(@as(usize, 0), tracker.live_bytes);
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    var metadata = [_]M{ M.one(), M.one().neg() };
    var witness = try C.Witness.initTruth(allocator, 7, &.{ .{ .inverses = 3 }, .{ .inverses = 5 } }, Provider{ .metadata = &metadata }, 1 << 25);
    defer witness.deinit();
}
test "classic pooled tile allocation failures clean every partially initialized owner" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var scope = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scope.deinit();
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
test "classic zero-weight poles and provider errors reject after joined workers" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var scope = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scope.deinit();
    var m = [_]M{M.one()};
    try std.testing.expectError(error.DivisionByZero, C.Witness.initTruth(a, 9, &.{.{ .inverses = 3 }}, Provider{ .metadata = &m, .zero_weight = true, .pole = 17 }, 1 << 25));
    try std.testing.expectError(error.InjectedProviderFailure, C.Witness.initTruth(a, 9, &.{.{ .inverses = 3 }}, Provider{ .metadata = &m, .failure = 33 }, 1 << 25));
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    defer lease.deinit();
    var fallback = try C.Witness.initTruth(a, 7, &.{.{ .inverses = 3 }}, Provider{ .metadata = &m }, 1 << 25);
    defer fallback.deinit();
}
test "non-opted stateful providers retain serial logical order" {
    const Stateful = struct {
        next: *usize,
        pub fn fill(self: @This(), logical: usize, d: []O, n: []C.Numerator) !void {
            if (logical != self.next.*) return error.InvalidProviderOrder;
            self.next.* += 1;
            for (d, n) |*den, *num| {
                den.* = dense(logical);
                num.* = .{ .base = M.one() };
            }
        }
    };
    var next: usize = 0;
    var witness = try C.Witness.init(a, 5, &.{.{ .inverses = 1 }}, Stateful{ .next = &next }, 1 << 20);
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 32), next);
}
test "packed classic inverse contributions and dots match scalar with tails and strict poles" {
    for ([_]usize{ 0, 1, 3, 4, 5, 16, 17, 512 }) |count| {
        const input = try a.alloc(O, count);
        defer a.free(input);
        const expected = try a.alloc(O, count);
        defer a.free(expected);
        const actual = try a.alloc(O, count);
        defer a.free(actual);
        for (input, 0..) |*v, i| v.* = dense(i);
        try core.fields.batchInverseInPlace(O, input, expected);
        try Numeric.batchInverse(input, actual);
        try std.testing.expectEqualDeep(expected, actual);
        const nums = try a.alloc(C.Numerator, count);
        defer a.free(nums);
        for (nums, 0..) |*v, i| v.* = if (i % 2 == 0) .{ .base = M.one().neg() } else .{ .secure = dense(i + 31) };
        const contribution = try a.alloc(O, count);
        defer a.free(contribution);
        Numeric.contributions(nums, actual, contribution);
        var total = O.zero();
        for (nums, actual, contribution) |n, inv, value| {
            try std.testing.expectEqualDeep(n.multiply(inv), value);
            total = total.add(value);
        }
        try std.testing.expectEqualDeep(total, Numeric.sum(contribution));
        if (count != 0) {
            input[count - 1] = O.zero();
            try std.testing.expectError(error.DivisionByZero, Numeric.batchInverse(input, actual));
        }
    }
}

test "optional classic640 inverse kernel A B" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_BENCH_CLASSIC_WITNESS")) return;
    var metadata = [_]M{ M.zero(), M.one(), M.one().neg(), M.fromCanonical(19) };
    const provider = Provider{ .metadata = &metadata };
    const groups = [_]C.Group{.{ .inverses = 640 }};
    var timer = try std.time.Timer.start();
    var reference = try C.Witness.initTruth(a, 12, &groups, Serial{ .value = provider }, 1 << 30);
    defer reference.deinit();
    const serial_ns = timer.read();
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
        defer pool.deinit();
        var scope = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer scope.deinit();
        const plan = try P.Plan.init(12, &groups, 1 << 30, workers);
        timer.reset();
        var actual = try C.Witness.initTruth(a, 12, &groups, provider, 1 << 30);
        defer actual.deinit();
        const elapsed = timer.read();
        try std.testing.expectEqualDeep(reference.claimSlice(), actual.claimSlice());
        try std.testing.expectEqualSlices(M, reference.data, actual.data);
        std.debug.print("CLASSIC_WITNESS_KERNEL log=12 inverses=640 workers={d} serial_ns={d} optimized_ns={d} scratch_bytes={d} chunk_rows={d} output_bytes={d} speedup={d:.3} exact=true\n", .{ workers, serial_ns, elapsed, plan.scratch_bytes, plan.chunk_rows, plan.output_bytes, @as(f64, @floatFromInt(serial_ns)) / @as(f64, @floatFromInt(elapsed)) });
    }
}
