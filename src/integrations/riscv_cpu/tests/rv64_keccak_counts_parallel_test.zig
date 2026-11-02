const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const L = K.layout;
const F = @import("rv64_keccak_proof_test.zig");
const a = std.testing.allocator;
// Retain valid native recipes without constructing a gigabyte-wide MAIN.
// Repeated facts are allowed; every pair still carries its distinct call IDs.
fn retainedFixture() !K.trace.Trace {
    const calls: u32 = 4531;
    const first = core.fields.m31.Modulus - calls;
    const inputs = [_]K.trace.State{ F.inputState(0), F.inputState(1) };
    var pair = try K.trace.Trace.initWithOptions(a, &inputs, first, 5, .{});
    defer pair.deinit();
    var odd = try K.trace.Trace.initWithOptions(a, inputs[0..1], first, 5, .{});
    defer odd.deinit();
    const log = try L.logSize(calls);
    const fixed = try K.trace.fixedColumnsForLog(a, log);
    errdefer a.free(fixed);
    const pairs = (calls + 1) / 2;
    const metadata = try a.alloc(K.trace.PackedRow, pairs * L.ROWS_PER_PAIR);
    for (0..pairs) |i| {
        const source = if (i + 1 == pairs) odd.metadata else pair.metadata;
        const destination = metadata[i * L.ROWS_PER_PAIR ..][0..L.ROWS_PER_PAIR];
        @memcpy(destination, source);
        for (destination) |*row| row.id = first + @as(u32, @intCast(2 * i));
    }
    return .{ .allocator = a, .log_size = log, .calls = calls, .first_call_id = first, .fixed = fixed, .main = &.{}, .metadata = metadata };
}
test "Keccak private histograms preserve exact serial counts at 1 3 8 16 workers and busy fallback" {
    var trace = try retainedFixture();
    defer trace.deinit();
    const expected = try K.interaction.Counts.serial(&trace);
    const mass = try L.lookupMass(trace.calls);
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 256 * 1024 });
        defer pool.deinit();
        var profile = K.interaction.CountProfile{};
        const actual = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool, .profile = &profile });
        try std.testing.expectEqualDeep(expected, actual);
        try std.testing.expectEqual(workers, profile.workers);
        try std.testing.expectEqual(mass.chi, profile.chi_queries);
        try std.testing.expectEqual(mass.xor5, profile.xor5_queries);
        if (workers == 16) {
            var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(16));
            defer lease.deinit();
            const fallback = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool, .profile = &profile });
            try std.testing.expectEqualDeep(expected, fallback);
            try std.testing.expectEqual(@as(usize, 1), profile.workers);
        }
    }
}
fn allocationCase(allocator: std.mem.Allocator, trace: *const K.trace.Trace, pool: *engine.work_pool.WorkPool) !void {
    _ = try K.interaction.Counts.fromTraceWithOptions(trace, .{ .allocator = allocator, .pool = pool });
}
test "Keccak private histograms drain failed submissions and clean every private allocation failure" {
    var trace = try retainedFixture();
    defer trace.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 256 * 1024 });
    defer pool.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &trace, &pool });
    for ([_]usize{ 0, 1, 14 }) |after| {
        try std.testing.expectError(error.InjectedNativeFillSubmissionFailure, K.interaction.Counts.testing.failSubmission(&trace, .{ .pool = &pool }, after));
        var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(16));
        lease.deinit();
    }
    const actual = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool });
    const expected = try K.interaction.Counts.serial(&trace);
    try std.testing.expectEqualDeep(expected, actual);
}
test "Keccak private histograms retain malformed tuple errors gate semantics and retry without MAIN" {
    var trace = try retainedFixture();
    defer trace.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 256 * 1024 });
    defer pool.deinit();
    const bit = trace.metadata[2].state_a[0];
    trace.metadata[2].state_a[0] ^= 1;
    try std.testing.expectError(error.InvalidTuple, K.interaction.Counts.serial(&trace));
    try std.testing.expectError(error.InvalidTuple, K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool }));
    trace.metadata[2].state_a[0] = bit;
    const id = trace.metadata[2].id;
    trace.metadata[2].id = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidKeccakMetadata, K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool }));
    trace.metadata[2].id = id;
    // A retained native hint is not authority: preserve exactly the old gate,
    // even for inconsistent main flags which the unchanged AIR rejects.
    trace.metadata[2].flags = 0;
    const expected = try K.interaction.Counts.serial(&trace);
    const actual = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool });
    try std.testing.expectEqualDeep(expected, actual);
    for (trace.metadata) |*row| row.flags = 0;
    const inactive = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = &pool });
    for (inactive.chi) |v| try std.testing.expectEqual(@as(u64, 0), v);
    for (inactive.xor5) |v| try std.testing.expectEqual(@as(u64, 0), v);
}
