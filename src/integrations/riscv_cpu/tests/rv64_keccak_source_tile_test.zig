const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const L = K.layout;
const M = core.fields.m31.M31;
const renderer = K.trace.source_render;
const F = @import("rv64_keccak_proof_test.zig");

fn compareNative(trace: *const K.trace.Trace, inputs: []const K.trace.State, first: u32) !void {
    const a = std.testing.allocator;
    const expected = try a.alloc(M, trace.main.len);
    defer a.free(expected);
    try renderer.testing.scatter(trace.metadata, expected, trace.log_size);
    try std.testing.expectEqualSlices(M, expected, trace.main);
    // The retained metadata projection is independently anchored by input/output
    // reference permutations and the existing all-round native residual gates.
    for (inputs, 0..) |input, i| {
        const row = trace.mainRow(i / 2 * L.ROWS_PER_PAIR + i % 2);
        for (0..L.STATE) |bit| try std.testing.expectEqual(@as(u32, @intCast((input[bit / 64] >> @as(u6, @intCast(bit % 64))) & 1)), row[bit].v);
        try std.testing.expectEqual(first + @as(u32, @intCast(i / 2 * 2)), row[L.BASE_ID].v);
        const output = F.reference(input);
        const last = trace.mainRow(i / 2 * L.ROWS_PER_PAIR + 27 + i % 2);
        for (0..L.STATE) |bit| try std.testing.expectEqual(@as(u32, @intCast((output[bit / 64] >> @as(u6, @intCast(bit % 64))) & 1)), last[bit].v);
    }
}
test "Keccak physical source tiles preserve empty odd even padding and high IDs" {
    const a = std.testing.allocator;
    var inputs: [17]K.trace.State = undefined;
    for (&inputs, 0..) |*state, i| state.* = F.inputState(i);
    for ([_]usize{ 0, 1, 2, 3, 16, 17 }) |count| {
        const first: u32 = core.fields.m31.Modulus - @as(u32, @intCast(@max(count, 1)));
        var trace = try K.trace.Trace.initWithOptions(a, inputs[0..count], first, 9, .{});
        defer trace.deinit();
        try compareNative(&trace, inputs[0..count], first);
        const poison = try a.alloc(M, trace.main.len);
        defer a.free(poison);
        @memset(poison, M.fromCanonical(71));
        try renderer.render(trace.metadata, poison, trace.log_size, null);
        try std.testing.expectEqualSlices(M, trace.main, poison);
    }
}
test "Keccak physical source tiles use bounded 1 3 8 16 worker waves and busy-pool fallback" {
    const a = std.testing.allocator;
    const inputs = [_]K.trace.State{ F.inputState(0), F.inputState(1), F.inputState(2) };
    var serial = try K.trace.Trace.initWithOptions(a, &inputs, 1, 9, .{});
    defer serial.deinit();
    const counts = try K.interaction.Counts.fromTrace(&serial);
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = renderer.MIN_STACK });
        defer pool.deinit();
        var trace = try K.trace.Trace.initWithOptions(a, &inputs, 1, 9, .{ .pool = &pool });
        defer trace.deinit();
        try std.testing.expectEqualSlices(M, serial.main, trace.main);
        try std.testing.expectEqualSlices(M, serial.fixed, trace.fixed);
        try std.testing.expectEqualDeep(serial.metadata, trace.metadata);
        const actual = try K.interaction.Counts.fromTrace(&trace);
        try std.testing.expectEqualDeep(counts, actual);
        var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
        defer lease.deinit();
        try renderer.render(trace.metadata, trace.main, trace.log_size, &pool);
        try std.testing.expectEqualSlices(M, serial.main, trace.main);
    }
}
fn allocationCase(a: std.mem.Allocator) !void {
    const inputs = [_]K.trace.State{ F.inputState(1), F.inputState(3), F.inputState(7) };
    var trace = try K.trace.Trace.initWithOptions(a, &inputs, 1, 8, .{});
    defer trace.deinit();
}
test "Keccak physical source tiles drain partial submissions and preserve source OOM custody" {
    const a = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = renderer.MIN_STACK });
    defer pool.deinit();
    const input = [_]K.trace.State{F.inputState(1)};
    for (0..2) |after| {
        renderer.testing.fail_after_submissions = after;
        defer renderer.testing.fail_after_submissions = null;
        try std.testing.expectError(error.InjectedKeccakSourceSubmissionFailure, K.trace.Trace.initWithOptions(a, &input, 1, 8, .{ .pool = &pool }));
        // The reservation and every previously submitted job must be retired.
        var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
        lease.deinit();
    }
    try std.testing.expectError(error.InvalidKeccakMainPhase, renderer.render(&.{}, &.{}, 100, null));
    var good = try K.trace.Trace.initWithOptions(a, &input, 1, 8, .{});
    defer good.deinit();
    const alias: [*]K.trace.PackedRow = @ptrCast(@alignCast(good.main.ptr));
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, renderer.render(alias[0..1], good.main, 8, null));
    var small_pool: engine.work_pool.WorkPool = .{};
    try small_pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = renderer.MIN_STACK / 2 });
    defer small_pool.deinit();
    try std.testing.expectError(error.InvalidKeccakSourceWorkerStack, renderer.render(good.metadata, good.main, 8, &small_pool));
}
