const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const F = @import("rv64_keccak_proof_test.zig");
const Oracle = @import("rv64_keccak_interaction_oracle.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn challenges() K.equations.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b505246, 17 });
    return K.equations.Challenges.draw(&channel);
}
fn inputsFixture(inputs: []K.trace.State) void {
    for (inputs, 0..) |*state, i| state.* = F.inputState(3 + i * 7);
}
const stack = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
test "Keccak parallel prefixes exactly preserve old oracle all-row bytes at odd chunks and all budgets" {
    const cases = [_]struct { count: usize, log: u32 }{ .{ .count = 0, .log = 8 }, .{ .count = 1, .log = 8 }, .{ .count = 2, .log = 8 }, .{ .count = 3, .log = 8 }, .{ .count = 5, .log = 10 }, .{ .count = 11, .log = 8 } };
    for (cases) |case| {
        const inputs = try a.alloc(K.trace.State, case.count);
        defer a.free(inputs);
        inputsFixture(inputs);
        const first = core.fields.m31.Modulus - @as(u32, @intCast(@max(1, case.count)));
        var oracle = try K.trace.Trace.initWithLog(a, inputs, first, case.log);
        defer oracle.deinit();
        const expected = try Oracle.generate(&oracle, challenges());
        for ([_]usize{ 1, 3, 8, 16 }) |workers| {
            var pool: engine.work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = stack, .backing_allocator = a });
            defer pool.deinit();
            var trace = try K.trace.Trace.initWithLog(a, inputs, first, case.log);
            defer trace.deinit();
            try trace.releaseMain();
            const actual = try K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool });
            try std.testing.expect(actual.eql(expected));
            try std.testing.expectEqualSlices(M, oracle.interaction, trace.interaction);
            try std.testing.expectEqual(workers, pool.availableWorkers());
        }
    }
}
fn allocationCase(allocator: std.mem.Allocator, pool: *engine.work_pool.WorkPool) !void {
    const inputs = [_]K.trace.State{F.inputState(19)};
    var trace = try K.trace.Trace.initWithLog(a, &inputs, 1, 8);
    defer trace.deinit();
    try trace.releaseMain();
    trace.allocator = allocator;
    defer trace.allocator = a;
    _ = try K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = pool });
    allocator.free(trace.interaction);
    trace.interaction = &.{};
}
test "Keccak two-wave interaction OOM rolls back without publishing and leaves pool reusable" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = stack, .backing_allocator = a });
    defer pool.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{&pool});
    var regained = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    regained.deinit();
}
test "Keccak partial prefix/correction submissions and correction failures drain before retry" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = stack, .backing_allocator = a });
    defer pool.deinit();
    const inputs = [_]K.trace.State{ F.inputState(19), F.inputState(23), F.inputState(29) };
    var trace = try K.trace.Trace.initWithLog(a, &inputs, 7, 8);
    defer trace.deinit();
    try trace.releaseMain();
    var unavailable = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    const denied = K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool });
    unavailable.deinit();
    try std.testing.expectError(error.WorkerBudgetUnavailable, denied);
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    const cases = [_]struct { faults: K.interaction.testing.Faults, err: anyerror }{
        .{ .faults = .{ .prefix_spawn_after = 0 }, .err = error.InjectedKeccakPrefixSubmissionFailure },
        .{ .faults = .{ .prefix_spawn_after = 1 }, .err = error.InjectedKeccakPrefixSubmissionFailure },
        .{ .faults = .{ .correction_spawn_after = 0 }, .err = error.InjectedKeccakCorrectionSubmissionFailure },
        .{ .faults = .{ .correction_spawn_after = 1 }, .err = error.InjectedKeccakCorrectionSubmissionFailure },
        .{ .faults = .{ .correction_fail_job = 0 }, .err = error.InjectedKeccakCorrectionFailure },
        .{ .faults = .{ .correction_fail_job = 1 }, .err = error.InjectedKeccakCorrectionFailure },
        .{ .faults = .{ .correction_fail_job = 2 }, .err = error.InjectedKeccakCorrectionFailure },
    };
    for (cases) |case| {
        try std.testing.expectError(case.err, K.interaction.testing.generateWithFaults(&trace, challenges(), .{ .pool = &pool }, case.faults));
        try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
        var regained = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
        regained.deinit();
    }
    var serial = try K.trace.Trace.initWithLog(a, &inputs, 7, 8);
    defer serial.deinit();
    const expected = try K.interaction.generateWithOptions(&serial, challenges(), .{});
    const actual = try K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool });
    try std.testing.expect(expected.eql(actual));
    try std.testing.expectEqualSlices(M, serial.interaction, trace.interaction);
}
test "Keccak helper IO poles and invalid active tuples leave interaction unpublished" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = stack, .backing_allocator = a });
    defer pool.deinit();
    var inputs: [9]K.trace.State = undefined;
    inputsFixture(&inputs);
    var trace = try K.trace.Trace.initWithLog(a, &inputs, 1, 8);
    defer trace.deinit();
    var pole = challenges();
    pole.io.offset = Q.zero();
    pole.io.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, K.interaction.generateWithOptions(&trace, pole, .{ .pool = &pool }));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    trace.metadata[89].state_a[0] ^= 1;
    try std.testing.expectError(error.InvalidTuple, K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool }));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    trace.metadata[89].state_a[0] ^= 1;
    _ = try K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool });
}

test "Keccak interaction rejects undersized worker stacks before publishing" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 128 * 1024, .backing_allocator = a });
    defer pool.deinit();
    const input = [_]K.trace.State{F.inputState(19)};
    var trace = try K.trace.Trace.initWithLog(a, &input, 1, 8);
    defer trace.deinit();
    try std.testing.expectError(error.InvalidKeccakInteractionWorkerStack, K.interaction.generateWithOptions(&trace, challenges(), .{ .pool = &pool }));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
}
