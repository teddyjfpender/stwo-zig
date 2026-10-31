const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const parallel = @import("../parallel.zig");
const cosets = @import("../coset_evaluation.zig");
const Component = @import("../component.zig").Component;
const Plan = @import("../../encoding.zig").Plan;
const frame = @import("../frame.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "RV64 row pool: exact serial residual authority, additive output, and drained coset reuse" {
    try compareRows(7, 3);
    try compareRows(10, 3);
}
fn compareRows(log: u32, workers: usize) !void {
    return compareRowsWithServices(log, workers, false);
}
fn compareRowsWithServices(log: u32, workers: usize, services: bool) !void {
    var all_opcodes: [65]@import("../../evaluation.zig").O = undefined;
    for (&all_opcodes, 0..) |*opcode, i| opcode.* = @enumFromInt(i);
    var plan = if (services) try Plan.fromOpcodesWithProfiles(&all_opcodes, .division_multiplication_services_v3, .ethereum_services_v2) else Plan.fromOpcodes(all_opcodes[0..63]);
    if (services) plan.setStatePolicy(.cyclic_canonical_v3);
    if (workers == 8 or workers == 16) {
        plan.control_policy = .limbs24_v2;
        if (!services) plan.setStatePolicy(.cyclic_v2);
    }
    const zero = Q.zero();
    const challenge = Q.fromU32Unchecked(17, 19, 23, 29);
    const typed = @import("../../providers/tables.zig").Challenges{ .offset = challenge, .coefficients = @splat(Q.fromU32Unchecked(31, 37, 41, 43)) };
    const challenges = @import("../component.zig").Challenges{ .state = .{ .offset = challenge, .coefficients = @splat(Q.fromU32Unchecked(31, 37, 41, 43)) }, .rom = .{ .offset = challenge, .coefficients = @splat(Q.fromU32Unchecked(31, 37, 41, 43)) }, .bytes = Q.fromU32Unchecked(47, 53, 59, 61), .bitwise = typed, .shifts = typed };
    const claims = @import("../component.zig").Claims{ .state = zero, .rom = zero, .bytes = zero, .bitwise = zero, .shifts = zero };
    const size: usize = @as(usize, 1) << @intCast(log);
    const public = frame.Public{ .steps = @intCast(size - 1), .initial_pc = 0x1000, .final_pc = 0x2000 };
    const component = if (services) try Component.initWithEthereum(
        log,
        &plan,
        public,
        challenges,
        claims,
        .{},
        .{ .challenges = .{ .offset = challenge, .coefficients = @splat(challenge) }, .claim = zero },
        .{ .challenges = .{ .offset = challenge, .coefficients = @splat(challenge) }, .claim = zero, .calls = 1, .first_call_id = 1 },
        .{ .challenges = .{ .offset = challenge, .coefficients = @splat(challenge) }, .claim = zero },
        .{ .challenges = .{ .offset = challenge, .coefficients = @splat(challenge) }, .claim = zero, .calls = .{ 1, 1 }, .execution_profile = .ethereum_services_v2 },
    ) else try Component.init(log, &plan, public, challenges, claims, .{});
    const total = frame.FIXED + component.mainCount() + component.interactionCount();
    const sources = try a.alloc(engine.air.component_prover.Poly, total);
    defer a.free(sources);
    const coefficients = try a.alloc(M, total * size);
    defer a.free(coefficients);
    const previous_columns = try a.alloc(bool, total);
    defer a.free(previous_columns);
    var prng = std.Random.DefaultPrng.init(0x5256504152414c4c);
    const rng = prng.random();
    for (sources, previous_columns, 0..) |*source, *previous, i| {
        const column = coefficients[i * size ..][0..size];
        for (column) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        source.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(column) };
        previous.* = if (i < frame.FIXED) false else if (i < frame.FIXED + component.mainCount()) component.needsPreviousMain(i - frame.FIXED) else component.needsPreviousInteraction(i - frame.FIXED - component.mainCount());
    }
    var evaluation = try cosets.Evaluation.init(a, sources, log, previous_columns);
    defer evaluation.deinit();
    const alpha = Q.fromU32Unchecked(2, 3, 5, 7);
    var serial = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, component.constraint_count);
    defer serial.deinit();
    var pooled = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, component.constraint_count);
    defer pooled.deinit();
    const serial_columns = try serial.columns(a, &.{.{ .log_size = log + 2, .n_cols = component.constraint_count }});
    defer a.free(serial_columns);
    const pooled_columns = try pooled.columns(a, &.{.{ .log_size = log + 2, .n_cols = component.constraint_count }});
    defer a.free(pooled_columns);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = parallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    // Repeat each complete wave: this must add to existing bucket values and
    // must not retain any pointer to a previous coset's scratch contents.
    for (0..2) |_| for (0..cosets.PARTS) |part| {
        try evaluation.evaluatePart(part);
        const inverse = try evaluation.denominatorInverse(part);
        try parallel.testing.evaluatePartUntiled(&component, &evaluation, part, &serial_columns[0], inverse);
        try parallel.evaluatePart(&component, &evaluation, part, &pooled_columns[0], inverse, &pool);
        for (0..4 * size) |row| try std.testing.expect(serial_columns[0].col.at(row).eql(pooled_columns[0].col.at(row)));
    };
    // SIMD packs the live columns directly into one coordinator-owned scratch
    // allocation; it no longer allocates the former native transpose slab.
    if (log == 7) for (0..1) |fail_index| {
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        evaluation.allocator = fail.allocator();
        defer evaluation.allocator = a;
        try std.testing.expectError(error.OutOfMemory, parallel.evaluatePart(&component, &evaluation, 0, &pooled_columns[0], M.one(), &pool));
        try std.testing.expectEqual(fail.allocated_bytes, fail.freed_bytes);
        for (0..4 * size) |row| try std.testing.expect(serial_columns[0].col.at(row).eql(pooled_columns[0].col.at(row)));
    };
    // Reservation failure occurs before publication/submission. No background
    // helper may touch the bucket after the failure is returned.
    if (workers == 1) return;
    var competing = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
    const before = pooled_columns[0].col.at(0);
    try std.testing.expectError(error.WorkerBudgetUnavailable, parallel.evaluatePart(&component, &evaluation, 0, &pooled_columns[0], M.one(), &pool));
    competing.deinit();
    try std.testing.expect(before.eql(pooled_columns[0].col.at(0)));
    try std.testing.expectError(error.InvalidRv64ParallelShape, parallel.evaluatePart(&component, &evaluation, 4, &pooled_columns[0], M.one(), &pool));
    if (workers >= 3 and size >= workers * parallel.MIN_ROWS_PER_WORKER) {
        try std.testing.expectError(error.InjectedRv64SpawnFailure, parallel.testing.evaluatePartWithTiles(&component, &evaluation, 0, &pooled_columns[0], M.one(), &pool, 64, 1));
        // A new full lease can be acquired only after every submitted helper
        // and its closure have drained; contexts/scratch are no longer borrowed.
        var regained = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
        regained.deinit();
    }
    var small_stack_pool: engine.work_pool.WorkPool = undefined;
    try small_stack_pool.initInPlaceWithOptions(.{ .worker_count = 2, .stack_size = parallel.MIN_STACK_BYTES / 2, .backing_allocator = a });
    defer small_stack_pool.deinit();
    try std.testing.expectError(error.InvalidRv64ParallelStack, parallel.evaluatePart(&component, &evaluation, 0, &pooled_columns[0], M.one(), &small_stack_pool));
}

test "RV64 dynamic row tiles preserve every quotient with 1 3 8 and 16 workers" {
    var binding = try parallel.testing.TileRowsBinding.init(63);
    defer binding.deinit();
    for ([_]usize{ 1, 3, 8, 16 }) |workers| try compareRows(10, workers);
}

const CoverageJob = struct {
    cursor: *parallel.testing.Cursor,
    cells: []std.atomic.Value(u8),
    claims: usize = 0,
    bad: bool = false,
    fn run(self: *CoverageJob) void {
        while (self.cursor.claim(self.cells.len, parallel.TILE_ROWS)) |tile| {
            self.claims += 1;
            if (tile.start % parallel.TILE_ROWS != 0 or tile.end <= tile.start or tile.end - tile.start > parallel.TILE_ROWS) self.bad = true;
            for (self.cells[tile.start..tile.end]) |*cell| _ = cell.fetchAdd(1, .monotonic);
        }
    }
};
test "real4096 concurrent tiles cover final partial tile exactly once with excess workers" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = parallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    for ([_]usize{ 0, 1, 4095, 4096, 4097, 4 * 4096 + 13 }) |size| {
        const cells = try a.alloc(std.atomic.Value(u8), size);
        defer a.free(cells);
        for (cells) |*cell| cell.* = .init(0);
        var cursor = parallel.testing.Cursor{};
        var jobs: [16]CoverageJob = undefined;
        for (&jobs) |*job| job.* = .{ .cursor = &cursor, .cells = cells };
        {
            var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(16));
            defer lease.deinit();
            var wait = std.Thread.WaitGroup{};
            defer {
                wait.wait();
                lease.completeWave();
            }
            for (jobs[1..]) |*job| try lease.spawnWg(&wait, CoverageJob.run, .{job});
            jobs[0].run();
        }
        var claims: usize = 0;
        for (jobs) |job| {
            try std.testing.expect(!job.bad);
            claims += job.claims;
        }
        try std.testing.expectEqual(try std.math.divCeil(usize, size, parallel.TILE_ROWS), claims);
        for (cells) |cell| try std.testing.expectEqual(@as(u8, 1), cell.load(.monotonic));
    }
}

test "RV64 SIMD full service CPU uses256KiB worker stacks with exact scalar residual parity" {
    try compareRowsWithServices(7, 3, true);
    try compareRowsWithServices(10, 16, true);
}
