const std = @import("std");
const O = @import("ordering.zig");
const P = @import("plan.zig");
const Pools = @import("stwo_prover_engine").work_pool;
const Task = extern struct { kind: u32, index: u32, level: u32 };

const Fixture = struct {
    a: std.mem.Allocator,
    source: []Task,
    levels: []u32,
    expected: []Task,
    actual: []Task,
    ends: []usize,
    expected_ends: []usize,
    cursors: []usize,
    fn init(a: std.mem.Allocator, n: usize, level_count: usize) !@This() {
        const source = try a.alloc(Task, n);
        errdefer a.free(source);
        const levels = try a.alloc(u32, n);
        errdefer a.free(levels);
        const expected = try a.alloc(Task, n);
        errdefer a.free(expected);
        const actual = try a.alloc(Task, n);
        errdefer a.free(actual);
        const ends = try a.alloc(usize, level_count);
        errdefer a.free(ends);
        const expected_ends = try a.alloc(usize, level_count);
        errdefer a.free(expected_ends);
        const cursors = try a.alloc(usize, level_count);
        for (source, levels, 0..) |*task, *level, i| {
            task.* = .{ .kind = @intCast(i % 9), .index = @intCast(i), .level = 0 };
            level.* = @intCast((i *% 131 + i / 31) % level_count);
        }
        return .{ .a = a, .source = source, .levels = levels, .expected = expected, .actual = actual, .ends = ends, .expected_ends = expected_ends, .cursors = cursors };
    }
    fn deinit(self: *@This()) void {
        self.a.free(self.source);
        self.a.free(self.levels);
        self.a.free(self.expected);
        self.a.free(self.actual);
        self.a.free(self.ends);
        self.a.free(self.expected_ends);
        self.a.free(self.cursors);
    }
    fn reference(self: *@This()) !void {
        try O.serial(Task, self.source, self.levels, self.expected_ends, self.cursors, self.expected);
    }
    fn fill(self: *@This(), a: std.mem.Allocator, options: O.Options) !bool {
        return O.fill(Task, a, self.source, self.levels, self.ends, self.cursors, self.actual, options);
    }
    fn check(self: *@This()) !void {
        try std.testing.expectEqualSlices(usize, self.expected_ends, self.ends);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(self.expected), std.mem.sliceAsBytes(self.actual));
        for (self.actual[1..], self.actual[0 .. self.actual.len - 1]) |next, previous| {
            try std.testing.expect(next.level > previous.level or (next.level == previous.level and next.index > previous.index));
        }
    }
};

test "witness ordering fixed logical chunks survive different physical wave shards" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a, O.MIN_TASKS + 17, 103);
    defer f.deinit();
    try f.reference();
    // No scoped pool keeps original serial ordering.
    try std.testing.expect(!try f.fill(a, .{}));
    try f.check();
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]O.Options{ .{ .count_shards = 4, .scatter_shards = 1 }, .{ .count_shards = 1, .scatter_shards = 4 }, .{ .count_shards = 2, .scatter_shards = 3 } }) |options| {
        try std.testing.expect(try f.fill(a, options));
        try f.check();
    }
    var held = try pool.acquire(try Pools.WorkerBudget.init(4));
    try std.testing.expect(!try f.fill(a, .{}));
    try f.check();
    held.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expect(!try f.fill(failing.allocator(), .{}));
    try std.testing.expect(failing.has_induced_failure);
    try f.check();
    // Invalid input in the last logical chunk rejects only after count jobs
    // join; retry proves no helper still borrows buffers from the error path.
    const old = f.levels[f.levels.len - 1];
    f.levels[f.levels.len - 1] = @intCast(f.ends.len);
    try std.testing.expectError(error.InvalidWitnessLevel, f.fill(a, .{}));
    f.levels[f.levels.len - 1] = old;
    try std.testing.expect(try f.fill(a, .{}));
    try f.check();
}

test "witness ordering benchmark bounded eight million records and110k levels" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a, 1 << 23, 110003);
    defer f.deinit();
    var serial_ns: [3]u64 = undefined;
    var parallel_ns: [3]u64 = undefined;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for (0..3) |iteration| {
        var timer = try std.time.Timer.start();
        try f.reference();
        serial_ns[iteration] = timer.read();
        timer.reset();
        try std.testing.expect(try f.fill(a, .{}));
        parallel_ns[iteration] = timer.read();
        try f.check();
    }
    std.mem.sort(u64, &serial_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &parallel_ns, {}, std.sort.asc(u64));
    std.debug.print("WITNESS_ORDER_PARITY tasks={} levels={} workers=4 logical_chunks=8 total_cursor_scratch_bytes={} serial_median_ns={} parallel_median_ns={} exact_order=true\n", .{ f.source.len, f.ends.len, (O.MAX_CHUNKS + 1) * f.ends.len * @sizeOf(usize), serial_ns[1], parallel_ns[1] });
    // Too many levels for the16MiB scratch cap uses original serial storage.
    const large_ends = try a.alloc(usize, (O.SCRATCH_CAP_BYTES / ((O.MAX_CHUNKS + 1) * @sizeOf(usize))) + 1);
    defer a.free(large_ends);
    const large_cursors = try a.alloc(usize, large_ends.len);
    defer a.free(large_cursors);
    try std.testing.expect(!try O.fill(Task, a, f.source, f.levels, large_ends, large_cursors, f.actual, .{}));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(f.expected), std.mem.sliceAsBytes(f.actual));
}

test "witness ordering real builder retains independent DFS seeds levels and task fields" {
    const a = std.testing.allocator;
    const C = @import("../builder/context.zig");
    const Q = @import("stwo_core").fields.qm31.QM31;
    const Var = @import("../builder/circuit.zig").Var;
    var ctx = try C.Context(Q).initWithWitnessOrigins(a, 1);
    defer ctx.deinit();
    const multiplier = try ctx.guess(Q.fromU32Unchecked(2, 1, 0, 0));
    var last: [256]Var = undefined;
    for (&last, 0..) |*variable, i| variable.* = try ctx.guess(Q.fromU32Unchecked(@intCast(i + 3), 0, 0, 0));
    for (0..256) |_| for (&last) |*variable| {
        variable.* = try ctx.mul(variable.*, multiplier);
    };
    try ctx.setOutputs(&.{last[0]});
    try ctx.finalize(false);
    var reference = try P.buildDfsReference(a, &ctx);
    defer reference.deinit();
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var actual = try P.build(a, &ctx);
    defer actual.deinit();
    try std.testing.expectEqualDeep(reference.tasks, actual.tasks);
    try std.testing.expectEqualDeep(reference.seeds, actual.seeds);
    try std.testing.expectEqualSlices(usize, reference.level_ends, actual.level_ends);
}
