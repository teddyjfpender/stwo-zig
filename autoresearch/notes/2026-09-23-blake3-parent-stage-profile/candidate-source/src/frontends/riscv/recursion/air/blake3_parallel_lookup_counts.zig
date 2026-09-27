//! Bounded private lookup counters; merge only after every worker succeeds.
const std = @import("std");
const pool_mod = @import("stwo_prover_engine").work_pool;
const columns = @import("blake3_row_columns.zig");
const binding = @import("universal_relation_binding.zig");
const framework = @import("framework_interaction.zig");
const Counter = @import("../../air/lookups/tables/counter.zig").Counter;

pub fn register(comptime Air: type, allocator: std.mem.Allocator, plan: *const binding.Binding(Air).Plan, view: framework.Runtime(binding.Binding(Air).Runtime).ColumnRows, log: u32, counters: *[2]Counter) !void {
    try view.validate(log);
    const pool = pool_mod.getGlobalPool() orelse return columns.registerColumns(Air, plan, view, log, counters);
    const workers = @min(pool.workerCount(), view.count / 4096);
    if (workers < 2 or std.process.hasEnvVarConstant("STWO_RISCV_SERIAL_PARENT_LOOKUPS")) return columns.registerColumns(Air, plan, view, log, counters);
    var lease = pool.acquire(try pool_mod.WorkerBudget.init(workers)) catch |err| switch (err) {
        error.WorkerBudgetUnavailable => return columns.registerColumns(Air, plan, view, log, counters),
        else => return err,
    };
    defer lease.deinit();
    const Context = struct {
        plan: *const binding.Binding(Air).Plan,
        view: framework.Runtime(binding.Binding(Air).Runtime).ColumnRows,
        log: u32,
        start: usize,
        end: usize,
        counters: [2]Counter,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            for (self.start..self.end) |index| columns.registerRepeated(Air, self.plan, self.view.read(index, self.log), 1, &self.counters) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    const contexts = try allocator.alloc(Context, workers);
    defer allocator.free(contexts);
    var initialized: usize = 0;
    defer for (contexts[0..initialized]) |*context| {
        for (&context.counters) |*counter| counter.deinit(allocator);
    };
    for (contexts, 0..) |*context, i| {
        var first = try Counter.init(allocator, .bitwise);
        errdefer first.deinit(allocator);
        const second = try Counter.init(allocator, .range_check_8_8);
        context.* = .{ .plan = plan, .view = view, .log = log, .start = view.count * i / workers, .end = view.count * (i + 1) / workers, .counters = .{ first, second } };
        initialized += 1;
    }
    var group: std.Thread.WaitGroup = .{};
    {
        // Submission failures still drain all started jobs before releasing storage.
        defer {
            group.wait();
            lease.completeWave();
        }
        for (contexts[1..]) |*context| try lease.spawnWg(&group, Context.run, .{context});
        contexts[0].run();
    }
    for (contexts) |context| if (context.failure) |err| return err;
    for (contexts) |context| for (counters, context.counters) |*destination, source| {
        for (destination.values, source.values) |*value, addend| value.* = value.add(addend);
    };
}
