//! Bounded parallel memoryless replay for an ordered leaf collection.
//!
//! Replay results are consumed synchronously by a caller-provided sink and
//! released on the worker that produced them. This keeps retained host memory
//! proportional to the admitted worker count instead of the block's leaf
//! count. The sink is invoked concurrently and must be thread-safe; it may
//! derive or serialize witness data during the call but may not retain the
//! borrowed `replay.Result`.

const std = @import("std");
const builtin = @import("builtin");
const replay = @import("replay.zig");
const types = @import("types.zig");

pub const MAX_WORKERS: usize = 32;
pub const DEFAULT_STACK_SIZE: usize = 16 << 20;

pub const RequestV1 = struct {
    leaf: *const types.LeafV1,
    program: replay.ProgramSource,
    boundary: replay.BoundarySource,
};

pub const OptionsV1 = struct {
    worker_count: usize,
    max_total_cycles: u64,
    stack_size: usize = DEFAULT_STACK_SIZE,

    fn validate(self: OptionsV1) !void {
        if (self.worker_count == 0 or self.worker_count > MAX_WORKERS)
            return error.InvalidReplayWorkerCount;
        if (self.max_total_cycles == 0)
            return error.InvalidReplayCycleBudget;
        if (self.stack_size == 0) return error.InvalidReplayStackSize;
        if (comptime builtin.single_threaded) {
            if (self.worker_count > 1) return error.SingleThreaded;
        }
    }
};

/// A failure leaves ownership with the replay worker, which always deinitializes
/// the result after this call. Implementations must therefore leave `result`
/// valid for deinitialization even when returning an error.
pub const SinkV1 = struct {
    context: *anyopaque,
    consume_fn: *const fn (*anyopaque, usize, *replay.Result) anyerror!void,

    fn consume(self: SinkV1, index: usize, result: *replay.Result) !void {
        return self.consume_fn(self.context, index, result);
    }
};

pub const ReceiptV1 = struct {
    leaf_count: u32,
    total_cycles: u64,
    admitted_workers: u16,
};

const Shared = struct {
    requests: []const RequestV1,
    sink: SinkV1,
    failures: []?anyerror,
    next: std.atomic.Value(usize) = .init(0),

    fn run(self: *Shared) void {
        // Each invocation belongs to exactly one worker. Reusing an arena
        // keeps the largest leaf's trace/state capacity local to that worker
        // instead of returning and reacquiring tens of megabytes through the
        // shared allocator for every leaf.
        var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        defer arena.deinit();
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.requests.len) return;
            const request = self.requests[index];
            var result = replay.replay(
                arena.allocator(),
                request.leaf,
                request.program,
                request.boundary,
            ) catch |failure| {
                self.failures[index] = failure;
                _ = arena.reset(.retain_capacity);
                continue;
            };
            self.sink.consume(index, &result) catch |failure| {
                self.failures[index] = failure;
            };
            result.deinit();
            _ = arena.reset(.retain_capacity);
        }
    }
};

/// Replays a canonical ordered leaf collection with at most `worker_count`
/// simultaneous full witnesses. Every request is validated before any worker
/// starts. Worker failures are retained per leaf and returned in canonical
/// leaf order, independent of scheduling.
pub fn replayLeaves(
    allocator: std.mem.Allocator,
    requests: []const RequestV1,
    options: OptionsV1,
    sink: SinkV1,
) !ReceiptV1 {
    try options.validate();
    const total_cycles = try validateRequests(requests, options.max_total_cycles);
    const worker_count = @min(options.worker_count, requests.len);

    const failures = try allocator.alloc(?anyerror, requests.len);
    defer allocator.free(failures);
    @memset(failures, null);
    var shared = Shared{
        .requests = requests,
        .sink = sink,
        .failures = failures,
    };

    if (worker_count == 1) {
        shared.run();
    } else {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{
            .allocator = std.heap.smp_allocator,
            .n_jobs = worker_count - 1,
            .stack_size = options.stack_size,
        });
        defer pool.deinit();
        var wait_group: std.Thread.WaitGroup = .{};
        for (1..worker_count) |_| {
            pool.spawnWg(&wait_group, Shared.run, .{&shared});
        }
        shared.run();
        pool.waitAndWork(&wait_group);
    }

    for (failures) |failure| if (failure) |err| return err;
    return .{
        .leaf_count = @intCast(requests.len),
        .total_cycles = total_cycles,
        .admitted_workers = @intCast(worker_count),
    };
}

fn validateRequests(requests: []const RequestV1, max_total_cycles: u64) !u64 {
    if (requests.len == 0) return error.EmptyReplayCollection;
    if (requests.len > std.math.maxInt(u32))
        return error.ReplayCollectionTooLarge;

    var total_cycles: u64 = 0;
    for (requests, 0..) |request, index| {
        try request.leaf.validate();
        if (request.leaf.completion != null) return error.UnsupportedCompletion;
        if (!std.mem.eql(u8, &request.leaf.source.program, &request.program.identity))
            return error.ProgramIdentityMismatch;
        if (!std.mem.eql(
            u8,
            &request.leaf.source.entry_memory,
            &request.boundary.entry_identity,
        ) or !std.mem.eql(
            u8,
            &request.leaf.source.exit_memory,
            &request.boundary.exit_identity,
        )) return error.MemoryBoundaryIdentityMismatch;

        total_cycles = std.math.add(
            u64,
            total_cycles,
            request.leaf.cycle_count,
        ) catch return error.ReplayCycleBudgetExceeded;
        if (total_cycles > max_total_cycles)
            return error.ReplayCycleBudgetExceeded;

        if (index == 0) continue;
        const previous = requests[index - 1].leaf;
        const expected_segment = std.math.add(
            u32,
            previous.segment_index,
            1,
        ) catch return error.NonCanonicalSegmentOrder;
        if (request.leaf.segment_index != expected_segment)
            return error.NonCanonicalSegmentOrder;
        const expected_global_first = std.math.add(
            u64,
            previous.global_first_cycle,
            previous.cycle_count,
        ) catch return error.InvalidGlobalCycleRange;
        if (request.leaf.global_first_cycle != expected_global_first)
            return error.NonContiguousGlobalCycleRange;
        if (!cpuEqual(previous.exit_cpu, request.leaf.entry_cpu))
            return error.CpuBoundaryMismatch;
        if (previous.source.profile != request.leaf.source.profile or
            !std.mem.eql(u8, &previous.source.program, &request.leaf.source.program) or
            !std.mem.eql(u8, &previous.source.input, &request.leaf.source.input) or
            !std.mem.eql(u8, &previous.source.session, &request.leaf.source.session))
        {
            return error.ReplaySourceMismatch;
        }
    }
    return total_cycles;
}

fn cpuEqual(left: @import("../cpu.zig").Cpu, right: @import("../cpu.zig").Cpu) bool {
    return left.pc == right.pc and std.mem.eql(u32, &left.regs, &right.regs);
}
