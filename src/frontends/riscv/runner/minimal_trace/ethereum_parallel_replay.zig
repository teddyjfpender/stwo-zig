//! Bounded parallel replay for an ordered compact Ethereum leaf collection.
//!
//! A worker owns at most one materialized trace, state-chain witness, and pair
//! of native-call tapes at a time. The caller-provided sink consumes that
//! borrowed witness synchronously; worker-local arenas retain capacity between
//! leaves so a block does not pay allocator contention once per segment.

const std = @import("std");
const builtin = @import("builtin");
const memory_state = @import("../memory_state.zig");
const ethereum_replay = @import("ethereum_replay.zig");
const ethereum_types = @import("ethereum_types.zig");
const base_replay = @import("replay.zig");

pub const MAX_WORKERS: usize = 32;
pub const DEFAULT_STACK_SIZE: usize = 16 << 20;

pub const RequestV1 = struct {
    leaf: *const ethereum_types.LeafV1,
    program: base_replay.ProgramSource,
    boundary_words: []const base_replay.BoundaryWord,
    expected_memory_layout: memory_state.MemoryLayout,
    expected_source: ethereum_types.SourceIdentityV1,
    expected_entry_cpu_sha256: ethereum_types.Digest,
    expected_exit_cpu_sha256: ethereum_types.Digest,
    expected_completion: ?ethereum_types.CompletionV1,
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

/// The result remains worker-owned and is deinitialized immediately after the
/// call. A sink may derive, serialize, or hash witness data synchronously, but
/// it must not retain any slice or pointer from `result`.
pub const SinkV1 = struct {
    context: *anyopaque,
    consume_fn: *const fn (
        *anyopaque,
        usize,
        *ethereum_replay.ResultV1,
    ) anyerror!void,

    fn consume(
        self: SinkV1,
        index: usize,
        result: *ethereum_replay.ResultV1,
    ) !void {
        return self.consume_fn(self.context, index, result);
    }
};

pub const ReceiptV1 = struct {
    leaf_count: u32,
    total_cycles: u64,
    core_cycles: u64,
    keccak_calls: u64,
    recovery_calls: u64,
    admitted_workers: u16,
};

const Shared = struct {
    requests: []const RequestV1,
    sink: SinkV1,
    failures: []?anyerror,
    next: std.atomic.Value(usize) = .init(0),

    fn run(self: *Shared) void {
        var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        defer arena.deinit();
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.requests.len) return;
            const request = self.requests[index];
            var boundary = base_replay.SliceBoundary.init(
                request.boundary_words,
            ) catch |failure| {
                self.failures[index] = failure;
                continue;
            };
            var result = ethereum_replay.replay(
                arena.allocator(),
                .{
                    .leaf = request.leaf,
                    .program = request.program,
                    .boundary = boundary.source(),
                    .expected_memory_layout = request.expected_memory_layout,
                    .expected_source = request.expected_source,
                    .expected_entry_cpu_sha256 = request.expected_entry_cpu_sha256,
                    .expected_exit_cpu_sha256 = request.expected_exit_cpu_sha256,
                    .expected_completion = request.expected_completion,
                },
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

pub fn replayLeaves(
    allocator: std.mem.Allocator,
    requests: []const RequestV1,
    options: OptionsV1,
    sink: SinkV1,
) !ReceiptV1 {
    try options.validate();
    const receipt = try validateCollection(requests, options.max_total_cycles);
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
        for (1..worker_count) |_|
            pool.spawnWg(&wait_group, Shared.run, .{&shared});
        shared.run();
        pool.waitAndWork(&wait_group);
    }
    for (failures) |failure| if (failure) |err| return err;

    var published = receipt;
    published.admitted_workers = @intCast(worker_count);
    return published;
}

/// Allocation-free collection admission, exposed so controllers can reject a
/// malformed 210-leaf bundle before they reserve worker stacks or start a
/// witness task. It authenticates both the local replay boundary and the full
/// snapshot identity used for cross-leaf memory continuity.
pub fn validateCollection(
    requests: []const RequestV1,
    max_total_cycles: u64,
) !ReceiptV1 {
    if (requests.len == 0) return error.EmptyReplayCollection;
    if (requests.len > std.math.maxInt(u32))
        return error.ReplayCollectionTooLarge;
    if (max_total_cycles == 0) return error.InvalidReplayCycleBudget;

    var result = ReceiptV1{
        .leaf_count = @intCast(requests.len),
        .total_cycles = 0,
        .core_cycles = 0,
        .keccak_calls = 0,
        .recovery_calls = 0,
        .admitted_workers = 0,
    };
    for (requests, 0..) |request, index| {
        const leaf = request.leaf;
        try leaf.validate();
        if (!std.meta.eql(leaf.source, request.expected_source))
            return error.SourceAuthorityMismatch;
        if (!std.mem.eql(
            u8,
            &ethereum_types.cpuIdentity(leaf.entry_cpu),
            &request.expected_entry_cpu_sha256,
        )) return error.EntryCpuAuthorityMismatch;
        if (!std.mem.eql(
            u8,
            &ethereum_types.cpuIdentity(leaf.exit_cpu),
            &request.expected_exit_cpu_sha256,
        )) return error.ExitCpuAuthorityMismatch;
        if (!std.meta.eql(leaf.completion, request.expected_completion))
            return error.CompletionAuthorityMismatch;
        if (leaf.completion != null and index + 1 != requests.len)
            return error.NonTerminalCompletion;
        if (!std.mem.eql(u8, &leaf.source.program, &request.program.identity))
            return error.ProgramIdentityMismatch;
        var boundary = try base_replay.SliceBoundary.init(request.boundary_words);
        if (!std.mem.eql(u8, &leaf.entry_boundary, &boundary.entry_identity) or
            !std.mem.eql(u8, &leaf.exit_boundary, &boundary.exit_identity))
        {
            return error.MemoryBoundaryIdentityMismatch;
        }

        result.total_cycles = std.math.add(
            u64,
            result.total_cycles,
            leaf.cycle_count,
        ) catch return error.ReplayCycleBudgetExceeded;
        if (result.total_cycles > max_total_cycles)
            return error.ReplayCycleBudgetExceeded;
        result.core_cycles = std.math.add(
            u64,
            result.core_cycles,
            leaf.core_cycle_count,
        ) catch return error.ReplayCycleBudgetExceeded;
        result.keccak_calls = std.math.add(
            u64,
            result.keccak_calls,
            leaf.keccak_records.len,
        ) catch return error.ExternalCallCountOverflow;
        result.recovery_calls = std.math.add(
            u64,
            result.recovery_calls,
            leaf.recovery_records.len,
        ) catch return error.ExternalCallCountOverflow;

        if (index == 0) continue;
        const previous_request = requests[index - 1];
        const previous = previous_request.leaf;
        if (leaf.segment_index != std.math.add(
            u32,
            previous.segment_index,
            1,
        ) catch return error.NonCanonicalSegmentOrder) {
            return error.NonCanonicalSegmentOrder;
        }
        if (leaf.global_first_cycle != std.math.add(
            u64,
            previous.global_first_cycle,
            previous.cycle_count,
        ) catch return error.InvalidGlobalCycleRange) {
            return error.NonContiguousGlobalCycleRange;
        }
        if (!cpuEqual(previous.exit_cpu, leaf.entry_cpu))
            return error.CpuBoundaryMismatch;
        if (!std.mem.eql(u8, &previous.source.program, &leaf.source.program) or
            !std.mem.eql(u8, &previous.source.input, &leaf.source.input) or
            !std.mem.eql(u8, &previous.source.session, &leaf.source.session))
        {
            return error.ReplaySourceMismatch;
        }
        if (!std.mem.eql(
            u8,
            &previous.source.exit_memory,
            &leaf.source.entry_memory,
        )) return error.MemoryContinuationMismatch;
        if (!std.meta.eql(
            previous_request.expected_memory_layout,
            request.expected_memory_layout,
        ))
            return error.MemoryLayoutMismatch;
    }
    return result;
}

fn cpuEqual(left: @import("../cpu.zig").Cpu, right: @import("../cpu.zig").Cpu) bool {
    return left.pc == right.pc and std.mem.eql(u32, &left.regs, &right.regs);
}
