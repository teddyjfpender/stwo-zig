//! Two-pass CPU block-v4 producer with one live execution leaf at a time.
//! This emits staged artifacts; fresh incremental receiver integration is a
//! separate authority boundary and is not supplied by this producer.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("block_v4_cpu_runner_source.zig");
const first_mod = @import("block_v4_cpu_streaming_first_round.zig");
const tables_mod = @import("block_v4_cpu_streaming_tables.zig");
const statement_mod = @import("block_v4_cpu_streaming_statement.zig");
const source_mod = @import("block_v4_public_source_assembly.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const Capture = @import("block_v4_cpu_staged_capture.zig").Capture;
const ExecutionSink = @import("block_v4_cpu_staged_execution.zig").Sink;
const Replay = @import("block_memory_replay.zig").Replay;

pub const Product = struct {
    statement: @import("block_memory_batch_verify_v2.zig").PinnedStatement,
    /// Independently pinned runner input for one-leaf-at-a-time verifier replay.
    source: *runner.Source,
    first: *const first_mod.FirstRound,
    public: *const source_mod.Prepared,
    memories: *Capture,
    opcode_tables: *const tables_mod.Tables,
    external_tables: ?*const tables_mod.Tables,
    executions: *ExecutionSink,
    elapsed_ns: u64,
    memory_second_pass_ns: u64 = 0,
    execution_second_pass_ns: u64 = 0,

    pub fn payloadBytes(self: Product) !u64 {
        return std.math.add(u64, self.memories.total_bytes, self.executions.total_bytes);
    }
};

const Sorted = struct {
    replay: *Replay,
    fn open(context: *anyopaque) anyerror!@import("../air/block/memory_transition.zig").Reader {
        const self: *Sorted = @ptrCast(@alignCast(context));
        return self.replay.reopenSortedTransitions();
    }
    fn source(self: *Sorted) producer.SortedSource {
        return .{ .context = self, .open = open };
    }
};

/// The callback sees staged, hashed files and the sealed statement only while
/// their borrowed metadata is alive. It must transfer/persist any bundle it
/// needs. No unverified receipt is returned by this producer.
pub fn withProduced(a: std.mem.Allocator, dir: std.fs.Dir, pool: *engine.work_pool.WorkPool, source: *runner.Source, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, options: trusted_mod.Options, comptime callback: anytype) !void {
    return withProducedContext(a, dir, pool, source, trusted, config, options, {}, struct {
        fn call(_: void, product: Product) !void {
            try callback(product);
        }
    }.call);
}

/// Runtime context lets production and detached-file orchestration retain
/// explicit state without globals while preserving the simple fixture API.
pub fn withProducedContext(a: std.mem.Allocator, dir: std.fs.Dir, pool: *engine.work_pool.WorkPool, source: *runner.Source, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, options: trusted_mod.Options, context: anytype, comptime callback: anytype) !void {
    if (!std.meta.eql(source.job, trusted.job) or
        source.schedule.segments != trusted.base_seal.instance_count or
        trusted.native_key_ids.len != @as(usize, source.schedule.segments) or
        @as(usize, source.schedule.segments) > options.max_segments)
        return error.UntrustedStreamingBlockSchedule;
    var timer = try std.time.Timer.start();
    var first = try first_mod.collect(a, dir, source, trusted.native_key_ids, config, options.spool_chunk_events);
    defer first.deinit();
    var sorted = Sorted{ .replay = first.replay };
    var memory_first = try producer.collectFirstPass(Cpu, a, sorted.source(), first.event_count, options.memory_instance_capacity, options.memory_minimum_log_size, config);
    defer memory_first.deinit();
    const hashes = try a.alloc(source_mod.HashPin, first.entries.len);
    defer a.free(hashes);
    for (first.entries, hashes) |entry, *hash| hash.* = entry.hash_pin;
    var public = try source_mod.prepare(a, dir, first.replay, trusted.job.complete.initial_state.rw_memory.bytes, trusted.job.complete.program.bytes, hashes);
    defer public.deinit();
    var opcode_tables = try tables_mod.Tables.init(a, &first.opcode_plan, first.opcode_counters.items, config);
    defer opcode_tables.deinit();
    var external_tables: ?tables_mod.Tables = if (first.external_events == 0) null else try tables_mod.Tables.init(a, &first.external_plan, first.external_counters.items, config);
    defer if (external_tables) |*value| value.deinit();
    var bound = try statement_mod.bind(a, trusted, &first, &memory_first, &public, &opcode_tables, if (external_tables) |*value| value else null);
    defer bound.deinit();
    var memory_stage = try Capture.init(a, dir, memory_first.claims.len, memory_first.table_roots.len);
    defer memory_stage.deinit();
    var execution_stage = try ExecutionSink.init(a, dir, first.entries.len);
    defer execution_stage.deinit();
    const Stage = struct {
        sink: *ExecutionSink,
        cancelled: ?*const std.atomic.Value(bool) = null,
        fn write(self: *@This(), index: usize, _: *@import("../runner/result.zig").EthereumShaSegmentResult, execution: *@import("block_v4_cpu_multi_execution_assembly.zig").Execution) !void {
            if (self.cancelled) |flag| if (flag.load(.acquire)) return error.CancelledParallelFamily;
            try self.sink.write(index, execution.opcodeWire(), execution.externalWire(@intCast(index)));
        }
    };
    var stage = Stage{ .sink = &execution_stage };
    const MemoryWork = struct {
        allocator: std.mem.Allocator,
        sorted: *Sorted,
        first_pass: *const producer.FirstPass,
        statement: @import("block_memory_batch_verify_v2.zig").PinnedStatement,
        config: core.pcs.PcsConfig,
        capture: *Capture,
        opcode: *tables_mod.Tables,
        external: ?*tables_mod.Tables,
        cancelled: *std.atomic.Value(bool),
        failure: ?anyerror = null,
        elapsed_ns: u64 = 0,
        fn prove(self: *@This()) !void {
            try producer.proveSecondPassWithCancel(Cpu, self.allocator, self.sorted.source(), self.first_pass, self.statement, self.config, self.capture.sink(), self.cancelled);
            if (self.cancelled.load(.acquire)) return error.CancelledParallelFamily;
            try self.opcode.prove(self.statement.seal, self.capture);
            if (self.cancelled.load(.acquire)) return error.CancelledParallelFamily;
            if (self.external) |value| try value.prove(self.statement.seal, self.capture);
        }
        fn run(self: *@This()) void {
            var memory_timer = std.time.Timer.start() catch {
                self.failure = error.TimerUnavailable;
                self.cancelled.store(true, .release);
                return;
            };
            self.prove() catch |err| {
                self.failure = err;
                self.cancelled.store(true, .release);
            };
            self.elapsed_ns = memory_timer.read();
        }
    };
    var cancelled = std.atomic.Value(bool).init(false);
    var memory_work = MemoryWork{
        .allocator = a,
        .sorted = &sorted,
        .first_pass = &memory_first,
        .statement = bound.value,
        .config = config,
        .capture = &memory_stage,
        .opcode = &opcode_tables,
        .external = if (external_tables) |*value| value else null,
        .cancelled = &cancelled,
    };
    var execution_second_pass_ns: u64 = 0;
    if (options.parallel_families) {
        stage.cancelled = &cancelled;
        const thread = try std.Thread.spawn(.{}, MemoryWork.run, .{&memory_work});
        var joined = false;
        defer if (!joined) thread.join();
        var execution_timer = try std.time.Timer.start();
        const execution_result = first_mod.proveSecondPass(a, source, &first, trusted.native_key_ids, config, bound.value.seal, pool, &stage, Stage.write);
        execution_second_pass_ns = execution_timer.read();
        if (execution_result) |_| {} else |_| cancelled.store(true, .release);
        thread.join();
        joined = true;
        if (memory_work.failure) |err| if (err != error.CancelledParallelFamily) return err;
        try execution_result;
        if (memory_work.failure) |err| return err;
    } else {
        var memory_timer = try std.time.Timer.start();
        try memory_work.prove();
        memory_work.elapsed_ns = memory_timer.read();
        var execution_timer = try std.time.Timer.start();
        try first_mod.proveSecondPass(a, source, &first, trusted.native_key_ids, config, bound.value.seal, pool, &stage, Stage.write);
        execution_second_pass_ns = execution_timer.read();
    }
    try callback(context, Product{ .statement = bound.value, .source = source, .first = &first, .public = &public, .memories = &memory_stage, .opcode_tables = &opcode_tables, .external_tables = if (external_tables) |*value| value else null, .executions = &execution_stage, .elapsed_ns = timer.read(), .memory_second_pass_ns = memory_work.elapsed_ns, .execution_second_pass_ns = execution_second_pass_ns });
}
