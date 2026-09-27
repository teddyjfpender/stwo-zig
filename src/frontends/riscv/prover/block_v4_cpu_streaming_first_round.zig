//! One-segment-at-a-time first-round execution and memory-roster collection.
//! The second pass must reproduce every entry before using its proof bytes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runner = @import("block_v4_cpu_runner_source.zig");
const execution_mod = @import("block_v4_cpu_multi_execution_assembly.zig");
const replay_mod = @import("block_memory_replay.zig");
const source_mod = @import("block_v4_public_source_assembly.zig");
const counter = @import("../air/lookups/tables/counter.zig").Counter;
const seal = @import("block_memory_source_seal_v2.zig").SourceSeal;
const shard = @import("block_execution_range_shard_v2.zig");

pub const Entry = struct {
    native_roots: [2][32]u8,
    opcode_witness_root: [32]u8,
    external_witness_root: ?[32]u8,
    opcode_events: u64,
    external_events: u64,
    opcode_counter_digest: [32]u8,
    external_counter_digest: ?[32]u8,
    hash_pin: source_mod.HashPin,

    pub fn eql(a: Entry, b: Entry) bool {
        return std.meta.eql(a, b);
    }
};

pub const FirstRound = struct {
    a: std.mem.Allocator,
    replay: *replay_mod.Replay,
    entries: []Entry,
    event_count: u64,
    opcode_events: u64,
    external_events: u64,
    opcode_plan: shard.Plan,
    external_plan: shard.Plan,
    opcode_counters: std.ArrayList(counter),
    external_counters: std.ArrayList(counter),

    pub fn deinit(self: *FirstRound) void {
        for (self.opcode_counters.items) |*value| value.deinit(self.a);
        for (self.external_counters.items) |*value| value.deinit(self.a);
        self.opcode_counters.deinit(self.a);
        self.external_counters.deinit(self.a);
        self.opcode_plan.deinit(self.a);
        self.external_plan.deinit(self.a);
        self.replay.deinit();
        self.a.destroy(self.replay);
        self.a.free(self.entries);
        self.* = undefined;
    }

    /// Recreate one leaf in pass two, then require exact first-round roots,
    /// event counts, hash-source ID and range multiplicities. This guards
    /// against a changed runner replay before any postchallenge proof work.
    pub fn checkLeaf(self: *const FirstRound, index: usize, execution: *execution_mod.Execution) !void {
        if (index >= self.entries.len) return error.InvalidBlockSecondPassIndex;
        const actual = try capture(execution);
        if (!Entry.eql(self.entries[index], actual)) return error.ChangedBlockFirstRoundExecution;
    }
};

/// Collect only fixed-size roots/counts per segment and an immutable sorted
/// event spool. Every runner segment, native witness, and execution sidecar is
/// released before advancing to the next leaf.
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, source: *runner.Source, trusted_native_keys: []const [32]u8, config: core.pcs.PcsConfig, spool_chunk_events: usize) !FirstRound {
    if (trusted_native_keys.len != @as(usize, source.schedule.segments) or trusted_native_keys.len == 0 or spool_chunk_events == 0)
        return error.InvalidBlockFirstRoundRoster;
    const entries = try a.alloc(Entry, trusted_native_keys.len);
    errdefer a.free(entries);
    const replay = try a.create(replay_mod.Replay);
    errdefer a.destroy(replay);
    var replay_ready = false;
    errdefer if (replay_ready) replay.deinit();
    var reader = try source.openPass(.first);
    defer reader.deinit();
    var opcode_tables = CounterCollector{ .a = a };
    errdefer opcode_tables.deinit();
    var external_tables = CounterCollector{ .a = a };
    errdefer external_tables.deinit();
    var index: usize = 0;
    var opcode_events: u64 = 0;
    var external_events: u64 = 0;
    while (try reader.next()) |owned| {
        var segment = owned;
        defer segment.deinit();
        if (index >= entries.len) return error.BlockFirstRoundScheduleOverrun;
        if (!replay_ready) {
            replay.* = try replay_mod.Replay.initFromSnapshot(a, dir, segment.base.entry_cpu.regs, &segment.base.rw_memory, spool_chunk_events);
            replay_ready = true;
        }
        try replay.appendResult(&segment.base);
        var execution = execution_mod.Execution.init(a, &segment, @intCast(index), config, trusted_native_keys[index]) catch |err| {
            std.log.err("block-v4 first round execution init failed at segment {d}/{d}: {s}", .{ index, entries.len, @errorName(err) });
            return err;
        };
        defer execution.deinit();
        entries[index] = capture(&execution) catch |err| {
            std.log.err("block-v4 first round root/counter capture failed at segment {d}/{d}: {s}", .{ index, entries.len, @errorName(err) });
            return err;
        };
        try opcode_tables.add(entries[index].opcode_events, execution.opcodeCounter());
        if (execution.externalCounter()) |value|
            try external_tables.add(entries[index].external_events, value)
        else if (entries[index].external_events != 0)
            return error.MissingBlockExternalCounter;
        opcode_events = try std.math.add(u64, opcode_events, entries[index].opcode_events);
        external_events = try std.math.add(u64, external_events, entries[index].external_events);
        index += 1;
        if (index == 1 or index % 16 == 0 or index == entries.len)
            std.debug.print("BLOCK_V4_FIRST_ROUND_PROGRESS segment={d}/{d} opcode_events={d} external_events={d}\n", .{ index, entries.len, opcode_events, external_events });
    }
    if (index != entries.len or !source.first_complete) return error.IncompleteBlockFirstRound;
    var sorted = try replay.finish();
    sorted.deinit();
    const event_count = replay.spooler.event_count;
    if (event_count != try std.math.add(u64, opcode_events, external_events))
        return error.BlockFirstRoundAccessCensusMismatch;
    const opcode_counts = try a.alloc(u64, entries.len);
    defer a.free(opcode_counts);
    const external_counts = try a.alloc(u64, entries.len);
    defer a.free(external_counts);
    for (entries, opcode_counts, external_counts) |entry, *opcode_count, *external_count| {
        opcode_count.* = entry.opcode_events;
        external_count.* = entry.external_events;
    }
    var opcode_plan = try shard.plan(a, opcode_counts);
    errdefer opcode_plan.deinit(a);
    var external_plan = try shard.plan(a, external_counts);
    errdefer external_plan.deinit(a);
    if (opcode_plan.shards.len != opcode_tables.counters.items.len or
        external_plan.shards.len != external_tables.counters.items.len)
        return error.BlockFirstRoundTableShardMismatch;
    return .{ .a = a, .replay = replay, .entries = entries, .event_count = event_count, .opcode_events = opcode_events, .external_events = external_events, .opcode_plan = opcode_plan, .external_plan = external_plan, .opcode_counters = opcode_tables.counters, .external_counters = external_tables.counters };
}

/// Prove each replayed leaf against the already sealed first-round roster.
/// The callback must serialize/stage any proof it needs before returning;
/// only one segment, native witness, and execution artifact remain live.
pub fn proveSecondPass(a: std.mem.Allocator, source: *runner.Source, first: *const FirstRound, trusted_native_keys: []const [32]u8, config: core.pcs.PcsConfig, bound: seal, pool: *engine.work_pool.WorkPool, context: anytype, comptime on_proved: anytype) !void {
    if (trusted_native_keys.len != first.entries.len or
        source.schedule.segments != @as(u32, @intCast(first.entries.len)))
        return error.InvalidBlockSecondPassRoster;
    var reader = try source.openPass(.second);
    defer reader.deinit();
    var index: usize = 0;
    while (try reader.next()) |owned| {
        var segment = owned;
        defer segment.deinit();
        if (index >= first.entries.len) return error.BlockSecondPassScheduleOverrun;
        var execution = try execution_mod.Execution.init(a, &segment, @intCast(index), config, trusted_native_keys[index]);
        defer execution.deinit();
        try first.checkLeaf(index, &execution);
        try execution.prove(bound, pool);
        try on_proved(context, index, &segment, &execution);
        index += 1;
    }
    if (index != first.entries.len) return error.IncompleteBlockSecondPass;
}

fn capture(execution: *execution_mod.Execution) !Entry {
    const external = execution.externalCounter();
    return .{
        .native_roots = execution.nativeRoots(),
        .opcode_witness_root = execution.opcodeWitnessRoot(),
        .external_witness_root = execution.externalWitnessRoot(),
        .opcode_events = execution.opcodeCount(),
        .external_events = try execution.externalCount(),
        .opcode_counter_digest = digestCounter(execution.opcodeCounter()),
        .external_counter_digest = if (external) |value| digestCounter(value) else null,
        .hash_pin = .{ .plan_id = execution.prepared.plan_id, .key_id = execution.prepared.id },
    };
}

fn digestCounter(value: *const counter) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("block-v4-execution-counter-v1");
    var word: [4]u8 = undefined;
    for (value.values) |item| {
        std.mem.writeInt(u32, &word, item.toU32(), .little);
        hasher.update(&word);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

const CounterCollector = struct {
    a: std.mem.Allocator,
    counters: std.ArrayList(counter) = .empty,
    current_events: u64 = 0,

    fn add(self: *CounterCollector, events: u64, input: *const counter) !void {
        if (events > shard.MAX_EVENTS_PER_SHARD) return error.ExecutionRangeInstanceExceedsShard;
        if (events == 0) {
            for (input.values) |value| if (!value.isZero()) return error.NonzeroEmptyExecutionCounter;
            return;
        }
        if (self.current_events != 0 and events > shard.MAX_EVENTS_PER_SHARD - self.current_events)
            self.current_events = 0;
        if (self.current_events == 0) {
            var fresh = try counter.init(self.a, .range_check_8_8);
            errdefer fresh.deinit(self.a);
            try self.counters.append(self.a, fresh);
        }
        const destination = &self.counters.items[self.counters.items.len - 1];
        if (destination.values.len != input.values.len) return error.InvalidBlockExecutionCounterShape;
        for (destination.values, input.values) |*value, addend| value.* = value.add(addend);
        self.current_events = try std.math.add(u64, self.current_events, events);
    }

    fn deinit(self: *CounterCollector) void {
        for (self.counters.items) |*value| value.deinit(self.a);
        self.counters.deinit(self.a);
    }
};

test "streaming table collector mirrors mixed zero-count shard boundary" {
    const a = std.testing.allocator;
    var source_counter = try counter.init(a, .range_check_8_8);
    defer source_counter.deinit(a);
    source_counter.values[7] = @import("stwo_core").fields.m31.M31.one();
    var collector = CounterCollector{ .a = a };
    defer collector.deinit();
    const counts = [_]u64{ 0, shard.MAX_EVENTS_PER_SHARD - 1, 0, 2, 0 };
    for (counts) |count| try collector.add(count, &source_counter);
    var plan = try shard.plan(a, &counts);
    defer plan.deinit(a);
    try std.testing.expectEqual(plan.shards.len, collector.counters.items.len);
    try std.testing.expectEqual(@as(usize, 2), plan.shards.len);
    try std.testing.expectEqual(@as(u32, 1), collector.counters.items[0].values[7].toU32());
    try std.testing.expectEqual(@as(u32, 1), collector.counters.items[1].values[7].toU32());
}
