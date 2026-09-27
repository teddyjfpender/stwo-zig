//! Bounded two-pass producer for independently sized block memory proofs.
//! The external sorted run is reread after the complete fixed/main roster is
//! sealed; only one trace and PCS scheme are live in either pass.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const instance = @import("../air/block/memory_instance.zig");
const size_plan = @import("../air/block/memory_size_plan.zig");
const transition = @import("../air/block/memory_transition.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const memory_proof = @import("block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");
const batch_verify = @import("block_memory_batch_verify_v2.zig");

pub const Roots = [2][32]u8;

/// `open` must reopen the same immutable sorted event run from its beginning.
/// The returned Reader owns its file cursor and borrows any initial image in
/// `context`; the source must outlive both phases.
pub const SortedSource = struct {
    context: *anyopaque,
    open: *const fn (context: *anyopaque) anyerror!transition.Reader,
};

/// Called while a single proof is live. The sink must serialize/persist it
/// synchronously; the producer deinitializes it before moving to the next.
pub const ProofSink = struct {
    context: *anyopaque,
    write_memory: *const fn (context: *anyopaque, index: u32, claim: memory.Claim, proof: *const memory_proof.Proof) anyerror!void,
    write_table: *const fn (context: *anyopaque, shard: shard_mod.Shard, proof: *const table_proof.Proof) anyerror!void,
};

pub const FirstPass = struct {
    a: std.mem.Allocator,
    claims: []memory.Claim,
    memory_roots: []Roots,
    counters: []counter_mod.Counter,
    table_roots: []Roots,
    plan: shard_mod.Plan,
    total_events: u64,
    capacity_plan: []u32,
    minimum_log_size: u32,

    pub fn deinit(self: *FirstPass) void {
        self.a.free(self.capacity_plan);
        self.plan.deinit(self.a);
        self.a.free(self.table_roots);
        for (self.counters) |*counter| counter.deinit(self.a);
        self.a.free(self.counters);
        self.a.free(self.memory_roots);
        self.a.free(self.claims);
        self.* = undefined;
    }

    /// The execution/provider first-round roots are supplied by their own
    /// producers. This helper exports only the sorted-memory/table entries in
    /// canonical first-round digest order.
    pub fn memoryAndTableEntries(self: *const FirstPass, a: std.mem.Allocator) ![]seal_mod.FirstRoundEntry {
        const count = try std.math.add(usize, self.memory_roots.len, self.table_roots.len);
        const entries = try a.alloc(seal_mod.FirstRoundEntry, count);
        for (self.memory_roots, 0..) |roots, i|
            entries[i] = .{ .family = .memory, .index = @intCast(i), .roots = roots };
        for (self.table_roots, 0..) |roots, i|
            entries[self.memory_roots.len + i] = .{ .family = .range_table, .index = @intCast(i), .roots = roots };
        return entries;
    }
};

pub fn collectFirstPass(
    comptime Backend: type,
    a: std.mem.Allocator,
    source: SortedSource,
    total_events: u64,
    instance_capacity: u32,
    minimum_log_size: u32,
    config: core.pcs.PcsConfig,
) !FirstPass {
    if (instance_capacity == 0 or instance_capacity > 1 << 30 or
        !std.math.isPowerOfTwo(instance_capacity) or minimum_log_size < 1 or
        minimum_log_size > std.math.log2_int(u32, instance_capacity))
        return error.InvalidMemorySizePlan;
    var selected = try size_plan.select(a, total_events, minimum_log_size, std.math.log2_int(u32, instance_capacity));
    errdefer selected.deinit();
    var reader = try source.open(source.context);
    defer reader.deinit();
    var partitioner = try instance.Partitioner.initPlanned(&reader, total_events, selected.capacities);
    var claims = std.ArrayList(memory.Claim).empty;
    errdefer claims.deinit(a);
    var roots = std.ArrayList(Roots).empty;
    errdefer roots.deinit(a);
    var counters = std.ArrayList(counter_mod.Counter).empty;
    errdefer {
        for (counters.items) |*counter| counter.deinit(a);
        counters.deinit(a);
    }
    var shard_events: u64 = 0;
    const api = memory_proof.ForBackend(Backend);
    while (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, minimum_log_size)) |next_trace| {
        var trace = next_trace;
        defer trace.deinit();
        if (trace.claim.rows > shard_mod.MAX_EVENTS_PER_SHARD or claims.items.len >= std.math.maxInt(u32))
            return error.InvalidBlockMemoryInstanceCensus;
        if (counters.items.len == 0 or shard_events + trace.claim.rows > shard_mod.MAX_EVENTS_PER_SHARD) {
            var fresh = try counter_mod.Counter.init(a, .range_check_8_8);
            errdefer fresh.deinit(a);
            try counters.append(a, fresh);
            shard_events = 0;
        }
        const first = try api.commitFirstRoundRootsOnly(a, &trace, &counters.items[counters.items.len - 1], @intCast(claims.items.len), config);
        try claims.append(a, trace.claim);
        try roots.append(a, first.roots);
        shard_events += trace.claim.rows;
    }
    if (partitioner.emitted != total_events or !partitioner.finished) return error.InvalidBlockMemoryInstanceCensus;
    const owned_claims = try claims.toOwnedSlice(a);
    errdefer a.free(owned_claims);
    const owned_roots = try roots.toOwnedSlice(a);
    errdefer a.free(owned_roots);
    var plan = try shard_mod.plan(a, owned_claims, total_events);
    errdefer plan.deinit(a);
    if (plan.shards.len != counters.items.len) return error.InvalidBlockRangeShardCensus;
    const owned_counters = try counters.toOwnedSlice(a);
    errdefer {
        for (owned_counters) |*counter| counter.deinit(a);
        a.free(owned_counters);
    }
    const table_roots = try a.alloc(Roots, plan.shards.len);
    errdefer a.free(table_roots);
    const table_api = table_proof.ForBackend(Backend);
    for (plan.shards, owned_counters, table_roots) |shard, *counter, *table_root| {
        // Thirty-five is the maximum number of declared effects per event;
        // some order-gadget effects are disabled on the global first row.
        // Sum exact canonical multiplicities as integers before field use.
        var actual_requests: u64 = 0;
        for (counter.values) |value| {
            actual_requests = std.math.add(u64, actual_requests, value.toU32()) catch
                return error.InvalidBlockRangeCounterCensus;
        }
        if (actual_requests > shard.max_requests) return error.InvalidBlockRangeCounterCensus;
        var first = try table_api.commitFirstRound(a, counter, shard, config);
        table_root.* = first.roots;
        first.deinit(a);
    }
    return .{
        .a = a,
        .claims = owned_claims,
        .memory_roots = owned_roots,
        .counters = owned_counters,
        .table_roots = table_roots,
        .plan = plan,
        .total_events = total_events,
        .capacity_plan = selected.capacities,
        .minimum_log_size = minimum_log_size,
    };
}

pub fn proveSecondPass(
    comptime Backend: type,
    a: std.mem.Allocator,
    source: SortedSource,
    first: *const FirstPass,
    statement: batch_verify.PinnedStatement,
    config: core.pcs.PcsConfig,
    sink: ProofSink,
) !void {
    return proveSecondPassWithCancel(Backend, a, source, first, statement, config, sink, null);
}

/// Cooperative cancellation is checked between independently proved
/// instances. A concurrent execution failure need not wait for the entire
/// sorted-memory roster before its caller can return.
pub fn proveSecondPassWithCancel(
    comptime Backend: type,
    a: std.mem.Allocator,
    source: SortedSource,
    first: *const FirstPass,
    statement: batch_verify.PinnedStatement,
    config: core.pcs.PcsConfig,
    sink: ProofSink,
    cancelled: ?*const std.atomic.Value(bool),
) !void {
    var admitted_plan = try statement.validate(a);
    defer admitted_plan.deinit(a);
    if (statement.memory_instances.len != first.claims.len or
        statement.range_table_roots.len != first.table_roots.len or
        !std.meta.eql(admitted_plan.digest, first.plan.digest) or
        statement.expected_events != first.total_events)
        return error.UnsealedBlockProofRoster;
    for (statement.memory_instances, first.claims, first.memory_roots) |pin, claim, roots| {
        if (!std.meta.eql(pin.claim, claim) or !std.meta.eql(pin.roots, roots))
            return error.UnsealedBlockProofRoster;
    }
    for (statement.range_table_roots, first.table_roots) |trusted, actual| {
        if (!std.meta.eql(trusted, actual)) return error.UnsealedBlockProofRoster;
    }
    const sealed = statement.seal;
    var reader = try source.open(source.context);
    defer reader.deinit();
    var partitioner = try instance.Partitioner.initPlanned(&reader, first.total_events, first.capacity_plan);
    const api = memory_proof.ForBackend(Backend);
    for (first.claims, first.memory_roots, 0..) |claim, roots, index| {
        if (cancelled) |flag| if (flag.load(.acquire)) return error.CancelledParallelFamily;
        var trace = (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, first.minimum_log_size)) orelse
            return error.MemoryEventCensusUnderflow;
        defer trace.deinit();
        if (!std.meta.eql(trace.claim, claim)) return error.BlockMemoryClaimReplayMismatch;
        var replay = try api.replayFirstRound(a, &trace, @intCast(index), roots, config);
        defer replay.deinit(a);
        var proof = try api.prove(a, &replay, &trace, sealed, @intCast(index), roots);
        defer proof.deinit(a);
        try sink.write_memory(sink.context, @intCast(index), claim, &proof);
    }
    if (!partitioner.finished or partitioner.emitted != first.total_events or
        (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, first.minimum_log_size)) != null)
        return error.InvalidBlockMemoryInstanceCensus;
    const table_api = table_proof.ForBackend(Backend);
    for (first.plan.shards, first.counters, first.table_roots) |shard, *counter, roots| {
        if (cancelled) |flag| if (flag.load(.acquire)) return error.CancelledParallelFamily;
        var replay = try table_api.replayFirstRound(a, counter, shard, roots, config);
        defer replay.deinit(a);
        var proof = try table_api.prove(a, &replay, counter, shard, sealed, roots);
        defer proof.deinit(a);
        try sink.write_table(sink.context, shard, &proof);
    }
}
