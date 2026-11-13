//! One canonical owner for coordinator records and their destruction rules.
//! Operational early-source specializations must borrow these types, never
//! instantiate another copy of Bundle, Stream or encoded proof records.
pub const Store = @import("../../retained_main_store.zig").Store;
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Pipeline = @import("../pipeline.zig");
const Advice = @import("../collector.zig").Advice;
const Native = @import("../../../word16_execution/prepared.zig").Prepared;

const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const W = @import("worker_protocol.zig");
const CPU = @import("cpu_worker.zig");
const Truth = @import("truth_worker.zig");
const FixedSet = @import("fixed_authority_set.zig").Set;
const Manifest = @import("manifest.zig");
const Execution = @import("execution.zig");
pub const WorkerTiming = struct {
    retained_local_binding_bytes: usize = 0,
    retained_local_projection_bytes: usize = 0,
    final_local_binding_bytes: usize = 0,
    deferred_binding_overlap_bytes: usize = 0,
    gkr_peak_including_final_binding_bytes: usize = 0,
    local_binding_completed: bool = false,
    resolved_tree_policy: ?@import("child.zig").TreePolicy = null,
    source_ns: u64 = 0,
    /// Observation only: nanoseconds since `Options.epoch` when this worker's
    /// witness source build began / its prover inputs were ready. Zero without
    /// an epoch. Never proof or schedule authority.
    source_begin_ns: u64 = 0,
    source_ready_ns: u64 = 0,
    seal_native_and_gkr_ns: u64 = 0,
    main_commit_ns: u64 = 0,
    early_source_and_main_ns: u64 = 0,
    early_main_commit_before_inventory: bool = false,
    gkr_ns: u64 = 0,
    inputs_ns: u64 = 0,
    numerical_ns: u64 = 0,
    binding_ns: u64 = 0,
    numerical_requested_peak_bytes: usize = 0,
    including_binding_requested_peak_bytes: usize = 0,
    admitted_gkr_peak_bytes: usize = 0,
    gkr_allocator_limit_bytes: usize = 0,
    metadata_retire_ns: u64 = 0,
    spill_ns: u64 = 0,
    restore_ns: u64 = 0,
    native_complete_ns: u64 = 0,
    stage1_ns: u64 = 0,
    stage2_ns: u64 = 0,
    actual_main_merkle_bytes: usize = 0,
    retired_memory_event_bytes: usize = 0,
    memory_event_retire_ns: u64 = 0,
    stage1_completed: bool = false,
    stage2_completed: bool = false,
    completed_worker_retired: bool = false,
};

pub const Stream = struct {
    context: *anyopaque,
    sealed: *const fn (context: *anyopaque, requests: []const P.Request, stage_one_bytes: []const u8) void,
    cpu_done: *const fn (context: *anyopaque, ordinal: usize, encoded: *const CPU.CpuEncoded) void,
    truth_done: *const fn (context: *anyopaque, ordinal: usize, encoded: *const Truth.TruthEncoded) void,
    abort: *const fn (context: *anyopaque) void,
};

pub const NativeStageTwo = struct {
    context: *anyopaque,
    stage_two: *const fn (context: *anyopaque, a: std.mem.Allocator, worker: *CPU.CpuWorker, pending: *const Manifest.PendingManifest, index: usize, global_budget: usize) anyerror!CPU.CpuEncoded,
};

pub const Bundle = struct {
    requests: []P.Request,
    stage_one_bytes: []u8,
    cpus: []CPU.CpuEncoded,
    truths: []Truth.TruthEncoded,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.cpus) |*v| v.deinit(a);
        for (self.truths) |*v| v.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        a.free(self.stage_one_bytes);
        freeRequests(a, self.requests);
        self.* = undefined;
    }
    pub fn verify(self: *const Bundle, a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig) !Execution.Verified {
        return Execution.verify(a, setups, truths, self.requests, expected, config, self.stage_one_bytes, self.cpus, self.truths);
    }
    pub fn verifyWithAuthority(self: *const Bundle, a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig, fixed: *const FixedSet) !Execution.Verified {
        return Execution.verifyWithAuthority(a, setups, truths, self.requests, expected, config, self.stage_one_bytes, self.cpus, self.truths, fixed);
    }
};

pub fn freeRequests(a: std.mem.Allocator, requests: []P.Request) void {
    for (requests) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    }
    a.free(requests);
}
pub const Worker = union(enum) {
    cpu: CPU.CpuWorker,
    truth: Truth.TruthWorker,
    delegation: @import("truth_v3_worker.zig").NativeTruthWorker,
    pub fn deinit(self: *Worker, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};

pub const Result = union(enum) {
    cpu: CPU.CpuEncoded,
    truth: Truth.TruthEncoded,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};

pub fn requestView(native: []const *Native, advice: *const Advice, i: usize) !P.Request {
    if (i >= native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len or native.len != advice.sha256.len or native.len != advice.arith256_mod.len or native.len != advice.curves.len or native.len != advice.bulk.len or native.len != advice.sponge.len) return error.InvalidCombinedInventory;
    const n = native[i];
    const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
    return .{ .calls = Pipeline.adviceCalls(advice, i), .bulk = advice.bulk[i].counts(), .sponge = advice.sponge[i].counts(), .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (i == 0) advice.initial else &.{}, .terminal = if (i + 1 == native.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[i].len) } } };
}

pub fn requestsFrom(a: std.mem.Allocator, setups: []const *const R.CpuSetup, native: []const *Native, advice: *const Advice) ![]P.Request {
    const requests = try a.alloc(P.Request, native.len);
    errdefer a.free(requests);
    var done: usize = 0;
    errdefer for (requests[0..done]) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    };
    for (requests, 0..) |*r, i| {
        var request = try requestView(native, advice, i);
        try routeDword(&request, setups[i].bridges, advice.events[i]);
        const initial = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.initial);
        errdefer a.free(initial);
        const terminal = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.terminal);
        request.base.memory.initial = initial;
        request.base.memory.terminal = terminal;
        r.* = request;
        done += 1;
        // Faithful counts first (requestView), then fail closed on any v3 advice.
        try @import("service_scope.zig").request(r.*);
    }
    try assignSpongeIds(requests);
    return requests;
}

pub fn mainNodes(scheme: *const W.Scheme) !usize {
    // Device MAIN occupies a logical trace slot, not a host PCS tree. Its
    // Merkle backing belongs to the device allocator, outside this host count.
    if (scheme.device_om31_trace_trees[1] != null) return 0;
    if (scheme.trees.items.len <= 1) return error.MissingPhysicalMainCommitment;
    var bytes: usize = 0;
    for (scheme.trees.items[1].commitment.layers) |layer| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, layer.len, @sizeOf(W.H.Hash)));
    return bytes;
}

pub fn buildInputsOnly(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, epoch: ?std.time.Instant, timings: []WorkerTiming, admitted_at_ns: *u64) !void {
    const count = try std.math.add(usize, setups.len, truths.len);
    if (timings.len != count) return error.InvalidWideCoordinatorTimings;
    if (setups.len == 0 or setups.len != native.len) return error.InvalidCombinedInventory;
    @memset(timings, .{});
    const requests = try requestsFrom(a, setups, native, advice);
    defer freeRequests(a, requests);
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
    defer inventory.deinit();
    admitted_at_ns.* = sinceEpoch(epoch);
    for (timings, 0..) |*t, index| {
        t.source_begin_ns = sinceEpoch(epoch);
        if (index < setups.len) {
            var source = try Pipeline.buildCpuSource(a, setups[index], requests[index], native[index], advice, index, inventory.first_ids[index], false, null);
            t.source_ready_ns = sinceEpoch(epoch);
            source.deinit();
        } else {
            var source = try R.TruthSource.init(a, truths[index - setups.len], advice);
            t.source_ready_ns = sinceEpoch(epoch);
            source.deinit();
        }
        t.source_ns = t.source_ready_ns - t.source_begin_ns;
    }
}

/// Observation clock only; zero when no epoch was supplied or the clock fails.
pub fn sinceEpoch(epoch: ?std.time.Instant) u64 {
    const origin = epoch orelse return 0;
    const now = std.time.Instant.now() catch return 0;
    return now.since(origin);
}

pub fn routeDword(request: *P.Request, logs: @import("../types.zig").Logs, events: []const A.memory.load_store_v2.native.Event) !void {
    if (logs.ls_dword != null) {
        request.ls_dword = Pipeline.dwordCount(events);
        if (request.ls_dword > request.base.memory.ls_count) return error.InvalidCombinedServiceCount;
        request.base.memory.ls_count -= request.ls_dword;
    }
}

pub fn assignSpongeIds(requests: []P.Request) !void {
    var next: u64 = 1;
    for (requests) |r| next = try std.math.add(u64, next, r.calls[0]);
    for (requests) |*r| if (r.sponge.any()) {
        r.sponge.first_id = std.math.cast(u32, next) orelse return error.CombinedLookupMassExceeded;
        next = try std.math.add(u64, next, r.sponge.perms);
    };
}
