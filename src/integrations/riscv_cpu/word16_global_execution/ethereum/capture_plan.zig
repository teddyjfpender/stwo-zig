//! CPU-only candidate cost from the SAME source-bound accounting as production.
//! No fixed keys, prover inputs, proof or acceptance are constructed here.
const std = @import("std");
const C = @import("../services/gkr_local/coordinator.zig");
const P = @import("../services/protocol.zig");
const W = @import("../services/wire.zig");
const Bounds = @import("../services/gkr_local/source_bounds.zig");
const CaptureModule = @import("capture.zig");
const Capture = CaptureModule.Owner;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Plan = @import("plan.zig");
const Collector = @import("../services/collector.zig");
const Events = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event;

pub fn sourceBounds(a: std.mem.Allocator, program_log: u32, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, captured: *const Capture) !Bounds.Report {
    _ = try Bounds.validateInventory(cpu.len, truths.len);
    const requests = try a.alloc(P.Request, captured.native.items.len);
    defer a.free(requests);
    for (requests, 0..) |*value, i| {
        value.* = try C.requestView(captured.native.items, &captured.advice, i);
        try C.routeDword(value, cpu[i].bridges, captured.advice.events[i]);
    }
    try C.assignSpongeIds(requests);
    return Bounds.derive(a, program_log, cpu, truths, requests);
}

pub fn committedBits(cells: [3]u64) !u64 {
    return std.math.mul(u64, try std.math.add(u64, cells[1], cells[2]), 31);
}

pub const Result = struct {
    schema: []const u8 = "rv64-native-plan-cost/v1",
    scope: []const u8 = "source-derived native FIXED/MAIN/INTERACTION cells including padding; excludes PCS blowup, composition, openings, recursion, proof bytes and timing; no proof or acceptance",
    security_qualified: bool = false,
    proof_generated: bool = false,
    profile: []const u8,
    program_log: u32,
    prefix_count: u32,
    total_steps: u64,
    final_pc: u64,
    memory_words: usize,
    capture_ns: u64,
    capture_backing_peak_bytes: ?usize = null,
    streaming_capture_census: bool = false,
    cpu: []const W.CpuDeclaration,
    truths: []const W.TruthDeclaration,
    source_shape: Bounds.Shape,
    native_trace_cells: [3]u64,
    main_interaction_bits: u64,
    base_field_bits: u8 = 31,
    storage_bits_per_cell: u8 = 32,
};
pub fn result(a: std.mem.Allocator, profile: []const u8, program_log: u32, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, captured: *const Capture, prefix_count: u32, capture_ns: u64) !Result {
    var bounds = try sourceBounds(a, program_log, cpu, truths, captured);
    defer bounds.deinit();
    return resultWithBounds(profile, program_log, cpu, truths, captured, prefix_count, capture_ns, bounds.shape);
}
fn resultWithBounds(profile: []const u8, program_log: u32, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, captured: *const Capture, prefix_count: u32, capture_ns: u64, shape: Bounds.Shape) !Result {
    return .{ .profile = profile, .program_log = program_log, .prefix_count = prefix_count, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns, .cpu = cpu, .truths = truths, .source_shape = shape, .native_trace_cells = shape.native_trace_cells, .main_interaction_bits = try committedBits(shape.native_trace_cells) };
}

/// Geometry-only direct planning. The ordered ledger still sees every value
/// and computes the exact boundaries. Each shard contributes declarations and
/// counts before its witness buffers are released.
pub const Census = struct {
    allocator: std.mem.Allocator,
    layout: Plan.CpuLayout,
    cpus: std.ArrayList(W.CpuDeclaration) = .empty,
    requests: std.ArrayList(P.Request) = .empty,

    pub fn deinit(self: *Census) void {
        self.cpus.deinit(self.allocator);
        self.requests.deinit(self.allocator);
    }

    pub fn hook(self: *Census) CaptureModule.Ready {
        return .{ .context = self, .call = ignoreReady, .consume_shard = consume };
    }

    fn ignoreReady(_: *anyopaque, _: usize, _: *const Native, _: []const Events, _: u64) void {}

    fn consume(context: *anyopaque, ordinal: usize, native: *Native, shard: Collector.Shard) anyerror!void {
        const self: *Census = @ptrCast(@alignCast(context));
        if (ordinal != self.cpus.items.len or ordinal != self.requests.items.len)
            return error.InvalidCaptureCensusOrdinal;
        const cpu = try Plan.cpuForShard(native, shard, ordinal, ordinal + 1, 0, self.layout);
        var view = Collector.OneShardView.init(shard);
        const advice = view.advice(self.allocator, &.{}, &.{});
        var request = try C.requestView(&.{native}, &advice, 0);
        try C.routeDword(&request, cpu.bridges, shard.events);
        try self.cpus.ensureUnusedCapacity(self.allocator, 1);
        try self.requests.ensureUnusedCapacity(self.allocator, 1);
        self.cpus.appendAssumeCapacity(cpu);
        self.requests.appendAssumeCapacity(request);
    }

    pub fn finish(self: *Census, profile: []const u8, program_log: u32, captured: *const Capture, options: Plan.KeccakTruthOptions, max_log: u32, prefix_count: u32, capture_ns: u64) !Result {
        const cpu = self.cpus.items;
        const requests = self.requests.items;
        if (cpu.len == 0 or cpu.len != requests.len or captured.native.items.len != 0 or cpu.len != captured.advice.events.len)
            return error.InvalidCaptureCensusOrdinal;
        const boundary_log = try @import("../../word16_execution/coverage.zig").minimalBoundaryLog(@intCast(captured.advice.initial.len));
        cpu[0].geometry.initial_log = boundary_log;
        cpu[cpu.len - 1].geometry.terminal_log = boundary_log;
        try cpu[0].geometry.validate();
        try cpu[cpu.len - 1].geometry.validate();
        requests[0].base.memory.initial = captured.advice.initial;
        requests[requests.len - 1].base.memory.terminal = captured.advice.terminal;
        try C.assignSpongeIds(requests);
        var totals: [@import("../services/types.zig").FAMILIES]u32 = @splat(0);
        for (requests) |request| {
            for (&totals, request.calls) |*total, calls| total.* = try std.math.add(u32, total.*, calls);
            totals[0] = try std.math.add(u32, totals[0], request.sponge.perms);
        }
        const truths = try Plan.truthsForServiceCounts(self.allocator, totals, options, max_log);
        errdefer self.allocator.free(truths);
        var bounds = try Bounds.derive(self.allocator, program_log, cpu, truths, requests);
        defer bounds.deinit();
        var out = try resultWithBounds(profile, program_log, cpu, truths, captured, prefix_count, capture_ns, bounds.shape);
        out.streaming_capture_census = true;
        return out;
    }
};

test "candidate cost excludes fixed key cells and rejects sum or product overflow" {
    try std.testing.expectEqual(@as(u64, 217), try committedBits(.{ std.math.maxInt(u64), 3, 4 }));
    try std.testing.expectError(error.Overflow, committedBits(.{ 0, std.math.maxInt(u64), 1 }));
    try std.testing.expectError(error.Overflow, committedBits(.{ 0, std.math.maxInt(u64) / 31 + 1, 0 }));
}
