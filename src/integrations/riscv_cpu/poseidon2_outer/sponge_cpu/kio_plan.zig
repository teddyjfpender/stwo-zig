//! Bounded view of the EXISTING canonical proof ID policy: all direct Keccak
//! calls in CPU order, then Sponge permutations in CPU/call order. Execution
//! retirement IDs are deliberately not this proof-local permutation space.
//! This is a deterministic producer/receiver planning convention, not an AIR
//! theorem about each CPU's permutation count. In the detached construction
//! only per-CPU call tuples and aggregate P/global IO are physical authority.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("../../word16_global_execution/services/protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Advice = @import("../../word16_global_execution/services/collector.zig").Advice;
pub const Limits = struct { cpus: usize = 256, max_inputs: u32 = 1 << 24 };
pub const Span = struct { first: u32, count: u32 };
pub const Input = struct { kind: enum { direct, sponge }, cpu: u32, index: u32 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    direct: []Span,
    sponge: []Span,
    calls: []u32,
    total_direct: u32,
    total_sponge: u32,
    detached_first: u32,
    pub fn init(a: std.mem.Allocator, requests: []const P.Request, limits: Limits) !Plan {
        if (limits.cpus == 0 or limits.cpus > 256 or requests.len == 0 or requests.len > limits.cpus or limits.max_inputs == 0 or limits.max_inputs >= core.fields.m31.Modulus) return error.SpongeKioPlanLimit;
        var direct: u64 = 0;
        var sponge: u64 = 0;
        for (requests, 0..) |request, ordinal| {
            if (request.base.epoch != ordinal + 1) return error.SpongeKioEpoch;
            if ((request.sponge.calls == 0) != (request.sponge.perms == 0) or request.sponge.perms < request.sponge.calls) return error.SpongeKioCallCoverage;
            if (@as(u64, request.calls[0]) + request.sponge.calls > request.base.cpu.steps) return error.SpongeKioCallCoverage;
            direct = try std.math.add(u64, direct, request.calls[0]);
            sponge = try std.math.add(u64, sponge, request.sponge.perms);
        }
        const input_total = try std.math.add(u64, direct, sponge);
        if (input_total > limits.max_inputs or input_total + 1 >= core.fields.m31.Modulus) return error.SpongeKioPlanLimit;
        // Reuse the qualified allocator, rather than add a second ID policy.
        // These are bounded shallow views only; nested public cells are borrowed.
        const canonical = try a.dupe(P.Request, requests);
        defer a.free(canonical);
        try Coordinator.assignSpongeIds(canonical);
        const direct_spans = try a.alloc(Span, requests.len);
        errdefer a.free(direct_spans);
        const sponge_spans = try a.alloc(Span, requests.len);
        errdefer a.free(sponge_spans);
        const calls = try a.alloc(u32, requests.len);
        errdefer a.free(calls);
        var first: u32 = 1;
        for (canonical, direct_spans, sponge_spans, calls) |request, *d, *s, *count| {
            // Direct first IDs retain the existing nonzero cursor even when
            // a CPU has zero direct calls; absent Sponge first ID is exactly0.
            d.* = .{ .first = first, .count = request.calls[0] };
            first += request.calls[0];
            s.* = .{ .first = if (request.sponge.any()) request.sponge.first_id else 0, .count = request.sponge.perms };
            count.* = request.sponge.calls;
        }
        return .{ .allocator = a, .direct = direct_spans, .sponge = sponge_spans, .calls = calls, .total_direct = @intCast(direct), .total_sponge = @intCast(sponge), .detached_first = if (sponge == 0) 0 else @intCast(direct + 1) };
    }
    pub fn total(self: *const Plan) u32 {
        return self.total_direct + self.total_sponge;
    }
    pub fn requireRequests(self: *const Plan, requests: []const P.Request) !void {
        if (requests.len != self.direct.len) return error.SpongeKioCallCoverage;
        for (requests, self.direct, self.sponge, self.calls, 0..) |r, d, s, calls, ordinal| {
            if (r.base.epoch != ordinal + 1 or r.calls[0] != d.count or r.sponge.calls != calls or r.sponge.perms != s.count or r.sponge.first_id != s.first) return error.SpongeKioCallCoverage;
        }
    }
    /// The CPU bridge ID is outside P.Request. This checks its KIO coordinate;
    /// other families remain the caller's original inventory authority.
    pub fn requireFirstIds(self: *const Plan, first: []const [@import("../../word16_global_execution/services/types.zig").FAMILIES]u32) !void {
        if (first.len != self.direct.len) return error.SpongeKioCallCoverage;
        for (first, self.direct) |ids, expected| if (ids[0] != expected.first) return error.SpongeKioCallCoverage;
    }
    /// Exact ordered physical truth coverage; zero-input executions have no
    /// truth spans. A duplicated span cannot stand in for a missing interval.
    pub fn requireTruthCoverage(self: *const Plan, spans: []const Span) !void {
        var next: u64 = 1;
        for (spans) |span| {
            if (span.count == 0 or span.first != next) return error.SpongeKioTruthCoverage;
            next = try std.math.add(u64, next, span.count);
            if (next > @as(u64, self.total()) + 1) return error.SpongeKioTruthCoverage;
        }
        if (next != @as(u64, self.total()) + 1) return error.SpongeKioTruthCoverage;
    }
    pub fn validateAdvice(self: *const Plan, advice: *const Advice) !void {
        if (advice.keccak.len != self.direct.len or advice.sponge.len != self.sponge.len) return error.SpongeKioAdviceCoverage;
        for (self.direct, self.sponge, self.calls, advice.keccak, advice.sponge) |d, s, calls, direct, sponge| {
            if (direct.len != d.count or sponge.calls.len != calls or sponge.inputs.len != s.count) return error.SpongeKioAdviceCoverage;
        }
    }
    /// This is also the order already implemented by roster.TruthSource.init.
    /// Mapping carries no witness values and allocates no reordered state plane.
    pub fn resolve(self: *const Plan, index: u32) !Input {
        if (index >= self.total()) return error.SpongeKioInputRange;
        const id = index + 1;
        const spans = if (index < self.total_direct) self.direct else self.sponge;
        for (spans, 0..) |span, ordinal| if (span.count != 0 and id >= span.first and id - span.first < span.count) return .{ .kind = if (index < self.total_direct) .direct else .sponge, .cpu = @intCast(ordinal), .index = id - span.first };
        return error.SpongeKioInputRange;
    }
    pub fn emit(self: *const Plan, writer: anytype) void {
        writer.tag(0x4b494f50);
        writer.tag(1);
        writer.integer(self.direct.len);
        writer.integer(self.total_direct);
        writer.integer(self.total_sponge);
        for (self.direct, self.sponge, self.calls, 0..) |d, s, calls, ordinal| {
            writer.integer(ordinal);
            writer.integer(d.first);
            writer.integer(d.count);
            writer.integer(s.first);
            writer.integer(s.count);
            writer.integer(calls);
        }
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.calls);
        self.allocator.free(self.sponge);
        self.allocator.free(self.direct);
        self.* = undefined;
    }
};
fn requestsForTest() [3]P.Request {
    var requests: [3]P.Request = @splat(std.mem.zeroes(P.Request));
    for (&requests, 0..) |*r, i| {
        r.base.epoch = @intCast(i + 1);
        r.base.cpu.steps = 5;
    }
    requests[0].calls[0] = 1;
    requests[0].sponge = .{ .calls = 1, .perms = 3 };
    requests[1].calls[0] = 1; // Retired after CPU0's Sponge, proved before it.
    requests[1].sponge = .{ .calls = 2, .perms = 2 };
    return requests;
}
test "sponge CPU canonical KIO policy reuses existing prefixes across retirement holes" {
    const a = std.testing.allocator;
    var requests = requestsForTest();
    var plan = try Plan.init(a, &requests, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 3), plan.detached_first);
    try std.testing.expectEqualDeep(Span{ .first = 1, .count = 1 }, plan.direct[0]);
    try std.testing.expectEqualDeep(Span{ .first = 2, .count = 1 }, plan.direct[1]);
    try std.testing.expectEqualDeep(Span{ .first = 3, .count = 3 }, plan.sponge[0]);
    try std.testing.expectEqualDeep(Span{ .first = 6, .count = 2 }, plan.sponge[1]);
    try std.testing.expectEqualDeep(Span{ .first = 0, .count = 0 }, plan.sponge[2]);
    try Coordinator.assignSpongeIds(&requests);
    try plan.requireRequests(&requests);
    var first: [3][@import("../../word16_global_execution/services/types.zig").FAMILIES]u32 = @splat(@splat(1));
    for (&first, plan.direct) |*ids, span| ids[0] = span.first;
    try plan.requireFirstIds(&first);
    first[1][0] += 1;
    try std.testing.expectError(error.SpongeKioCallCoverage, plan.requireFirstIds(&first));
    try plan.requireTruthCoverage(&.{ .{ .first = 1, .count = 2 }, .{ .first = 3, .count = 5 } });
    try std.testing.expectEqualDeep(Input{ .kind = .direct, .cpu = 1, .index = 0 }, try plan.resolve(1));
    try std.testing.expectEqualDeep(Input{ .kind = .sponge, .cpu = 0, .index = 0 }, try plan.resolve(2));
    try std.testing.expectEqualDeep(Input{ .kind = .sponge, .cpu = 1, .index = 1 }, try plan.resolve(6));
    try std.testing.expectError(error.SpongeKioInputRange, plan.resolve(7));
    try std.testing.expectError(error.SpongeKioTruthCoverage, plan.requireTruthCoverage(&.{ .{ .first = 1, .count = 2 }, .{ .first = 4, .count = 4 } }));
    try std.testing.expectError(error.SpongeKioTruthCoverage, plan.requireTruthCoverage(&.{ .{ .first = 1, .count = 2 }, .{ .first = 1, .count = 5 } }));
    requests[1].sponge.first_id -= 1;
    try std.testing.expectError(error.SpongeKioCallCoverage, plan.requireRequests(&requests));
}
test "sponge CPU KIO policy bounds zero calls and overflowing or malformed counts" {
    const a = std.testing.allocator;
    var requests = requestsForTest();
    for (&requests) |*r| {
        r.calls[0] = 0;
        r.sponge = .{};
    }
    var zero = try Plan.init(a, &requests, .{});
    defer zero.deinit();
    try std.testing.expectEqual(@as(u32, 0), zero.total());
    try zero.requireTruthCoverage(&.{});
    try std.testing.expectError(error.SpongeKioTruthCoverage, zero.requireTruthCoverage(&.{.{ .first = 1, .count = 0 }}));
    try std.testing.expectError(error.SpongeKioPlanLimit, Plan.init(a, &requests, .{ .cpus = 257 }));
    requests[0].sponge.perms = 1;
    try std.testing.expectError(error.SpongeKioCallCoverage, Plan.init(a, &requests, .{}));
    requests = requestsForTest();
    requests[0].calls[0] = std.math.maxInt(u32);
    requests[0].sponge = .{};
    requests[0].base.cpu.steps = std.math.maxInt(u32);
    try std.testing.expectError(error.SpongeKioPlanLimit, Plan.init(a, &requests, .{}));
    requests = requestsForTest();
    try std.testing.expectError(error.SpongeKioPlanLimit, Plan.init(a, &requests, .{ .max_inputs = 6 }));
}
