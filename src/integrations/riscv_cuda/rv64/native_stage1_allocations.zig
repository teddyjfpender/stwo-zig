//! Before-mutation allocation inventory for the exclusive early CPU0 path.
//! It closes transient coverage that a post-join arena snapshot cannot show.
//! Source phase ordering supplies the audited compact-input retirement seam.
const std = @import("std");
const Cost = @import("native_source_cost.zig");
pub const Phase = enum { projection, source, commit };
fn phase(owner: Cost.Owner) Phase {
    return switch (owner) {
        .immutable_rom, .cpu_scratch, .cpu_evaluations, .compact_ingress => .projection,
        .commit_workspace, .committed_coefficients => .commit,
        else => .source,
    };
}
pub const Guard = struct {
    mutex: std.Thread.Mutex = .{},
    plan: ?*const Cost.Plan = null,
    scope: [8]u32 = @splat(0),
    current: Phase = .projection,
    consumed: [256]bool = @splat(false),
    pub fn begin(self: *Guard, plan: *const Cost.Plan, scope: [8]u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.plan != null or std.mem.allEqual(u32, &scope, 0) or plan.count == 0 or plan.count > self.consumed.len) return error.InvalidEarlyAllocationGuard;
        self.plan = plan;
        self.scope = scope;
        self.current = .projection;
        @memset(&self.consumed, false);
    }
    /// No active ticket means ordinary proving is unaffected. An active guard
    /// rejects a foreign namespace or an unplanned/repeated allocation BEFORE
    /// the native allocator or CUDA launch can mutate state.
    pub fn allocate(self: *Guard, scope: [8]u32, words: u64, kind: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const plan = self.plan orelse return;
        if (!std.mem.eql(u32, &scope, &self.scope)) return error.ForeignEarlyAllocationScope;
        for (plan.list(), 0..) |allocation, i| {
            if (!self.consumed[i] and phase(allocation.owner) == self.current and allocation.words == words and allocation.kind == kind) {
                self.consumed[i] = true;
                return;
            }
        }
        std.debug.print("GPU_EARLY_MAIN_ALLOCATION_REFUSED phase={s} words={} kind={}\n", .{ @tagName(self.current), words, kind });
        return error.UnplannedEarlyStageAllocation;
    }
    fn completePhase(self: *Guard, p: Phase) !void {
        const plan = self.plan.?;
        for (plan.list(), 0..) |allocation, i| {
            // Conservative cold ROM is the only optional allocation. A real
            // cache hit pins its existing immutable owner instead of growing.
            if (phase(allocation.owner) == p and allocation.owner != .immutable_rom and !self.consumed[i]) {
                std.debug.print("GPU_EARLY_MAIN_ALLOCATION_MISSING phase={s} owner={s} words={} kind={}\n", .{ @tagName(p), @tagName(allocation.owner), allocation.words, allocation.kind });
                return error.MissingEarlyStageAllocation;
            }
        }
    }
    pub fn advance(self: *Guard, scope: [8]u32, next: Phase) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.plan == null) return;
        if (!std.mem.eql(u32, &scope, &self.scope)) return error.ForeignEarlyAllocationScope;
        if (@intFromEnum(next) != @as(u32, @intFromEnum(self.current)) + 1) return error.InvalidEarlyAllocationPhase;
        try self.completePhase(self.current);
        self.current = next;
    }
    pub fn finish(self: *Guard, plan: *const Cost.Plan) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.plan != plan or self.current != .commit) return error.InvalidEarlyAllocationPhase;
        try self.completePhase(.commit);
        self.plan = null;
    }
    /// Only after unpublished physical owners have joined/destructed on error.
    pub fn cancelDestroyed(self: *Guard, plan: *const Cost.Plan) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.plan == null or self.plan == plan);
        if (self.plan == plan) self.plan = null;
    }
};
fn fixture() Cost.Plan {
    var p = Cost.Plan{ .binding = @splat(7), .trace = undefined };
    p.allocations[0] = .{ .owner = .immutable_rom, .words = 1024, .kind = 4, .release = .immutable_release };
    p.allocations[1] = .{ .owner = .cpu_scratch, .words = 111, .kind = 0, .release = .main_adopt_join };
    p.allocations[2] = .{ .owner = .cpu_evaluations, .words = 222, .kind = 1, .release = .main_adopt_join };
    p.allocations[3] = .{ .owner = .core_input, .words = 111, .kind = 0, .release = .main_adopt_join };
    p.allocations[4] = .{ .owner = .core_output, .words = 333, .kind = 1, .release = .main_adopt_join };
    p.allocations[5] = .{ .owner = .commit_workspace, .words = 444, .kind = 0, .release = .main_adopt_join };
    p.allocations[6] = .{ .owner = .committed_coefficients, .words = 555, .kind = 2, .release = .worker_destroy };
    p.count = 7;
    return p;
}
test "early allocation inventory accepts within-phase order and optional cold ROM" {
    const p = fixture();
    var g = Guard{};
    const scope: [8]u32 = @splat(7);
    try g.begin(&p, scope);
    try g.allocate(scope, 222, 1);
    try g.allocate(scope, 111, 0);
    try g.advance(scope, .source);
    try g.allocate(scope, 333, 1);
    try g.allocate(scope, 111, 0);
    try g.advance(scope, .commit);
    try g.allocate(scope, 444, 0);
    try g.allocate(scope, 555, 2);
    try g.finish(&p);
    try g.allocate(@splat(8), 999, 0); // Inactive, ordinary work unaffected.
}
test "early allocation guard refuses temporary omission duplication phase and namespace mutants" {
    const p = fixture();
    var g = Guard{};
    const scope: [8]u32 = @splat(7);
    try g.begin(&p, scope);
    defer g.cancelDestroyed(&p);
    try std.testing.expectError(error.ForeignEarlyAllocationScope, g.allocate(@splat(8), 111, 0));
    try std.testing.expectError(error.UnplannedEarlyStageAllocation, g.allocate(scope, 112, 0));
    try std.testing.expectError(error.UnplannedEarlyStageAllocation, g.allocate(scope, 111, 1));
    try std.testing.expectError(error.UnplannedEarlyStageAllocation, g.allocate(scope, 333, 1));
    try g.allocate(scope, 111, 0);
    try std.testing.expectError(error.UnplannedEarlyStageAllocation, g.allocate(scope, 111, 0));
    try std.testing.expectError(error.MissingEarlyStageAllocation, g.advance(scope, .source));
    try g.allocate(scope, 222, 1);
    try std.testing.expectError(error.InvalidEarlyAllocationPhase, g.advance(scope, .commit));
    try g.advance(scope, .source);
    try g.allocate(scope, 111, 0);
    try g.allocate(scope, 333, 1);
    try g.advance(scope, .commit);
    try g.allocate(scope, 444, 0);
    try std.testing.expectError(error.MissingEarlyStageAllocation, g.finish(&p));
}
