//! Future consumer headroom follows the allocation owner's final scope.
//! retireAfterDestruction is called only after checked physical lease cleanup.
const std = @import("std");
const A = @import("global_admission.zig");
const R = @import("admission_runtime.zig");
pub const Scope = [8]u32;
const Claim = struct { scope: Scope, token: A.Token };
pub const Registry = struct {
    mutex: std.Thread.Mutex = .{},
    claims: std.ArrayList(Claim) = .empty,
    pub fn complete(self: *Registry, a: std.mem.Allocator, permit: *R.Permit, scope: Scope, successor: A.Footprint) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        errdefer permit.endpoint.planner.poisonPhysical(permit.endpoint.physical);
        const retained = successor.large != 0 or successor.small != 0;
        // Admit host metadata before completing the permit. Allocation failure
        // cannot leave an unregistered inactive claim after the stage succeeds.
        if (retained) try self.claims.ensureUnusedCapacity(a, 1);
        try permit.finish(successor);
        if (retained) self.claims.appendAssumeCapacity(.{ .scope = scope, .token = permit.token });
    }
    /// The actual lease rebind must succeed before this metadata migration.
    pub fn promoted(self: *Registry, old: Scope, next: Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.claims.items) |*claim| if (std.mem.eql(u32, &claim.scope, &old)) {
            claim.scope = next;
        };
    }
    /// Call only after ALL allocations owned by this scope have been freed and
    /// joined successfully. A failed owner submission must never reach here.
    pub fn retireAfterDestruction(self: *Registry, planner: *A.Planner, scope: Scope) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var i: usize = 0;
        while (i < self.claims.items.len) {
            const claim = self.claims.items[i];
            if (!std.mem.eql(u32, &claim.scope, &scope)) {
                i += 1;
                continue;
            }
            try planner.release(claim.token);
            _ = self.claims.swapRemove(i);
        }
    }
    /// Only the successful context destructor authorizes final claim retirement.
    pub fn contextDestroyed(self: *Registry, planner: ?*A.Planner) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.claims.items.len != 0) {
            const claim = self.claims.items[self.claims.items.len - 1];
            try (planner orelse return error.MissingRetentionPlanner).release(claim.token);
            _ = self.claims.pop();
        }
    }
    /// Failed native cleanup leaves allocations owned by the poisoned native
    /// context until terminal pool destruction. Forget only local metadata;
    /// planner entries remain charged and cannot authorize subsequent work.
    pub fn abandonToPoisonedPool(self: *Registry, planner: *A.Planner) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.claims.items) |claim| if (planner.healthy(claim.token.physical)) return error.CannotAbandonLiveAdmissionClaims;
        self.claims.clearRetainingCapacity();
    }
    pub fn deinit(self: *Registry, a: std.mem.Allocator) void {
        std.debug.assert(self.claims.items.len == 0);
        self.claims.deinit(a);
    }
};

test "scope future claim survives until final physical owner retirement" {
    var p = try A.Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    var registry: Registry = .{};
    defer registry.deinit(std.testing.allocator);
    const demand = A.Demand{ .owner = .{ .request = 1, .domain = .native_packet, .ordinal = 7 }, .stage = .trace_commit, .known = true, .host_known = true, .temporary = try A.Footprint.allocation(1 << 30), .successor = try A.Footprint.allocation(15 << 30) };
    const token = (try p.tryBegin(0, demand)).token.?;
    try p.completeObserved(token, demand.temporary, demand.successor);
    try registry.claims.append(std.testing.allocator, .{ .scope = @splat(1), .token = token });
    // A release notification and cleanup of an unrelated alias scope do not
    // authorize removal of this allocation owner's future consumer envelope.
    p.notifyResourceRelease();
    try registry.retireAfterDestruction(&p, @splat(0));
    try std.testing.expectEqual(@as(usize, 1), (try p.snapshot(0)).owners);
    registry.promoted(@splat(1), @splat(2));
    try registry.retireAfterDestruction(&p, @splat(1));
    try std.testing.expectEqual(@as(usize, 1), (try p.snapshot(0)).owners);
    try registry.retireAfterDestruction(&p, @splat(2));
    try std.testing.expectEqual(@as(usize, 0), (try p.snapshot(0)).owners);
    // Byte retention is reconciled separately from the successor token. A
    // token release cannot silently erase physical allocations from the ledger.
    try std.testing.expectEqual(demand.temporary.large, (try p.snapshot(0)).retained.large);
    try p.observeIdle(0, .{});
    try std.testing.expectEqual(@as(u64, 0), (try p.snapshot(0)).retained.large);
}

test "failed source cleanup keeps planner claim until poisoned pool destruction" {
    var p = try A.Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    var registry: Registry = .{};
    defer registry.deinit(std.testing.allocator);
    const demand = A.Demand{ .owner = .{ .request = 1, .domain = .recursion_node, .ordinal = 0 }, .stage = .witness, .known = true, .host_known = true, .temporary = try A.Footprint.allocation(1 << 30), .successor = try A.Footprint.allocation(2 << 30) };
    const token = (try p.tryBegin(0, demand)).token.?;
    try p.completeObserved(token, demand.temporary, demand.successor);
    try registry.claims.append(std.testing.allocator, .{ .scope = @splat(3), .token = token });
    try std.testing.expectError(error.CannotAbandonLiveAdmissionClaims, registry.abandonToPoisonedPool(&p));
    p.poisonPhysical(0);
    try registry.abandonToPoisonedPool(&p);
    try std.testing.expectEqual(@as(usize, 1), (try p.snapshot(0)).owners);
    p.poolDestroyed();
    try std.testing.expectEqual(@as(usize, 0), (try p.snapshot(0)).owners);
}
