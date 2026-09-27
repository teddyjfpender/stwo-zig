//! Shared local ownership for one arena referenced by multiple FRI trees.
//! References are acquired explicitly; copying a Ref does not retain it.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;
const allocation_policy = @import("fri_allocation_policy_v1.zig");

pub const Owner = struct {
    allocator: std.mem.Allocator,
    reservation: external.Reservation,
    references: std.atomic.Value(usize) = .init(1),
    binding: allocation_policy.Binding,

    /// Consumes only on success. Heap control bytes are charged through a.
    pub fn create(a: std.mem.Allocator, reservation: *external.Reservation) !Ref {
        return createWithPolicy(a, reservation, .require_shared_budget);
    }
    pub fn createWithPolicy(a: std.mem.Allocator, reservation: *external.Reservation, policy: allocation_policy.Policy) !Ref {
        // Keep the strict API's established owner-mismatch error surface.
        if (policy == .require_shared_budget) try reservation.requireOwner(a, reservation.bytes);
        const binding = try allocation_policy.Binding.init(a, policy);
        try binding.require(a, reservation, reservation.bytes);
        const owner = try a.create(Owner);
        owner.* = .{ .allocator = a, .reservation = reservation.take(), .binding = binding };
        return .{ .owner = owner };
    }
};

pub const Ref = struct {
    owner: ?*Owner = null,
    pub fn take(self: *Ref) Ref {
        const moved = self.*;
        self.* = .{};
        return moved;
    }
    pub fn retain(self: *const Ref) !Ref {
        const owner = self.owner orelse return error.FriArenaReleased;
        var seen = owner.references.load(.monotonic);
        while (true) {
            if (seen == 0 or seen == std.math.maxInt(usize)) return error.InvalidFriArenaReferenceCount;
            if (owner.references.cmpxchgWeak(seen, seen + 1, .monotonic, .monotonic)) |actual| seen = actual else break;
        }
        return .{ .owner = owner };
    }
    pub fn requireOwner(self: *const Ref, a: std.mem.Allocator, bytes: usize) !void {
        const owner = self.owner orelse return error.FriArenaReleased;
        try owner.binding.require(a, &owner.reservation, bytes);
    }
    pub fn deinit(self: *Ref) void {
        const owner = self.owner orelse return;
        self.owner = null;
        const previous = owner.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            // The reservation retains the allocator until its control is freed.
            var reservation = owner.reservation.take();
            const a = owner.allocator;
            a.destroy(owner);
            reservation.deinit();
        }
    }
};
