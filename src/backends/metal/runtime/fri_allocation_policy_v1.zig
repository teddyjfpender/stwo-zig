//! General Metal FRI compatibility is explicitly uncapped for historical
//! foreign-allocator callers. Canonical block/RAM entrypoints require a shared
//! budget before reaching FRI; a supplied budget is never bypassed here.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;
pub const Policy = external.Policy;

pub fn ordinaryMetal(a: std.mem.Allocator) Policy {
    return if (external.SharedBudget.fromAllocator(a) != null) .require_shared_budget else .explicit_unbudgeted;
}

/// Shape-only admission, before an ordinary compatibility ingress factory.
pub fn ordinaryHostIngress(a: std.mem.Allocator, resident: bool, lengths: [4]usize) !usize {
    const binding = try Binding.init(a, .explicit_unbudgeted);
    if (binding.policy != .explicit_unbudgeted or resident) return error.InvalidFriUnbudgetedPolicy;
    _ = try @import("fri_budget_v1.zig").secureValues(lengths[0]);
    for (lengths) |length| if (length != lengths[0]) return error.InvalidFriResidentOwner;
    return lengths[0];
}

/// A local consuming resource binds allocator identity as well as its charge.
/// This does not change ownership of proof output or caller-owned source arrays.
pub const Binding = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    pub fn init(a: std.mem.Allocator, policy: Policy) !Binding {
        const shared = external.SharedBudget.fromAllocator(a) != null;
        if (!shared and policy == .require_shared_budget) return error.SharedExternalBudgetRequired;
        return .{ .allocator = a, .policy = if (shared) .require_shared_budget else policy };
    }
    pub fn require(self: Binding, a: std.mem.Allocator, reservation: *const external.Reservation, bytes: usize) !void {
        if (self.allocator.ptr != a.ptr or self.allocator.vtable != a.vtable) return error.InvalidFriAllocatorBinding;
        if (self.policy == .require_shared_budget) return reservation.requireOwner(a, bytes);
        if (external.SharedBudget.fromAllocator(a) != null or !reservation.active or reservation.owner != null or reservation.bytes != bytes) return error.InvalidFriAllocatorBinding;
    }
    pub fn reserve(self: Binding, bytes: usize) !external.Reservation {
        return external.reserve(self.allocator, bytes, self.policy);
    }
    /// Legacy allocator-less sources own their own uncapped context. Borrowing
    /// that context does not transfer/free source heap through the requester.
    /// Any supplied shared-budget requester still requires its exact owner.
    pub fn requireBorrowed(self: Binding, requester: Binding, reservation: *const external.Reservation, bytes: usize) !void {
        if (requester.policy == .require_shared_budget) return self.require(requester.allocator, reservation, bytes);
        if (self.policy != .explicit_unbudgeted) return error.InvalidFriAllocatorBinding;
        try self.require(self.allocator, reservation, bytes);
    }
};
