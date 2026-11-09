//! Typed ownership for external allocations admitted by SharedHostBudget.
//! Resource factories reserve before allocating, and command completion joins
//! before release. These are local resource contracts, never proof authority.
const std = @import("std");
const budget = @import("host_budget_allocator.zig");
pub const SharedBudget = budget.SharedHostBudget;
pub const Reservation = SharedBudget.ExternalReservation;
pub const Policy = enum { require_shared_budget, explicit_unbudgeted };

pub fn reserve(a: std.mem.Allocator, bytes: usize, policy: Policy) !Reservation {
    if (SharedBudget.fromAllocator(a)) |owner| return owner.reserveExternal(bytes);
    if (policy == .require_shared_budget) return error.SharedExternalBudgetRequired;
    return Reservation.unbudgeted(bytes);
}

/// Join callbacks must return only after commands no longer borrow inputs,
/// including error returns (e.g. checked device pole/invalid status). A failed
/// completion never exposes the resource through checked() or transfer().
pub const Completion = union(enum) {
    joined,
    in_flight: struct {
        context: *anyopaque,
        join: *const fn (?*anyopaque) anyerror!void,
        cancel_and_join: ?*const fn (?*anyopaque) anyerror!void,
    },
    pub fn completed() Completion {
        return .joined;
    }
    pub fn pending(context: *anyopaque, join: *const fn (?*anyopaque) anyerror!void, cancel_and_join: ?*const fn (?*anyopaque) anyerror!void) Completion {
        return .{ .in_flight = .{ .context = context, .join = join, .cancel_and_join = cancel_and_join } };
    }
    pub fn isCompleted(self: Completion) bool {
        return self == .joined;
    }
};
pub const Phase = enum { pending, ready, failed, cancelled, moved, released };
pub fn Product(comptime Resource: type) type {
    return struct {
        resource: Resource,
        /// Total private external extent after transient command allocations
        /// have been released, bounded by the reservation made before factory.
        retained_bytes: usize,
        completion: Completion,
    };
}
pub fn Owned(comptime Resource: type) type {
    return struct {
        const Self = @This();
        resource: ?Resource,
        reservation: Reservation,
        completion: Completion,
        phase: Phase,
        retained_bytes: usize,
        host: ?HostBorrow = null,
        pub fn complete(self: *Self) !void {
            switch (self.phase) {
                .ready => return,
                .pending => {},
                .failed => return error.ExternalCompletionFailed,
                .cancelled => return error.ExternalResourceCancelled,
                .moved, .released => return error.ExternalResourceUnavailable,
            }
            const pending = self.completion.in_flight;
            pending.join(pending.context) catch |err| {
                self.phase = .failed;
                return err;
            };
            self.reservation.resize(self.retained_bytes) catch |err| {
                self.phase = .failed;
                return err;
            };
            self.phase = .ready;
        }
        pub fn checked(self: *Self) !*Resource {
            if (self.phase != .ready or self.resource == null) return error.ExternalResourceNotChecked;
            return &self.resource.?;
        }
        pub fn cancel(self: *Self) !void {
            if (self.phase == .pending) {
                const pending = self.completion.in_flight;
                const join = pending.cancel_and_join orelse pending.join;
                self.phase = .cancelled;
                try join(pending.context);
            } else if (self.phase == .ready) self.phase = .cancelled;
        }
        /// Explicit consuming transfer. Raw struct copies do not retain a
        /// lease and are outside this API's ownership contract.
        pub fn take(self: *Self) !Self {
            if (self.phase != .ready or self.resource == null) return error.ExternalResourceNotChecked;
            const result = self.*;
            self.resource = null;
            self.reservation = .empty();
            self.host = null;
            self.phase = .moved;
            return result;
        }
        pub fn deinit(self: *Self) void {
            if (self.phase == .released or self.phase == .moved) return;
            self.cancel() catch {};
            if (self.resource) |*resource| resource.deinit();
            self.resource = null;
            // Destroy the device resource after join, before dropping its
            // external charge or retained host owner.
            if (self.host) |host| host.release(host.context);
            self.host = null;
            // A zero-charge alias reservation can be the final budget lease.
            // Keep it alive while host.release frees the charged heap backing.
            self.reservation.deinit();
            self.phase = .released;
        }
    };
}

/// Caller must keep the original allocator owner alive through acquisition.
/// The factory receives a hard upper extent, including its transient device
/// buffers. It must not allocate beyond that already admitted envelope.
/// An error return must already have joined and destroyed every unpublished
/// resource; the wrapper then rolls back the unused reservation.
pub fn createPrivate(comptime Resource: type, a: std.mem.Allocator, upper_bytes: usize, policy: Policy, context: anytype, factory: anytype) !Owned(Resource) {
    var reservation = try reserve(a, upper_bytes, policy);
    errdefer reservation.deinit();
    const product: Product(Resource) = try factory(context, upper_bytes);
    var owner = Owned(Resource){ .resource = product.resource, .reservation = reservation.take(), .completion = product.completion, .phase = if (product.completion.isCompleted()) .ready else .pending, .retained_bytes = product.retained_bytes };
    errdefer owner.deinit();
    if (product.retained_bytes > upper_bytes) return error.ExternalExtentExceedsReservation;
    // Pending commands can still own transient scratch. Keep their complete
    // envelope charged until a later explicit terminal shrink.
    if (owner.phase == .ready) try owner.reservation.resize(product.retained_bytes);
    return owner;
}

/// Construct only from the actual owning host allocation, never a received
/// address/claimed allocator. Retain/release keep the backing allocation alive
/// through GPU commands; the allocator identity selects the same shared cap.
pub const HostBorrow = struct {
    allocator: std.mem.Allocator,
    bytes: usize,
    context: *anyopaque,
    retain: *const fn (*anyopaque) anyerror!void,
    release: *const fn (*anyopaque) void,
};
pub fn createAlias(comptime Resource: type, host: HostBorrow, policy: Policy, context: anytype, factory: anytype) !Owned(Resource) {
    // No-copy memory is already charged by its real heap allocator. The zero
    // external charge retains only the same budget's lifetime lease.
    var reservation = try reserve(host.allocator, 0, policy);
    errdefer reservation.deinit();
    try host.retain(host.context);
    var owns_host = true;
    errdefer if (owns_host) host.release(host.context);
    const product: Product(Resource) = try factory(context, host.bytes);
    var owner = Owned(Resource){ .resource = product.resource, .reservation = reservation.take(), .completion = product.completion, .phase = if (product.completion.isCompleted()) .ready else .pending, .retained_bytes = 0, .host = host };
    owns_host = false;
    errdefer owner.deinit();
    if (product.retained_bytes != 0) return error.NoCopyAliasHasPrivateExtent;
    return owner;
}
