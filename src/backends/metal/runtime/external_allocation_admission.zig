//! Constructor-time admission for private device scratch. The caller joins or
//! cancels device work and destroys its buffers before releasing this scope.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;

pub const Scope = struct {
    allocator: std.mem.Allocator,
    reservation: external.Reservation,
    failure: ?anyerror = null,
    active: bool = true,

    pub fn init(a: std.mem.Allocator, policy: external.Policy) !Scope {
        return .{ .allocator = a, .reservation = try external.reserve(a, 0, policy) };
    }
    pub fn validateAllocator(self: *const Scope, a: std.mem.Allocator) !void {
        if (!self.active) return error.ExternalAdmissionClosed;
        if (self.allocator.ptr != a.ptr or self.allocator.vtable != a.vtable)
            return error.ExternalAdmissionAllocatorMismatch;
    }
    /// Only allocator-less legacy entrypoints use this policy. Ordinary
    /// allocators have no shared charge to rebind; a supplied shared budget
    /// must match the original owner and cannot enter an uncapped scope.
    pub fn validateOrdinaryCompatibility(self: *const Scope, a: std.mem.Allocator) !void {
        if (!self.active) return error.ExternalAdmissionClosed;
        if (self.reservation.owner == null and external.SharedBudget.fromAllocator(a) == null) return;
        try self.validateAllocator(a);
    }
    pub fn admit(self: *Scope, bytes: usize) !void {
        if (!self.active) return error.ExternalAdmissionClosed;
        if (self.failure) |err| return err;
        const total = std.math.add(usize, self.reservation.bytes, bytes) catch |err| {
            self.failure = err;
            return err;
        };
        self.reservation.resize(total) catch |err| {
            self.failure = err;
            return err;
        };
    }
    pub fn callback(context: *anyopaque, bytes: usize) callconv(.c) bool {
        const self: *Scope = @ptrCast(@alignCast(context));
        self.admit(bytes) catch return false;
        return true;
    }
    /// Only after the device join and destruction of all private scratch.
    /// Preserve the allocator lease until enclosing heap owners are gone.
    pub fn releaseAfterJoin(self: *Scope) !void {
        if (!self.active) return error.ExternalAdmissionClosed;
        try self.reservation.resize(0);
    }
    /// Release a destroyed, joined wave while retaining persistent scratch.
    /// The caller must not report bytes still borrowed by any device command.
    pub fn releaseJoined(self: *Scope, bytes: usize) !void {
        if (!self.active) return error.ExternalAdmissionClosed;
        if (bytes > self.reservation.bytes) return error.ExternalAdmissionReleaseExtent;
        try self.reservation.resize(self.reservation.bytes - bytes);
    }
    pub fn deinit(self: *Scope) void {
        if (!self.active) return;
        self.reservation.deinit();
        self.active = false;
    }
};
