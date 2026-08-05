//! Process-owned CUDA resources shared by sequential proof transactions.

const std = @import("std");
const runtime_error = @import("error.zig");
const session_module = @import("session.zig");

pub const NativeRuntime = ProcessOwnedRuntimeFor(session_module.NativeSession);
pub const CuMetalRuntime = ProcessOwnedRuntimeFor(session_module.CuMetalSession);

/// Wraps one session implementation in a process-wide ownership lease.
///
/// Each specialization owns a distinct registry. `NativeRuntime` therefore
/// admits exactly one live CUDA owner, while fake sessions remain isolated in
/// tests.
pub fn ProcessOwnedRuntimeFor(comptime Session: type) type {
    return struct {
        const Self = @This();
        const Inner = RuntimeFor(Session);

        var registry_mutex: std.Thread.Mutex = .{};
        var registry_active = false;

        inner: Inner,
        owns_registry: bool = true,

        pub const ProofSession = Session;

        pub fn open(accepted_sms: []const u32) runtime_error.Error!Self {
            if (!acquireRegistry()) return error.InvalidState;
            errdefer releaseRegistry();
            return .{ .inner = try Inner.open(accepted_sms) };
        }

        pub fn beginProof(self: *Self) runtime_error.Error!*Session {
            return self.inner.beginProof();
        }

        pub fn planningSession(self: *const Self) *const Session {
            return self.inner.planningSession();
        }

        pub fn prepareExecution(
            self: *Self,
            allocator: std.mem.Allocator,
            cache_key: [32]u8,
            owned_plan: @import("arena.zig").Plan,
        ) runtime_error.Error!void {
            return self.inner.prepareExecution(
                allocator,
                cache_key,
                owned_plan,
            );
        }

        pub fn completedProofs(self: Self) u64 {
            return self.inner.completedProofs();
        }

        pub fn isReady(self: *const Self) bool {
            return self.owns_registry and self.inner.isReady();
        }

        pub fn executionLaneCount(self: *const Self) u32 {
            return self.inner.executionLaneCount();
        }

        pub fn hasPreparedExecution(
            self: *const Self,
            cache_key: [32]u8,
        ) bool {
            return self.owns_registry and
                self.inner.hasPreparedExecution(cache_key);
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            if (!self.owns_registry) return error.InvalidState;
            try self.inner.close();
            self.owns_registry = false;
            releaseRegistry();
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            if (!self.owns_registry) return error.InvalidState;
            const result = self.inner.abort();
            self.owns_registry = false;
            releaseRegistry();
            return result;
        }

        fn acquireRegistry() bool {
            registry_mutex.lock();
            defer registry_mutex.unlock();
            if (registry_active) return false;
            registry_active = true;
            return true;
        }

        fn releaseRegistry() void {
            registry_mutex.lock();
            defer registry_mutex.unlock();
            std.debug.assert(registry_active);
            registry_active = false;
        }
    };
}

pub fn RuntimeFor(comptime Session: type) type {
    return struct {
        const Self = @This();
        pub const ProofSession = Session;

        session: Session,
        state: enum { ready, closed } = .ready,

        pub fn open(accepted_sms: []const u32) runtime_error.Error!Self {
            return .{ .session = try Session.open(accepted_sms) };
        }

        pub fn beginProof(self: *Self) runtime_error.Error!*Session {
            if (self.state != .ready) return error.InvalidState;
            try self.session.beginProof();
            return &self.session;
        }

        /// Returns immutable planning identity without starting a proof or
        /// changing per-proof telemetry.
        pub fn planningSession(self: *const Self) *const Session {
            std.debug.assert(self.state == .ready);
            return &self.session;
        }

        pub fn prepareExecution(
            self: *Self,
            allocator: std.mem.Allocator,
            cache_key: [32]u8,
            owned_plan: @import("arena.zig").Plan,
        ) runtime_error.Error!void {
            if (self.state != .ready) return error.InvalidState;
            try self.session.prepareExecution(
                allocator,
                cache_key,
                owned_plan,
            );
        }

        pub fn completedProofs(self: Self) u64 {
            return self.session.completed_proofs;
        }

        pub fn isReady(self: *const Self) bool {
            return self.state == .ready and self.session.isReady();
        }

        pub fn executionLaneCount(self: *const Self) u32 {
            return self.session.executionLaneCount();
        }

        pub fn hasPreparedExecution(
            self: *const Self,
            cache_key: [32]u8,
        ) bool {
            return self.state == .ready and
                self.session.hasPreparedExecution(cache_key);
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            if (self.state != .ready) return error.InvalidState;
            try self.session.close();
            self.state = .closed;
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            if (self.state != .ready) return error.InvalidState;
            const result = self.session.abort();
            self.state = .closed;
            return result;
        }
    };
}

test "process runtime admits sequential proof sessions" {
    const FakeSession = struct {
        completed_proofs: u64 = 0,
        active: bool = false,
        closed: bool = false,

        pub fn open(_: []const u32) runtime_error.Error!@This() {
            return .{};
        }

        pub fn beginProof(self: *@This()) runtime_error.Error!void {
            if (self.active or self.closed) return error.InvalidState;
            self.active = true;
        }

        pub fn isReady(self: *const @This()) bool {
            return !self.active and !self.closed;
        }

        pub fn executionLaneCount(_: *const @This()) u32 {
            return 1;
        }

        pub fn hasPreparedExecution(
            _: *const @This(),
            cache_key: [32]u8,
        ) bool {
            return cache_key[0] == 7;
        }

        pub fn finishRetained(self: *@This()) runtime_error.Error!void {
            if (!self.active or self.closed) return error.InvalidState;
            self.active = false;
            self.completed_proofs += 1;
        }

        pub fn close(self: *@This()) runtime_error.Error!void {
            if (self.active or self.closed) return error.InvalidState;
            self.closed = true;
        }

        pub fn abort(self: *@This()) runtime_error.Error!void {
            self.closed = true;
        }
    };

    const Runtime = RuntimeFor(FakeSession);
    var runtime = try Runtime.open(&.{89});
    try std.testing.expect(!runtime.planningSession().active);
    try std.testing.expect(runtime.isReady());
    try std.testing.expectEqual(@as(u32, 1), runtime.executionLaneCount());
    try std.testing.expect(
        runtime.hasPreparedExecution([_]u8{7} ** 32),
    );
    (try runtime.beginProof()).finishRetained() catch unreachable;
    (try runtime.beginProof()).finishRetained() catch unreachable;
    try std.testing.expectEqual(@as(u64, 2), runtime.completedProofs());
    try runtime.close();
}

test "process-owned runtime admits exactly one live owner" {
    const FakeSession = struct {
        completed_proofs: u64 = 0,
        active: bool = false,
        closed: bool = false,

        pub fn open(_: []const u32) runtime_error.Error!@This() {
            return .{};
        }

        pub fn beginProof(self: *@This()) runtime_error.Error!void {
            if (self.active or self.closed) return error.InvalidState;
            self.active = true;
        }

        pub fn isReady(self: *const @This()) bool {
            return !self.active and !self.closed;
        }

        pub fn executionLaneCount(_: *const @This()) u32 {
            return 1;
        }

        pub fn hasPreparedExecution(
            _: *const @This(),
            cache_key: [32]u8,
        ) bool {
            return cache_key[0] == 9;
        }

        pub fn close(self: *@This()) runtime_error.Error!void {
            if (self.active or self.closed) return error.InvalidState;
            self.closed = true;
        }

        pub fn abort(self: *@This()) runtime_error.Error!void {
            self.closed = true;
        }
    };

    const Runtime = ProcessOwnedRuntimeFor(FakeSession);
    var first = try Runtime.open(&.{89});
    try std.testing.expect(first.isReady());
    try std.testing.expectEqual(@as(u32, 1), first.executionLaneCount());
    try std.testing.expect(
        first.hasPreparedExecution([_]u8{9} ** 32),
    );
    try std.testing.expectError(error.InvalidState, Runtime.open(&.{89}));
    try first.close();

    var second = try Runtime.open(&.{89});
    try second.abort();
    var third = try Runtime.open(&.{89});
    try third.close();
}
