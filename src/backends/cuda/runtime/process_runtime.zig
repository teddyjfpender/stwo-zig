//! Process-owned CUDA resources shared by sequential proof transactions.

const std = @import("std");
const runtime_error = @import("error.zig");
const session_module = @import("session.zig");

pub const NativeRuntime = RuntimeFor(session_module.NativeSession);

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

        pub fn completedProofs(self: Self) u64 {
            return self.session.completed_proofs;
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
    (try runtime.beginProof()).finishRetained() catch unreachable;
    (try runtime.beginProof()).finishRetained() catch unreachable;
    try std.testing.expectEqual(@as(u64, 2), runtime.completedProofs());
    try runtime.close();
}
