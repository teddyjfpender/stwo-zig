//! Stable immutable caller policies shared by publication and later readers.
//! The source seal and entries remain borrowed until every reader is joined.
//! This owns geometry only, never a proof, capture or verified equation.
const std = @import("std");
const Arithmetic = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Fused = @import("block_v5_caller_fused_recursive_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Pin = @import("block_v5_caller_fused_receiver_v1.zig").Pin;
pub const Limits = struct { arithmetic: Arithmetic.Limits = .{}, fused: Fused.Limits = .{} };
pub const Pair = struct {
    a: std.mem.Allocator,
    arithmetic: Arithmetic.Prepared,
    fused: Fused.Prepared,
    sessions: usize = 0,
    mutex: std.Thread.Mutex = .{},
    pub fn create(a: std.mem.Allocator, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !*Pair {
        const out = try a.create(Pair);
        errdefer a.destroy(out);
        var fused = try Fused.Prepared.init(a, index, pin, sealed, pins, entries, limits.fused);
        errdefer fused.deinit();
        var arithmetic = try Arithmetic.Prepared.init(a, pin.statement.*, pin.total_steps, fused.binding, sealed, pins, entries, limits.arithmetic);
        errdefer arithmetic.deinit();
        out.* = .{ .a = a, .arithmetic = arithmetic, .fused = fused };
        return out;
    }
    pub fn require(self: *const Pair) !void {
        if (!std.meta.eql(self.arithmetic.binding, self.fused.binding) or
            !std.meta.eql(self.arithmetic.statement, self.fused.statement) or
            self.arithmetic.total_steps != self.fused.total_steps or
            !std.meta.eql(self.arithmetic.sealed, self.fused.sealed) or
            !std.meta.eql(self.arithmetic.pins, self.fused.pins) or
            !std.meta.eql(self.arithmetic.entries, self.fused.entries))
            return error.MixedRecursiveCallerAdmissions;
        try self.arithmetic.validate(self.arithmetic.template_id);
        try self.fused.validate(self.fused.template_id);
    }
    /// Caller and any subsequent durable/recursive readers must join before
    /// this owner is destroyed. Session leases guard the active caller part.
    pub fn deinit(self: *Pair) void {
        self.mutex.lock();
        if (self.sessions != 0) @panic("destroying active recursive caller admissions");
        self.mutex.unlock();
        self.arithmetic.deinit();
        self.fused.deinit();
        const a = self.a;
        a.destroy(self);
    }
    pub fn acquireSession(self: *Pair) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sessions = try std.math.add(usize, self.sessions, 1);
    }
    pub fn releaseSession(self: *Pair) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.sessions != 0);
        self.sessions -= 1;
    }
};
