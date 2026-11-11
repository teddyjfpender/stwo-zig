//! Synchronous C allocation admission and returned quotient-tree ownership.
//! A callback rejects growth before a private Metal buffer is constructed.
//! The dispatch joins before return; only the published hash arena survives.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;

pub const Scope = struct {
    reservation: external.Reservation,
    failure: ?anyerror = null,
    closed: bool = false,

    pub fn init(a: std.mem.Allocator) !Scope {
        return .{ .reservation = try external.reserve(a, 0, .explicit_unbudgeted) };
    }
    /// Legacy ordinary APIs may retain their uncapped domain cache. A supplied
    /// shared budget uses a proof-local GPU grid, never an uncharged global hit.
    pub fn retainsDomainCache(self: *const Scope) bool {
        return self.reservation.owner == null;
    }
    pub fn admit(self: *Scope, bytes: usize) !void {
        if (self.closed or !self.reservation.active) return error.QuotientBudgetClosed;
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
    /// Call only after the synchronous ABI has joined every submitted command
    /// and released private temporaries. Failure keeps the full charge intact.
    pub fn finish(self: *Scope, rows: usize, has_tree: bool, retained: usize) !void {
        if (self.closed or !self.reservation.active) return error.QuotientBudgetClosed;
        if (self.failure) |err| return err;
        if (has_tree) {
            const expected = try hashArenaBytes(rows);
            // A discrete device additionally owns a 32-byte root readback.
            if (retained != expected and retained != try std.math.add(usize, expected, 32)) return error.InvalidQuotientRetainedExtent;
        } else if (retained != 0) return error.InvalidQuotientRetainedExtent;
        if (retained > self.reservation.bytes) return error.InvalidQuotientRetainedExtent;
        try self.reservation.resize(retained);
        self.closed = true;
    }
    pub fn take(self: *Scope) !external.Reservation {
        if (!self.closed or !self.reservation.active) return error.QuotientBudgetNotFinished;
        return self.reservation.take();
    }
    pub fn deinit(self: *Scope) void {
        self.reservation.deinit();
        self.closed = true;
    }
};

/// Same 64-word layer alignment and u32 offsets as the actual quotient ABI.
pub fn hashArenaBytes(rows: usize) !usize {
    if (rows == 0 or !std.math.isPowerOfTwo(rows) or rows > 1 << 30) return error.InvalidQuotientRetainedExtent;
    var words: usize = 0;
    var count = rows;
    while (count != 0) : (count >>= 1) {
        words = (try std.math.add(usize, words, 63)) & ~@as(usize, 63);
        words = try std.math.add(usize, words, try std.math.mul(usize, count, 8));
        if (words > std.math.maxInt(u32)) return error.InvalidQuotientRetainedExtent;
    }
    return std.math.mul(usize, words, 4);
}
