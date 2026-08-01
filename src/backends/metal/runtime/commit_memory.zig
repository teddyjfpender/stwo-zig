//! Process-wide admission for allocator-backed Metal commitment arenas.
//!
//! A reservation begins before a potentially moving resize, covers both the
//! old and new allocations while that resize is in flight, and then follows an
//! optional PCS backing-teardown token until the host allocation is freed.

const std = @import("std");

var live_reserved_bytes: std.atomic.Value(u64) = .init(0);

pub const Reservation = struct {
    retained_bytes: u64,
    transient_bytes: u64,

    pub fn finishResize(self: *Reservation) void {
        const transient = self.transient_bytes;
        if (transient == 0) return;
        release(transient);
        self.transient_bytes = 0;
    }

    /// Transfers the retained part to the backing-teardown token, which must
    /// call `release` exactly once after the host allocation is freed.
    pub fn transferRetained(self: *Reservation) u64 {
        std.debug.assert(self.transient_bytes == 0);
        const retained = self.retained_bytes;
        self.retained_bytes = 0;
        return retained;
    }

    pub fn deinit(self: *Reservation) void {
        release(self.retained_bytes + self.transient_bytes);
        self.* = undefined;
    }
};

/// Atomically reserves the final retained arena plus the source allocation
/// that can coexist with it during a moving realloc.
pub fn tryReserve(cap: u64, retained_bytes: u64, transient_bytes: u64) ?Reservation {
    const requested = std.math.add(u64, retained_bytes, transient_bytes) catch return null;
    if (requested == 0 or requested > cap) return null;

    var observed = live_reserved_bytes.load(.monotonic);
    while (true) {
        const desired = std.math.add(u64, observed, requested) catch return null;
        if (desired > cap) return null;
        if (live_reserved_bytes.cmpxchgWeak(
            observed,
            desired,
            .monotonic,
            .monotonic,
        )) |actual| {
            observed = actual;
            continue;
        }
        return .{
            .retained_bytes = retained_bytes,
            .transient_bytes = transient_bytes,
        };
    }
}

pub fn release(bytes: u64) void {
    if (bytes == 0) return;
    const previous = live_reserved_bytes.fetchSub(bytes, .monotonic);
    std.debug.assert(previous >= bytes);
}

pub fn liveBytes() u64 {
    return live_reserved_bytes.load(.monotonic);
}

test "commit arena reservation covers cumulative live bytes and resize peak" {
    const before = liveBytes();
    const cap = std.math.add(u64, before, 192) catch return error.SkipZigTest;
    {
        var reservation = tryReserve(cap, 128, 64) orelse return error.TestUnexpectedResult;
        defer reservation.deinit();
        try std.testing.expectEqual(before + 192, liveBytes());
        try std.testing.expect(tryReserve(cap, 1, 0) == null);
        reservation.finishResize();
        try std.testing.expectEqual(before + 128, liveBytes());
    }
    try std.testing.expectEqual(before, liveBytes());
}
