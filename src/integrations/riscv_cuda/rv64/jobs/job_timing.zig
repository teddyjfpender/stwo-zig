//! Diagnostic event ownership. A worker owns installed pairs through teardown;
//! request jobs borrow one (actual parity, segment) pair through their finish.
//! Component harnesses may explicitly own a span. No synchronization is added.
const std = @import("std");

pub const Create = *const fn (*?*anyopaque) callconv(.c) c_int;
pub const Destroy = *const fn (*anyopaque) callconv(.c) c_int;

pub const Pair = struct {
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    fn init(create: Create, destroy: Destroy) !Pair {
        var out = Pair{};
        errdefer out.deinit(destroy);
        if (create(&out.begin) != 0 or out.begin == null) return error.CudaTimingFailed;
        if (create(&out.end) != 0 or out.end == null) return error.CudaTimingFailed;
        return out;
    }
    fn deinit(self: *Pair, destroy: Destroy) void {
        if (self.begin) |event| _ = destroy(event);
        if (self.end) |event| _ = destroy(event);
        self.* = .{};
    }
};

pub const Pool = struct {
    pairs: [2][]Pair = .{ &.{}, &.{} },

    /// Install only, on the owning GPU thread. Failure leaves both old
    /// parity arrays intact; copied handles move ownership only at commit.
    pub fn reserve(self: *Pool, a: std.mem.Allocator, count: usize, create: Create, destroy: Destroy) !void {
        var grown: [2][]Pair = .{ &.{}, &.{} };
        errdefer for (&grown, 0..) |slice, parity| {
            if (slice.len == 0) continue;
            for (slice[self.pairs[parity].len..]) |*pair| pair.deinit(destroy);
            a.free(slice);
        };
        for (&grown, 0..) |*slice, parity| {
            const old = self.pairs[parity];
            if (old.len >= count) continue;
            slice.* = try a.alloc(Pair, count);
            @memset(slice.*, .{});
            @memcpy(slice.*[0..old.len], old);
            for (slice.*[old.len..]) |*pair| pair.* = try Pair.init(create, destroy);
        }
        for (grown, 0..) |slice, parity| {
            if (slice.len == 0) continue;
            a.free(self.pairs[parity]);
            self.pairs[parity] = slice;
        }
    }
    pub fn get(self: *const Pool, parity: u1, index: usize) !Pair {
        if (index >= self.pairs[parity].len) return error.JobTimingNotReserved;
        const pair = self.pairs[parity][index];
        if (pair.begin == null or pair.end == null) return error.JobTimingNotReserved;
        return pair;
    }
    /// The worker calls this after quiescence, before destroying its context,
    /// including the worker's fatal-error shutdown path.
    pub fn deinit(self: *Pool, a: std.mem.Allocator, destroy: Destroy) void {
        for (&self.pairs) |*slice| {
            for (slice.*) |*pair| pair.deinit(destroy);
            a.free(slice.*);
            slice.* = &.{};
        }
    }
};

pub const Timing = struct {
    ctx: ?*anyopaque = null,
    create: *const fn (?*anyopaque, *?*anyopaque) c_int,
    record: *const fn (?*anyopaque, *anyopaque, *anyopaque) c_int,
    elapsed: *const fn (?*anyopaque, *f32, *anyopaque, *anyopaque) c_int,
    destroy: *const fn (?*anyopaque, *anyopaque) void,

    pub const Span = struct {
        begin: ?*anyopaque = null,
        end: ?*anyopaque = null,
        gpu_ms: f32 = -1,
        ownership: enum { owned, borrowed } = .owned,

        pub fn borrow(pair: Pair) Span {
            return .{ .begin = pair.begin, .end = pair.end, .ownership = .borrowed };
        }
        pub fn open(self: *Span, t: ?*const Timing) !void {
            const tm = t orelse return;
            if (self.begin != null and self.end != null) return;
            if (self.ownership == .borrowed) return error.JobTimingNotReserved;
            errdefer self.close(t);
            if (self.begin == null) if (tm.create(tm.ctx, &self.begin) != 0 or self.begin == null) return error.CudaTimingFailed;
            if (self.end == null) if (tm.create(tm.ctx, &self.end) != 0 or self.end == null) return error.CudaTimingFailed;
        }
        pub fn mark(self: *Span, t: ?*const Timing, comptime which: enum { begin, end }, stream: *anyopaque) !void {
            const tm = t orelse return;
            const event = (if (which == .begin) self.begin else self.end) orelse return error.JobTimingNotReserved;
            if (tm.record(tm.ctx, event, stream) != 0) return error.CudaTimingFailed;
        }
        pub fn read(self: *Span, t: ?*const Timing) void {
            const tm = t orelse return;
            if (self.begin == null or self.end == null or tm.elapsed(tm.ctx, &self.gpu_ms, self.begin.?, self.end.?) != 0 or !std.math.isFinite(self.gpu_ms) or self.gpu_ms < 0) self.gpu_ms = -1;
        }
        pub fn close(self: *Span, t: ?*const Timing) void {
            if (t) |tm| if (self.ownership == .owned) {
                if (self.begin) |event| tm.destroy(tm.ctx, event);
                if (self.end) |event| tm.destroy(tm.ctx, event);
            };
            self.* = .{ .gpu_ms = self.gpu_ms, .ownership = self.ownership };
        }
    };
};

test {
    _ = @import("job_timing_test.zig");
}
