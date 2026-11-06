//! Request-scoped retained device regions (native-hybrid; M8-INTERFACES).
//!
//! A region is device memory tied to a REQUEST id that survives across jobs
//! on one worker (NativeStage1 -> host seal -> NativeStage2: MAIN
//! coefficients, binding columns across the global-chi barrier). Unlike
//! `Stager.persistent` (class-keyed, LRU-evictable, worker lifetime) it is:
//!   * keyed by (request, name), never evicted, never shared across requests;
//!   * released explicitly (`release`, `releaseRequest`; abort = releaseRequest);
//!   * accounted: live/peak words and an optional budget (memory policy
//!     `gpu.retained_budget_words`, worker.Config.retained_budget_words).
//!
//! Lifetime safety without a host wait. Every job that references a region
//! pins it (stage or enqueue) and unpins it when the worker reports the job
//! (after its single event wait: all of its device work, h2d included, is
//! done). A released region is freed only once no job pins it, on the worker
//! thread (the exec-context ledger is the worker thread's), with the
//! stream-ordered `stwo_exec_context_free_u32` on the exec stream.
//!
//! This file is pure bookkeeping over buffers; worker.zig owns allocation,
//! freeing and the threading (tests: retained_test.zig).
const std = @import("std");
const api = @import("api.zig");

pub const Key = struct {
    request: u64,
    name: [32]u8,
    pub fn eql(a: Key, b: Key) bool {
        return a.request == b.request and std.mem.eql(u8, &a.name, &b.name);
    }
};

/// Name helper: a short ASCII tag plus an index (e.g. "s1.main", segment 3).
pub fn name(tag: []const u8, index: u32) [32]u8 {
    var out: [32]u8 = @splat(0);
    const n = @min(tag.len, 27);
    @memcpy(out[0..n], tag[0..n]);
    std.mem.writeInt(u32, out[28..32], index, .little);
    return out;
}

pub const Entry = struct {
    key: Key,
    buffer: api.DeviceBuffer,
    pins: u32 = 0,
    /// Release requested; freed when `pins` reaches 0.
    released: bool = false,
};

pub const Stats = struct {
    live_regions: u64 = 0,
    live_words: u64 = 0,
    peak_words: u64 = 0,
    created: u64 = 0,
    freed: u64 = 0,
    freed_words: u64 = 0,
    /// Regions still live when the worker shut down (freed there: a leak of
    /// the request protocol, never of device memory).
    leaked_at_shutdown: u64 = 0,
    budget_refusals: u64 = 0,
};

pub const Table = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    /// 0 = no cap (accounted only).
    budget_words: usize = 0,
    stats: Stats = .{},

    pub fn deinit(self: *Table, a: std.mem.Allocator) void {
        self.entries.deinit(a);
    }

    pub fn find(self: *const Table, key: Key) ?usize {
        for (self.entries.items, 0..) |e, i| if (!e.released and e.key.eql(key)) return i;
        return null;
    }

    /// Room for `words` more under the budget (always true without one).
    pub fn admits(self: *const Table, words: usize) bool {
        if (self.budget_words == 0) return true;
        return words <= self.budget_words and self.stats.live_words <= self.budget_words - words;
    }

    /// Record a freshly allocated region (pinned once by the creating job).
    pub fn insert(self: *Table, a: std.mem.Allocator, key: Key, buffer: api.DeviceBuffer) !void {
        if (self.find(key) != null) return error.RetainedRegionExists;
        try self.entries.append(a, .{ .key = key, .buffer = buffer, .pins = 1 });
        self.stats.created += 1;
        self.stats.live_regions += 1;
        self.stats.live_words += buffer.words;
        self.stats.peak_words = @max(self.stats.peak_words, self.stats.live_words);
    }

    /// Pin a live region for a job; `words` must match its geometry.
    pub fn pin(self: *Table, key: Key, words: usize) !api.DeviceBuffer {
        const i = self.find(key) orelse return error.RetainedRegionNotFound;
        const e = &self.entries.items[i];
        if (e.buffer.words != words) return error.RetainedGeometryMismatch;
        e.pins += 1;
        return e.buffer;
    }

    /// Drop one pin of the region at `buffer` (jobs record the buffers they
    /// pinned, not keys: a released key may be re-created while its old
    /// region is still pinned). Returns the buffer to free when it was
    /// released and this was its last pin (the caller frees it, then `drop`).
    pub fn unpin(self: *Table, buffer: api.DeviceBuffer) ?api.DeviceBuffer {
        for (self.entries.items) |*e| if (e.buffer.ptr == buffer.ptr and e.pins != 0) {
            e.pins -= 1;
            if (e.pins == 0 and e.released) return e.buffer;
            return null;
        };
        return null;
    }

    /// Request a release. Returns the buffer if it can be freed now (no pins).
    pub fn release(self: *Table, key: Key) !?api.DeviceBuffer {
        const i = self.find(key) orelse return error.RetainedRegionNotLive;
        const e = &self.entries.items[i];
        e.released = true;
        return if (e.pins == 0) e.buffer else null;
    }

    /// Mark every live region of `request` released; appends the buffers
    /// that can be freed now to `out`. Idempotent (a second call finds none).
    pub fn releaseRequest(self: *Table, a: std.mem.Allocator, request: u64, out: *std.ArrayListUnmanaged(api.DeviceBuffer)) !usize {
        var n: usize = 0;
        for (self.entries.items) |e| if (!e.released and e.key.request == request) {
            n += 1;
        };
        try out.ensureUnusedCapacity(a, n);
        for (self.entries.items) |*e| if (!e.released and e.key.request == request) {
            e.released = true;
            if (e.pins == 0) out.appendAssumeCapacity(e.buffer);
        };
        return n;
    }

    /// Forget a freed buffer (after the device free succeeded or failed: a
    /// failed free is never retried).
    pub fn drop(self: *Table, buffer: api.DeviceBuffer) void {
        for (self.entries.items, 0..) |e, i| if (e.buffer.ptr == buffer.ptr) {
            self.stats.live_regions -= 1;
            self.stats.live_words -= e.buffer.words;
            self.stats.freed += 1;
            self.stats.freed_words += e.buffer.words;
            _ = self.entries.swapRemove(i);
            return;
        };
    }

    pub fn contains(self: *const Table, ptr: usize, words: usize) bool {
        for (self.entries.items) |e| {
            const lo = @intFromPtr(e.buffer.ptr);
            if (ptr >= lo and words <= e.buffer.words and (ptr - lo) / 4 <= e.buffer.words - words) return true;
        }
        return false;
    }

    pub fn liveWords(self: *const Table, request: ?u64) usize {
        var n: usize = 0;
        for (self.entries.items) |e| if (request == null or e.key.request == request.?) {
            n += e.buffer.words;
        };
        return n;
    }
};

test {
    _ = @import("retained_test.zig");
}
