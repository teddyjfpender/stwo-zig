//! Per-class recursion plans built once and shared by every node of the class
//! (GPU-native design rv64-m8-gpu-native.md §3.1, host work H18-H20).
//!
//! Today every node rebuilds its class products on the request path:
//!   prestage  leaf class statics (lookup gathers, class plan, gathered FIXED
//!             evaluations, composition roles, mask points): 0.18-0.34 s per
//!             leaf [M, feeder gate-c 24628607 warm, GPU_M8_OUTER_NODE_HOST];
//!   initWhole stream schedules, composition commit stream and the PCS framing
//!             (PcsJob.prepare at the placeholder point): 0.09-0.57 s per node
//!             [M, same run], 5.26 / 6.48 s summed per warm request [M].
//! All of it is a pure function of the class authority (identity = FIXED root,
//! component logs, output count) and process constants (stream knobs, the
//! kernels' compact mode, the PCS framing version), so a `Slot` per cached
//! class holds the immutable product, built by the first node of the class
//! (install/warm request) and borrowed by every later node. A plan built under
//! a different process signature is never reused (the node builds privately).
//! No proof byte depends on whether a plan was borrowed: the borrowed schedule
//! and framing are the very values the node would have built.
//!
//! STWO_RV64_M8_OUTER_CLASS_PLAN (default 0): "1" caches leaf statics by
//! authority identity (folds were already cached) and borrows the whole-node
//! plan from the class slot. STWO_RV64_M8_OUTER_CLASS_PLAN_HOST_MB caps the
//! host bytes of cached class statics (default 65536: the pod has 377 GB RAM,
//! 24628607's largest leaf class gathers ~0.5 GB of FIXED [M plan_words]).
//!
//! Type-erased on purpose: outer_staged.zig carries a `?*anyopaque` to it and
//! outer_job.zig owns the concrete plan type, so this file stays in the GPU-free
//! outer test root.
const std = @import("std");
const Env = @import("outer_env.zig");

pub const Signature = [32]u8;

pub fn selected() !bool {
    return Env.flag("STWO_RV64_M8_OUTER_CLASS_PLAN", false);
}
pub fn hostBudgetBytes() !u64 {
    return (65536) << 20;
}

/// Counters of every slot of the process (receipts: GPU_M8_OUTER_CLASS_PLAN).
pub const Stats = struct {
    builds: std.atomic.Value(u64) = .init(0),
    hits: std.atomic.Value(u64) = .init(0),
    bypasses: std.atomic.Value(u64) = .init(0),
    build_ns: std.atomic.Value(u64) = .init(0),
};
pub var stats: Stats = .{};

/// One class's lazily built, immutable plan. Thread safe: the first node of a
/// class builds under the slot lock (concurrent nodes of the same class wait
/// for it instead of building twice); later nodes only take the lock to read.
pub const Slot = struct {
    mutex: std.Thread.Mutex = .{},
    plan: ?*anyopaque = null,
    signature: Signature = @splat(0),
    destroy_fn: ?*const fn (*anyopaque) void = null,
    builds: u64 = 0,
    hits: u64 = 0,
    bypasses: u64 = 0,

    pub const Builder = struct {
        ctx: *anyopaque,
        build: *const fn (*anyopaque) anyerror!*anyopaque,
        destroy: *const fn (*anyopaque) void,
    };

    /// The class plan for `signature`, built at most once per slot. Null when
    /// the slot already holds a plan of another signature: the caller builds
    /// its own (never a wrong-signature borrow, never a rebuild that would
    /// pull the plan from under a node still using it).
    pub fn acquire(self: *Slot, signature: Signature, builder: Builder) !?*anyopaque {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.plan) |p| {
            if (std.mem.eql(u8, &self.signature, &signature)) {
                self.hits += 1;
                _ = stats.hits.fetchAdd(1, .monotonic);
                return p;
            }
            self.bypasses += 1;
            _ = stats.bypasses.fetchAdd(1, .monotonic);
            return null;
        }
        var timer = std.time.Timer.start() catch null;
        const p = try builder.build(builder.ctx);
        self.plan = p;
        self.signature = signature;
        self.destroy_fn = builder.destroy;
        self.builds += 1;
        _ = stats.builds.fetchAdd(1, .monotonic);
        if (timer) |*t| _ = stats.build_ns.fetchAdd(t.read(), .monotonic);
        return p;
    }
    /// Only when no node can still borrow the plan (class statics teardown).
    pub fn deinit(self: *Slot) void {
        if (self.plan) |p| self.destroy_fn.?(p);
        self.* = .{};
    }
};

/// Host-byte budget of cached class statics (process wide). A class that does
/// not fit stays uncached (built per node as before): correct, only slower.
pub const Budget = struct {
    limit: u64,
    used: std.atomic.Value(u64) = .init(0),
    pub fn reserve(self: *Budget, bytes: u64) bool {
        var now = self.used.load(.monotonic);
        while (true) {
            if (now + bytes > self.limit) return false;
            now = self.used.cmpxchgWeak(now, now + bytes, .monotonic, .monotonic) orelse return true;
        }
    }
    pub fn release(self: *Budget, bytes: u64) void {
        _ = self.used.fetchSub(bytes, .monotonic);
    }
};

/// The class cache's eviction choice: the least recently used entry no node
/// still borrows (`refs[i] == 0`), or null when every entry is in use (the
/// new class then stays per node). Evicting only unreferenced entries is what
/// makes destruction safe: a node's jobs (and the WholePlan they borrow) end
/// before its Staged releases its reference (outer_job_factory Prover.prove).
pub fn lruVictim(refs: []const u32, last_use: []const u64) ?usize {
    std.debug.assert(refs.len == last_use.len);
    var best: ?usize = null;
    for (refs, last_use, 0..) |r, t, i| {
        if (r != 0) continue;
        if (best == null or t < last_use[best.?]) best = i;
    }
    return best;
}

/// Signature hashing helper: process constants a class plan was built under.
pub fn signatureOf(parts: []const u64) Signature {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/m8/outer-class-plan/signature/v1\x00");
    h.update(std.mem.sliceAsBytes(parts));
    return h.finalResult();
}

test "class plan slot builds once, borrows after, refuses another signature" {
    const T = struct {
        var built: u32 = 0;
        var destroyed: u32 = 0;
        var value: u32 = 7;
        fn build(_: *anyopaque) anyerror!*anyopaque {
            built += 1;
            return @ptrCast(&value);
        }
        fn destroy(_: *anyopaque) void {
            destroyed += 1;
        }
        fn fail(_: *anyopaque) anyerror!*anyopaque {
            return error.Boom;
        }
    };
    var ctx: u8 = 0;
    const b = Slot.Builder{ .ctx = &ctx, .build = T.build, .destroy = T.destroy };
    var slot = Slot{};
    const s1 = signatureOf(&.{ 1, 2 });
    const s2 = signatureOf(&.{ 1, 3 });
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
    const p1 = (try slot.acquire(s1, b)).?;
    const p2 = (try slot.acquire(s1, b)).?;
    try std.testing.expectEqual(p1, p2);
    try std.testing.expectEqual(@as(u32, 1), T.built);
    try std.testing.expectEqual(@as(u64, 1), slot.hits);
    try std.testing.expectEqual(@as(?*anyopaque, null), try slot.acquire(s2, b));
    try std.testing.expectEqual(@as(u64, 1), slot.bypasses);
    slot.deinit();
    try std.testing.expectEqual(@as(u32, 1), T.destroyed);
    // A failed build leaves the slot empty (the next node retries).
    try std.testing.expectError(error.Boom, slot.acquire(s1, .{ .ctx = &ctx, .build = T.fail, .destroy = T.destroy }));
    try std.testing.expectEqual(@as(?*anyopaque, null), slot.plan);
    _ = (try slot.acquire(s1, b)).?;
    try std.testing.expectEqual(@as(u32, 2), T.built);
    slot.deinit();
}

test "class plan slot is built once under concurrent first nodes" {
    const T = struct {
        var built = std.atomic.Value(u32).init(0);
        var value: u32 = 1;
        fn build(_: *anyopaque) anyerror!*anyopaque {
            _ = built.fetchAdd(1, .monotonic);
            std.Thread.sleep(2 * std.time.ns_per_ms);
            return @ptrCast(&value);
        }
        fn destroy(_: *anyopaque) void {}
        fn run(slot: *Slot, out: *?*anyopaque) void {
            var ctx: u8 = 0;
            out.* = slot.acquire(signatureOf(&.{9}), .{ .ctx = &ctx, .build = build, .destroy = destroy }) catch null;
        }
    };
    var slot = Slot{};
    defer slot.deinit();
    var outs: [4]?*anyopaque = @splat(null);
    var threads: [4]std.Thread = undefined;
    for (&threads, &outs) |*t, *o| t.* = try std.Thread.spawn(.{}, T.run, .{ &slot, o });
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(u32, 1), T.built.load(.monotonic));
    for (outs) |o| try std.testing.expectEqual(outs[0].?, o.?);
}

test "class cache evicts the least recently used unreferenced entry only" {
    try std.testing.expectEqual(@as(?usize, 2), lruVictim(&.{ 1, 0, 0, 3 }, &.{ 1, 9, 4, 0 }));
    try std.testing.expectEqual(@as(?usize, null), lruVictim(&.{ 1, 2 }, &.{ 0, 0 }));
    try std.testing.expectEqual(@as(?usize, null), lruVictim(&.{}, &.{}));
    try std.testing.expectEqual(@as(?usize, 0), lruVictim(&.{ 0, 0 }, &.{ 5, 5 }));
}

test "class statics budget admits up to the limit" {
    var b = Budget{ .limit = 100 };
    try std.testing.expect(b.reserve(60));
    try std.testing.expect(!b.reserve(41));
    try std.testing.expect(b.reserve(40));
    b.release(60);
    try std.testing.expect(b.reserve(50));
}
