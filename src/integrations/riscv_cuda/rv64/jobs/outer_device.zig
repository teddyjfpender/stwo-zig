//! M8 GPU-native recursion (stream: recursion). Contract: gpu_native.zig
//! RecursionFactory; design: rv64-m8-gpu-native.md §3.3, §6.
//!
//! Landed: the class side. Every recursion class the request layer has
//! planned (a leaf/fold/root authority whose statics and whole-node plan sit
//! in an outer_class_plan.zig slot) is registered here under its AUTHORITY
//! (proof kind + the class keys of what it verifies, the identity the
//! statics cache keys on), never under a position in one request's topology:
//! a second block shape served by the same install has different ordinals
//! for the same classes. `warm` publishes one gpu_native.ClassEntry per class
//! into the driver's ClassCache; each entry holds a counted pin on the class
//! statics (outer_job_prestage.ClassPin), released when the entry is
//! destroyed, so statics-cache eviction never frees a warmed class's plan.
//! `class_of` answers from the registry, so after `ClassCache.seal` a node of
//! an unplanned authority fails closed (GpuNativeClassNotWarmed) instead of
//! planning on the request path.
//!
//! Not landed (fail closed, error.M8GpuNativeRecursionNotLanded): `truth` and
//! `node` jobs, and the warm entry that registers the install-time class mix
//! (prestage/initWhole per class before Driver.install warms). They need the
//! device seed fill from the children's encoded slab regions, device
//! lookupSum / OODS checks and device om31 encoding; the node body itself is
//! today's OuterNodeJob (outer_job.zig).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

/// A counted reference on a class plan (outer_job_prestage.ClassPin in the
/// service; a counter in tests). `retain`/`release` are balanced.
pub const Pin = struct {
    ctx: *anyopaque,
    retain: *const fn (*anyopaque) void,
    release: *const fn (*anyopaque) void,
};

pub const ClassInfo = struct {
    /// Class plan (outer_job_prestage Statics.public), kept alive by `pin`.
    plan: *anyopaque,
    /// Counted reference that keeps `plan` alive; ownership of ONE reference
    /// moves to the registry with `register` (released at `deinit`). Null only
    /// for a plan the caller guarantees outlives the registry and every
    /// ClassCache it warms.
    pin: ?Pin = null,
    /// Upper bound of the class's encoded proof bytes (0: not yet measured).
    max_encoded_bytes: usize = 0,
    /// GPUs that hold this class's warm state (bit d = device d).
    devices: u8 = 0,
    /// Device words per GPU this class's statics hold (FIXED trees, tapes):
    /// reported to the memory plan through ClassEntry.held_words.
    held_words: [G.max_devices]u64 = @splat(0),
    arena_peak_words: usize = 0,
    cost_us: u64 = 1,
};

/// Authority digest of a recursion proof: kind + the class keys it verifies
/// (+ the ordinal for a truth, which names the truth statement kind).
pub fn authority(id: G.ProofId, children: []const G.ClassKey) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/m8/gpu-native/recursion-authority/v1\x00");
    h.update(&[_]u8{@intFromEnum(id.kind)});
    if (id.kind == .truth) h.update(std.mem.asBytes(&id.ordinal));
    h.update(std.mem.asBytes(&@as(u64, children.len)));
    for (children) |c| h.update(&c);
    return h.finalResult();
}

pub const Recursion = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoHashMapUnmanaged(G.ClassKey, Registered) = .empty,
    /// Authority digest -> class key.
    authorities: std.AutoHashMapUnmanaged([32]u8, G.ClassKey) = .empty,

    const Registered = struct { info: ClassInfo, phase_b: bool };

    pub fn deinit(self: *Recursion) void {
        var it = self.classes.valueIterator();
        while (it.next()) |r| if (r.info.pin) |p| p.release(p.ctx);
        self.classes.deinit(self.a);
        self.authorities.deinit(self.a);
    }
    /// Install: the recursion proof of kind `id.kind` verifying `children`
    /// (class keys, gpu_native.RecursionFactory.class_of order) is of class
    /// `key`. A class may be registered by many authorities; its info merges
    /// (largest encoded bound / peaks, union of devices). Re-registering an
    /// authority under another class is refused. Takes ownership of
    /// `info.pin` (one reference) on success, releases it on error.
    pub fn register(self: *Recursion, id: G.ProofId, children: []const G.ClassKey, key: G.ClassKey, info: ClassInfo) !void {
        errdefer if (info.pin) |p| p.release(p.ctx);
        if (id.kind == .request or id.kind == .native_segment) return error.GpuNativeNotARecursionProof;
        const auth = authority(id, children);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.classes.get(key)) |known| if (known.info.plan != info.plan) return error.GpuNativeClassPlanConflict;
        if (self.authorities.get(auth)) |known| if (!std.mem.eql(u8, &known, &key)) return error.GpuNativeProofClassChanged;
        try self.authorities.put(self.a, auth, key);
        const c = try self.classes.getOrPut(self.a, key);
        if (!c.found_existing) {
            c.value_ptr.* = .{ .info = info, .phase_b = id.kind == .fold or id.kind == .root };
            return;
        }
        const v = &c.value_ptr.info;
        v.max_encoded_bytes = @max(v.max_encoded_bytes, info.max_encoded_bytes);
        v.arena_peak_words = @max(v.arena_peak_words, info.arena_peak_words);
        v.cost_us = @max(v.cost_us, info.cost_us);
        for (&v.held_words, info.held_words) |*x, y| x.* = @max(x.*, y);
        v.devices |= info.devices;
        // A class that also runs as a fold/root is budgeted in phase B.
        c.value_ptr.phase_b = c.value_ptr.phase_b or id.kind == .fold or id.kind == .root;
        // The registry already holds this class's reference.
        if (info.pin) |p| p.release(p.ctx);
    }
    pub fn classCount(self: *Recursion) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.count();
    }

    pub fn factory(self: *Recursion) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.RecursionFactory.VTable{ .warm = warm, .class_of = classOf, .truth = truth, .node = node };
    fn of(raw: *anyopaque) *Recursion {
        return @ptrCast(@alignCast(raw));
    }

    /// A ClassEntry's plan: the class statics plus the entry's own pin.
    pub const Held = struct {
        a: std.mem.Allocator,
        plan: *anyopaque,
        pin: ?Pin,
    };
    const Build = struct {
        reg: Registered,
        fn build(raw: *anyopaque, a: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
            const self: *Build = @ptrCast(@alignCast(raw));
            const info = self.reg.info;
            const held = try a.create(Held);
            held.* = .{ .a = a, .plan = info.plan, .pin = info.pin };
            // The entry's own reference (the registry keeps its own).
            if (info.pin) |p| p.retain(p.ctx);
            return .{ .key = key, .plan = held, .destroy = destroyHeld, .max_encoded_bytes = info.max_encoded_bytes, .arena_peak_words = info.arena_peak_words, .cost_us = info.cost_us, .phase_b = self.reg.phase_b, .held_words = info.held_words };
        }
    };
    fn destroyHeld(raw: *anyopaque) void {
        const held: *Held = @ptrCast(@alignCast(raw));
        if (held.pin) |p| p.release(p.ctx);
        held.a.destroy(held);
    }
    /// The class statics behind a recursion ClassEntry's `plan`.
    pub fn planOf(entry: *const G.ClassEntry) *anyopaque {
        const held: *const Held = @ptrCast(@alignCast(entry.plan));
        return held.plan;
    }
    fn warm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.classes.iterator();
        while (it.next()) |kv| {
            var b = Build{ .reg = kv.value_ptr.* };
            const entry = try cache.warm(kv.key_ptr.*, .{ .ctx = &b, .build = Build.build });
            if (planOf(entry) != kv.value_ptr.info.plan) return error.GpuNativeClassPlanConflict;
        }
    }
    fn classOf(raw: *anyopaque, id: G.ProofId, children: []const G.ClassKey) anyerror!G.ClassKey {
        const self = of(raw);
        if (id.kind == .request or id.kind == .native_segment) return error.GpuNativeNotARecursionProof;
        const auth = authority(id, children);
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.authorities.get(auth) orelse error.GpuNativeClassNotWarmed;
    }
    fn truth(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn node(_: *anyopaque, _: *const G.RequestContext, _: G.ProofId, _: []const G.ProofId, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
};

const Counter = struct {
    refs: i32 = 0,
    fn retain(raw: *anyopaque) void {
        const c: *Counter = @ptrCast(@alignCast(raw));
        c.refs += 1;
    }
    fn release(raw: *anyopaque) void {
        const c: *Counter = @ptrCast(@alignCast(raw));
        c.refs -= 1;
    }
    fn pin(self: *Counter) Pin {
        self.refs += 1; // the reference `register` takes ownership of
        return .{ .ctx = self, .retain = retain, .release = release };
    }
};

test "recursion factory: unregistered authorities and non-recursion proofs fail closed" {
    var r = Recursion{ .a = std.testing.allocator };
    defer r.deinit();
    const f = r.factory();
    try std.testing.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 0 }, &.{@splat(1)}));
    try std.testing.expectError(error.GpuNativeNotARecursionProof, r.register(.{ .kind = .native_segment, .ordinal = 0 }, &.{}, @splat(1), .{ .plan = @ptrCast(&r) }));
}

test "recursion factory: classes are keyed by authority, not by topology ordinal" {
    const t = std.testing;
    var plan_leaf: u32 = 1;
    var plan_fold: u32 = 2;
    var c_leaf = Counter{};
    var c_fold = Counter{};
    var r = Recursion{ .a = t.allocator };
    const seg_a: G.ClassKey = @splat(0x51);
    const seg_b: G.ClassKey = @splat(0x52);
    const k_leaf_a: G.ClassKey = @splat(0xa);
    const k_leaf_b: G.ClassKey = @splat(0xb);
    const k_fold: G.ClassKey = @splat(0xf);
    // Block shape 1 registers leaf(seg class A) at ordinal 0 and leaf(seg
    // class B) at ordinal 1; shape 2 has them the other way round.
    try r.register(.{ .kind = .leaf, .ordinal = 0 }, &.{seg_a}, k_leaf_a, .{ .plan = @ptrCast(&plan_leaf), .pin = c_leaf.pin(), .max_encoded_bytes = 600_000 });
    try r.register(.{ .kind = .leaf, .ordinal = 1 }, &.{seg_b}, k_leaf_b, .{ .plan = @ptrCast(&plan_leaf), .pin = null, .max_encoded_bytes = 600_001 });
    try r.register(.{ .kind = .fold, .ordinal = 2 }, &.{ k_leaf_a, k_leaf_b }, k_fold, .{ .plan = @ptrCast(&plan_fold), .pin = c_fold.pin(), .max_encoded_bytes = 632_624 });
    try t.expectEqual(@as(usize, 3), r.classCount());
    const f = r.factory();
    // Shape 2: ordinal 0 verifies class B -> class B, whatever its ordinal.
    try t.expectEqualSlices(u8, &k_leaf_b, &try f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 0 }, &.{seg_b}));
    try t.expectEqualSlices(u8, &k_leaf_a, &try f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 7 }, &.{seg_a}));
    // Children order is part of the authority.
    try t.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, .{ .kind = .fold, .ordinal = 2 }, &.{ k_leaf_b, k_leaf_a }));
    // An authority cannot move to another class; a class cannot change its plan.
    try t.expectError(error.GpuNativeProofClassChanged, r.register(.{ .kind = .leaf, .ordinal = 5 }, &.{seg_a}, k_leaf_b, .{ .plan = @ptrCast(&plan_leaf) }));
    try t.expectError(error.GpuNativeClassPlanConflict, r.register(.{ .kind = .leaf, .ordinal = 9 }, &.{seg_b}, k_fold, .{ .plan = @ptrCast(&plan_leaf), .pin = c_fold.pin() }));
    try t.expectEqual(@as(i32, 1), c_fold.refs); // the refused pin was released

    var cache = G.ClassCache.init(t.allocator);
    try f.vtable.warm(f.ctx, &cache);
    try f.vtable.warm(f.ctx, &cache); // idempotent: no second build
    try t.expectEqual(@as(u64, 3), cache.builds);
    // Registry + cache entry each hold one reference (the class plan stays
    // alive however the statics cache evicts).
    try t.expectEqual(@as(i32, 2), c_leaf.refs);
    try t.expectEqual(@as(i32, 2), c_fold.refs);
    cache.seal();
    const e_fold = try cache.get(k_fold);
    try t.expect(e_fold.phase_b);
    try t.expect(!(try cache.get(k_leaf_a)).phase_b);
    try t.expectEqual(@as(*anyopaque, @ptrCast(&plan_fold)), Recursion.planOf(e_fold));
    // A class registered after the seal is never built on the request path.
    try r.register(.{ .kind = .fold, .ordinal = 7 }, &.{ k_leaf_a, k_leaf_a }, @splat(0xc), .{ .plan = @ptrCast(&plan_leaf) });
    try t.expectError(error.GpuNativeClassBuildOnRequestPath, f.vtable.warm(f.ctx, &cache));
    try t.expectError(error.GpuNativeClassNotWarmed, cache.get(@splat(0xc)));
    // The job entries are not landed and fail closed.
    try t.expectError(error.M8GpuNativeRecursionNotLanded, f.vtable.node(f.ctx, undefined, .{ .kind = .fold, .ordinal = 3 }, &.{}, 0));
    cache.deinit();
    try t.expectEqual(@as(i32, 1), c_leaf.refs);
    try t.expectEqual(@as(i32, 1), c_fold.refs);
    r.deinit();
    try t.expectEqual(@as(i32, 0), c_leaf.refs);
    try t.expectEqual(@as(i32, 0), c_fold.refs);
}
