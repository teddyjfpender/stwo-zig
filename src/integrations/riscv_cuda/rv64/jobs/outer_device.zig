//! Installed recursion authorities for the GPU-native request path.
//!
//! Registration keys classes by scoped authority, never request topology
//! position. Warm ClassCache entries hold their own counted class-plan pins;
//! sealed caches refuse construction during a request. Registration commits
//! authority/class entries together only after both maps reserve capacity.
//!
//! outer_node_job.zig owns construction, execution and custody of request
//! jobs, including two in-flight slab parities. The registry resolves the
//! installed class and delegates that ownership. After worker quiescence,
//! request bodies are destroyed before the registry releases class pins.
//! Truth production remains owned by truth_factory.zig.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Enc = @import("outer_encode.zig");
const Seed = @import("outer_seed_device.zig");
const Nodes = @import("outer_node_job.zig");
/// outer_kernels.zig Copy / lane and outer_checks.zig field_index, restated
/// (this file is in the driver's test root, which has no CUDA backend
/// module; outer_seed_harness_test.zig pins the restatement).
pub const Copy = Nodes.Copy;
pub const lookup_field_index = Nodes.lookup_field_index;

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
    /// With `encode_descriptor` it is at least the device encoder's class
    /// bound (outer_encode.maxEncodedBytes), so the slab entry holds it.
    max_encoded_bytes: usize = 0,
    /// Device encoder descriptor of the class (outer_encode.buildDescriptor
    /// over the class PCS framing), owned by the caller like `plan`.
    encode_descriptor: ?[]const u32 = null,
    /// GPUs that hold this class's warm state (bit d = device d).
    devices: u8 = 0,
    /// Device words per GPU this class's statics hold (FIXED trees, tapes):
    /// reported to the memory plan through ClassEntry.held_words.
    held_words: [G.max_devices]u64 = @splat(0),
    arena_peak_words: usize = 0,
    /// Install may require every use to follow native MAIN retirement.
    /// The request planner rejects a DAG that places this class in phase A.
    phase_b: bool = false,
    cost_us: u64 = 1,
    /// GPU-native node products of this class (null: not warmed for the
    /// GPU-native path; `node` fails closed with GpuNativeNodeClassMissing).
    node: ?*const NodeClass = null,
    extra_checks: []const G.Check = &.{},
};

// Public compatibility names refer to the request owner's contract.
pub const NodeClass = Nodes.NodeClass;
pub const Target = Nodes.Target;
pub const Made = Nodes.Made;
pub const Inputs = Nodes.Inputs;
pub const DeviceOps = Nodes.DeviceOps;
pub const NodeJob = Nodes.NodeJob;
pub const max_graph_devices = Nodes.max_graph_devices;

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
    /// Install/request planning scope. Different blocks can have the same
    /// physical child class and different exact leaf circuit authorities.
    scope: u64 = 0,
    /// GPU-native node job entry points (null: `node` fails closed).
    device: ?DeviceOps = null,
    /// The class `class_of` resolved for each recursion proof id of the
    /// request being planned (the driver plans, then makes, one request at
    /// a time: driver_request.zig plan -> make).
    planned: std.AutoHashMapUnmanaged(u64, G.ClassKey) = .empty,
    /// Per-request custody is separate from installed class registration.
    /// The request owner retains both slab parities until jobs settle.
    requests: Nodes.Requests = .{},

    const Registered = struct { info: ClassInfo, phase_b: bool };

    pub fn selectScope(self: *Recursion, scope: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.scope = scope;
    }
    fn scopedAuthority(self: *const Recursion, id: G.ProofId, children: []const G.ClassKey) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64/m8/recursion-block-authority/v1");
        hash.update(std.mem.asBytes(&self.scope));
        hash.update(&authority(id, children));
        return hash.finalResult();
    }

    pub fn deinit(self: *Recursion) void {
        // Bodies may borrow class statics in their destructors. Release all
        // quiescent request jobs before dropping the registry's class pins.
        self.requests.deinit(self.a);
        var it = self.classes.valueIterator();
        while (it.next()) |r| if (r.info.pin) |p| p.release(p.ctx);
        self.classes.deinit(self.a);
        self.authorities.deinit(self.a);
        self.planned.deinit(self.a);
    }
    /// After publication of `request` (its single wait returned): free its
    /// node jobs.
    pub fn end(self: *Recursion, request: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.requests.end(self.a, request);
    }
    /// Node jobs held (tests, receipts).
    pub fn heldJobs(self: *Recursion) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.requests.count();
    }
    fn idKey(id: G.ProofId) u64 {
        return (@as(u64, @intFromEnum(id.kind)) << 32) | id.ordinal;
    }
    /// Install: the recursion proof of kind `id.kind` verifying `children`
    /// (class keys, gpu_native.RecursionFactory.class_of order) is of class
    /// `key`. A class may be registered by many authorities; its info merges
    /// (largest encoded bound / peaks, union of devices). Re-registering an
    /// authority under another class is refused. Takes ownership of
    /// `info.pin` (one reference) on success, releases it on error.
    pub fn register(self: *Recursion, id: G.ProofId, children: []const G.ClassKey, key: G.ClassKey, info_in: ClassInfo) !void {
        errdefer if (info_in.pin) |p| p.release(p.ctx);
        var info = info_in;
        if (info.encode_descriptor) |d| {
            if (d.len < Enc.D.tables or d[Enc.D.magic] != Enc.descriptor_magic or d[Enc.D.words] != d.len) return error.GpuNativeEncodeDescriptorInvalid;
            info.max_encoded_bytes = @max(info.max_encoded_bytes, Enc.maxEncodedBytes(d));
        }
        if (id.kind == .request or id.kind == .native_segment) return error.GpuNativeNotARecursionProof;
        self.mutex.lock();
        defer self.mutex.unlock();
        const auth = self.scopedAuthority(id, children);
        if (self.classes.get(key)) |known| if (known.info.plan != info.plan) return error.GpuNativeClassPlanConflict;
        if (self.authorities.get(auth)) |known| if (!std.mem.eql(u8, &known, &key)) return error.GpuNativeProofClassChanged;
        // Reserve both maps before publishing either logical entry. A class
        // allocation failure must not leave an authority naming no class.
        if (!self.classes.contains(key)) try self.classes.ensureUnusedCapacity(self.a, 1);
        if (!self.authorities.contains(auth)) try self.authorities.ensureUnusedCapacity(self.a, 1);
        self.authorities.putAssumeCapacity(auth, key);
        const c = self.classes.getOrPutAssumeCapacity(key);
        if (!c.found_existing) {
            c.value_ptr.* = .{ .info = info, .phase_b = info.phase_b or id.kind == .fold or id.kind == .root };
            return;
        }
        const v = &c.value_ptr.info;
        v.max_encoded_bytes = @max(v.max_encoded_bytes, info.max_encoded_bytes);
        v.arena_peak_words = @max(v.arena_peak_words, info.arena_peak_words);
        v.cost_us = @max(v.cost_us, info.cost_us);
        for (&v.held_words, info.held_words) |*x, y| x.* = @max(x.*, y);
        v.devices |= info.devices;
        // A class that also runs as a fold/root is budgeted in phase B.
        c.value_ptr.phase_b = c.value_ptr.phase_b or info.phase_b or id.kind == .fold or id.kind == .root;
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
        node: ?*const NodeClass = null,
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
            held.node = info.node;
            return .{ .key = key, .plan = held, .destroy = destroyHeld, .max_encoded_bytes = info.max_encoded_bytes, .extra_checks = info.extra_checks, .arena_peak_words = info.arena_peak_words, .cost_us = info.cost_us, .phase_b = self.reg.phase_b, .held_words = info.held_words };
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
        self.mutex.lock();
        defer self.mutex.unlock();
        const auth = self.scopedAuthority(id, children);
        const key = self.authorities.get(auth) orelse return error.GpuNativeClassNotWarmed;
        if (id.kind != .truth) try self.planned.put(self.a, idKey(id), key);
        return key;
    }
    fn truth(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn node(raw: *anyopaque, rc: *const G.RequestContext, id: G.ProofId, children: []const G.ProofId, device: u32) anyerror!api.Job {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        const ops = self.device orelse return error.M8GpuNativeNodeDeviceUnbound;
        if (id.kind != .leaf and id.kind != .fold and id.kind != .root) return error.GpuNativeNotARecursionProof;
        // Reclaim settled jobs of earlier requests; a job of a request still
        // in flight (the other parity) stays until it settles or `end`.
        self.requests.reclaimSettled(self.a);
        const key = self.planned.get(idKey(id)) orelse return error.GpuNativeClassNotWarmed;
        const entry = try rc.classes.get(key);
        const nc = (@as(*const Held, @ptrCast(@alignCast(entry.plan)))).node orelse return error.GpuNativeNodeClassMissing;
        return self.requests.make(self.a, ops, nc, rc, id, children, device);
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

test "recursion teardown keeps class pins alive while request jobs are destroyed" {
    const t = std.testing;
    const Observe = struct {
        class: *Counter,
        refs_at_destroy: i32 = -1,
        fn destroy(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.refs_at_destroy = self.class.refs;
        }
    };
    var counter = Counter{};
    var observed = Observe{ .class = &counter };
    var recursion = Recursion{ .a = t.allocator };
    try recursion.register(.{ .kind = .leaf, .ordinal = 0 }, &.{}, @splat(9), .{ .plan = &counter, .pin = counter.pin() });
    const job = try t.allocator.create(NodeJob);
    // Teardown only invokes the body's destructor, after quiescence. No
    // device state or fake staging is required to check class custody.
    job.* = undefined;
    job.made = .{ .ctx = &observed, .destroy = Observe.destroy, .job = undefined, .inputs = undefined };
    _ = try recursion.requests.adopt(t.allocator, job);
    recursion.deinit();
    try t.expectEqual(@as(i32, 1), observed.refs_at_destroy);
    try t.expectEqual(@as(i32, 0), counter.refs);
}

test "failed recursion registration leaves no authority and returns its pin" {
    const Probe = struct {
        fn run(a: std.mem.Allocator) !void {
            var counter = Counter{};
            var r = Recursion{ .a = a };
            defer r.deinit();
            r.register(.{ .kind = .leaf, .ordinal = 0 }, &.{}, @splat(1), .{ .plan = &counter, .pin = counter.pin() }) catch |err| {
                try std.testing.expectEqual(@as(usize, 0), r.classCount());
                try std.testing.expectEqual(@as(usize, 0), r.authorities.count());
                try std.testing.expectEqual(@as(i32, 0), counter.refs);
                return err;
            };
            try std.testing.expectEqual(@as(usize, 1), r.classCount());
            try std.testing.expectEqual(@as(usize, 1), r.authorities.count());
            try std.testing.expectEqual(@as(i32, 1), counter.refs);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Probe.run, .{});
}

test "recursion factory: unregistered authorities and non-recursion proofs fail closed" {
    var r = Recursion{ .a = std.testing.allocator };
    defer r.deinit();
    const f = r.factory();
    try std.testing.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 0 }, &.{@splat(1)}));
    try std.testing.expectError(error.GpuNativeNotARecursionProof, r.register(.{ .kind = .native_segment, .ordinal = 0 }, &.{}, @splat(1), .{ .plan = @ptrCast(&r) }));
}

test "recursion planning selects the block authority for shared physical child classes" {
    const t = std.testing;
    var r = Recursion{ .a = t.allocator };
    defer r.deinit();
    var p0: u32 = 1;
    var p1: u32 = 2;
    const child: G.ClassKey = @splat(3);
    const k0: G.ClassKey = @splat(4);
    const k1: G.ClassKey = @splat(5);
    const id = G.ProofId{ .kind = .leaf, .ordinal = 0 };
    r.selectScope(10);
    try r.register(id, &.{child}, k0, .{ .plan = &p0 });
    r.selectScope(20);
    try r.register(id, &.{child}, k1, .{ .plan = &p1 });
    const f = r.factory();
    try t.expectEqualSlices(u8, &k1, &try f.vtable.class_of(f.ctx, id, &.{child}));
    r.selectScope(10);
    try t.expectEqualSlices(u8, &k0, &try f.vtable.class_of(f.ctx, id, &.{child}));
    r.selectScope(30);
    try t.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, id, &.{child}));
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
    // Without bound device entry points the node job fails closed.
    try t.expectError(error.M8GpuNativeNodeDeviceUnbound, f.vtable.node(f.ctx, undefined, .{ .kind = .fold, .ordinal = 3 }, &.{}, 0));
    cache.deinit();
    try t.expectEqual(@as(i32, 1), c_leaf.refs);
    try t.expectEqual(@as(i32, 1), c_fold.refs);
    r.deinit();
    try t.expectEqual(@as(i32, 0), c_leaf.refs);
    try t.expectEqual(@as(i32, 0), c_fold.refs);
}

test "recursion factory: the encoder descriptor sets the class's encoded bound" {
    const t = std.testing;
    var r = Recursion{ .a = t.allocator };
    defer r.deinit();
    var plan: u32 = 0;
    const logs = [_]u32{ 3, 4 };
    const cfg = Enc.Config{ .pow_bits = 1, .log_blowup = 1, .log_last_layer = 0, .n_queries = 8, .fold_step = 2, .lifting = null };
    const desc = try Enc.buildDescriptor(t.allocator, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 0, 1 }, .sample_counts = &.{ 1, 1 } }} }, null, null);
    defer t.allocator.free(desc);
    try r.register(.{ .kind = .leaf, .ordinal = 0 }, &.{@splat(1)}, @splat(7), .{ .plan = @ptrCast(&plan), .max_encoded_bytes = 4, .encode_descriptor = desc });
    var cache = G.ClassCache.init(t.allocator);
    defer cache.deinit();
    const f = r.factory();
    try f.vtable.warm(f.ctx, &cache);
    try t.expectEqual(Enc.maxEncodedBytes(desc), (try cache.get(@splat(7))).max_encoded_bytes);
    const bad = try t.allocator.dupe(u32, desc);
    defer t.allocator.free(bad);
    bad[Enc.D.magic] = 0;
    try t.expectError(error.GpuNativeEncodeDescriptorInvalid, r.register(.{ .kind = .leaf, .ordinal = 1 }, &.{@splat(2)}, @splat(8), .{ .plan = @ptrCast(&plan), .encode_descriptor = bad }));
}

// ---------------------------------------------------------------------------
// Host end-to-end test of the GPU-native node job (fake device: host memory,
// in-order immediate execution; the seed fill is the bit-exact host mirror)
// ---------------------------------------------------------------------------

const W = @import("worker.zig");
const fake = @import("fake.zig");
const Slab = @import("slab.zig");

const TestBody = struct {
    // The class's "whole-node job": allocates the node-region inputs in
    // stage, binds a slab with the lookup check field, and in enqueue (after
    // the seed fill ran) keeps a copy of what the device wrote.
    layout: Slab.ProofLayout = .{},
    seeds_words: usize,
    out_words: usize,
    seeds: api.DeviceBuffer = undefined,
    channel_seed: api.DeviceBuffer = undefined,
    outputs: api.DeviceBuffer = undefined,
    got_seeds: []u32 = &.{},
    got_cp: [9]u32 = @splat(0),
    got_out: [64]u32 = @splat(0),
    lookup_word: u32 = 0,
    channel_status: u32 = 0,
    a: std.mem.Allocator,
    finished: bool = false,
    pub fn classKey(_: *TestBody) [32]u8 {
        return @splat(0x77);
    }
    pub fn footprint(self: *TestBody) api.Footprint {
        const n = self.seeds_words + 64 + 64 + self.out_words + 64;
        return .{ .device_words = n, .staged_words = n, .slab_words = self.layout.words };
    }
    pub fn stage(self: *TestBody, s: *api.Stager) !void {
        self.seeds = try s.alloc(self.seeds_words);
        self.channel_seed = try s.alloc(9);
        self.outputs = try s.alloc(@max(self.out_words, 1));
    }
    pub fn enqueue(self: *TestBody, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const f = try e.slab.field(.opaque_words, lookup_field_index);
        f.ptr[0] = self.lookup_word;
        // A healthy device channel latch (the real body runs the transcript).
        e.channel.stateBuffer().ptr[10] = self.channel_status;
        if (self.got_seeds.len != 0) self.a.free(self.got_seeds);
        self.got_seeds = try self.a.dupe(u32, self.seeds.ptr[0..self.seeds_words]);
        @memcpy(&self.got_cp, self.channel_seed.ptr[0..9]);
        @memcpy(self.got_out[0..self.out_words], self.outputs.ptr[0..self.out_words]);
    }
    pub fn finish(self: *TestBody, _: api.SlabView) !void {
        self.finished = true;
    }
    pub fn abort(_: *TestBody) void {}
    fn inputs(raw: *anyopaque) anyerror!Inputs {
        const self: *TestBody = @ptrCast(@alignCast(raw));
        return .{ .seeds = self.seeds, .channel_seed = self.channel_seed, .outputs = .{ .ptr = self.outputs.ptr, .words = self.out_words } };
    }
    fn destroy(_: *anyopaque) void {}
    fn make(raw: *anyopaque, _: std.mem.Allocator, _: Target) anyerror!Made {
        const self: *TestBody = @ptrCast(@alignCast(raw));
        return .{ .job = api.Job.from(TestBody, self), .ctx = self, .inputs = inputs, .destroy = destroy };
    }
};
/// Fake seed fill: the host mirror on the fake device's host memory.
fn fakeFill(_: *anyopaque, _: u32, io: *const Seed.Io) callconv(.c) c_int {
    const prog = Seed.Program{ .words = @constCast(io.program[0..io.program_words]) };
    var regions: [Seed.max_children][]const u32 = undefined;
    for (0..io.n_children) |k| regions[k] = io.children[k].?[0..io.children_words[k]];
    const scratch = io.scratch[0..io.scratch_words];
    io.seed_status.* = Seed.fillHost(prog, regions[0..io.n_children], scratch, io.seeds[0..io.seeds_words]);
    if (io.bind_status) |b| {
        var cp: [9]u32 = undefined;
        b.* = Seed.statementHost(prog, regions[0..io.n_children], io.outputs.?[0..io.outputs_words], &cp);
        @memcpy(io.checkpoint.?[0..9], &cp);
    }
    return 0;
}
fn fakeD2d(_: *anyopaque, dst: *anyopaque, src: *const anyopaque, bytes: usize) callconv(.c) c_int {
    const d: [*]u8 = @ptrCast(dst);
    const s: [*]const u8 = @ptrCast(src);
    @memmove(d[0..bytes], s[0..bytes]);
    return 0;
}

test "gn-node: node job reads children from the request slab (own + peer GPU), fills seeds, writes verdict words" {
    const t = std.testing;
    const a = t.allocator;
    fake.reset();
    // Two leaf children: leaf 0 on GPU 0, leaf 1 on GPU 1; the fold on GPU 0.
    const wire_words: u32 = 128;
    var c0: Seed.Synthetic = undefined;
    try c0.init(a, 11, wire_words);
    defer c0.deinit(a);
    var c1: Seed.Synthetic = undefined;
    try c1.init(a, 12, wire_words);
    defer c1.deinit(a);
    const identity: Seed.Hash = @splat(0x1234);
    const profile: Seed.Hash = @splat(0xabcd);
    for ([_]*Seed.Synthetic{ &c0, &c1 }) |c| {
        c.region[1] = Seed.wire_magic[0];
        c.region[2] = Seed.wire_magic[1];
        @memcpy(c.region[3..11], &profile);
        @memcpy(c.region[11..19], &identity);
        c.region[19] = 2; // n_outputs
        for (c.region[20..28], 0..) |*w, i| w.* = @intCast(i + 1);
    }
    const L0 = try Seed.Layout.of(c0.shape);
    const fixed0: Seed.Hash = c0.image[L0.roots..][0..8].*;
    const fixed1: Seed.Hash = c1.image[L0.roots..][0..8].*;
    const classes = [_]Seed.ChildClass{
        .{ .shape = c0.shape, .wire_words = wire_words, .n_outputs = 2, .identity = identity, .fixed_root = fixed0 },
        .{ .shape = c1.shape, .wire_words = wire_words, .n_outputs = 2, .identity = identity, .fixed_root = fixed1 },
    };
    const tape = try Seed.tapeLength(&classes, 3, a);
    const vars = try a.alloc(u32, tape + 2);
    defer a.free(vars);
    for (vars, 0..) |*v, i| v.* = @intCast(7 + i);
    const constants = [_][4]u32{ .{ 1, 0, 0, 0 }, .{ 2, 0, 0, 0 } };
    const prog = try Seed.buildFold(a, &classes, 3, vars, &constants, .{ .domain = 0x4f464c31, .version_word = 2, .n_outputs = 8, .prefix = @splat(3), .identity = @splat(4), .fixed_root = @splat(5), .profile = profile });
    defer prog.deinit(a);
    // Expected device results (host mirror over the same regions).
    const want = try a.alloc(u32, 5 * vars.len);
    defer a.free(want);
    const scr = try a.alloc(u32, prog.header(Seed.P.scratch_words) + 8);
    defer a.free(scr);
    try t.expectEqual(@as(u32, 0), Seed.fillHost(prog, &.{ c0.region, c1.region }, scr, want));
    var want_out: [32]u32 = undefined;
    var want_cp: [9]u32 = undefined;
    try t.expectEqual(@as(u32, 0), Seed.statementHost(prog, &.{ c0.region, c1.region }, &want_out, &want_cp));

    // Request layout: leaves carry their region (len word + wire + image).
    const cap_bytes = 4 * (c0.region.len - 1);
    const specs = [_]G.ProofSpec{
        .{ .id = .{ .kind = .leaf, .ordinal = 0 }, .device = 0, .max_encoded_bytes = cap_bytes },
        .{ .id = .{ .kind = .leaf, .ordinal = 1 }, .device = 1, .max_encoded_bytes = cap_bytes },
        .{ .id = .{ .kind = .fold, .ordinal = 2 }, .device = 0, .max_encoded_bytes = 4096 },
    };
    const exch = G.Exchange{ .segments = 0, .claims_per_segment = 0, .devices = 2 };
    var layout = try G.RequestLayout.build(a, 2, &specs, exch);
    defer layout.deinit();
    var seg_mem: [2][]u32 = undefined;
    var segs: [2]api.DeviceBuffer = undefined;
    for (&seg_mem, &segs, layout.segments) |*m, *b, s| {
        m.* = try a.alloc(u32, s.words);
        @memset(m.*, G.Verdict.unset);
        b.* = .{ .ptr = m.ptr, .words = m.len };
    }
    defer for (seg_mem) |m| a.free(m);
    @memcpy((try layout.segments[0].encodedBuffer(segs[0], specs[0].id)).ptr[0..c0.region.len], c0.region);
    @memcpy((try layout.segments[1].encodedBuffer(segs[1], specs[1].id)).ptr[0..c1.region.len], c1.region);

    // The fold class: registered by authority, warmed with its NodeClass.
    var body = TestBody{ .a = a, .seeds_words = 5 * vars.len, .out_words = 32, .lookup_word = 0 };
    _ = try body.layout.add(.opaque_words, lookup_field_index, 2);
    defer if (body.got_seeds.len != 0) a.free(body.got_seeds);
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(prog.words), &key, .{});
    const nc = NodeClass{ .program = prog.words, .prog_key = key, .n_children = 2, .output_words = 32, .ctx = &body, .make = TestBody.make };
    var r = Recursion{ .a = a };
    defer r.deinit();
    var plan_word: u32 = 0;
    const leaf_key: G.ClassKey = @splat(0x11);
    const fold_key: G.ClassKey = @splat(0x22);
    try r.register(.{ .kind = .fold, .ordinal = 2 }, &.{ leaf_key, leaf_key }, fold_key, .{ .plan = @ptrCast(&plan_word), .node = &nc, .max_encoded_bytes = 4096 });
    var cache = G.ClassCache.init(a);
    defer cache.deinit();
    const f = r.factory();
    try f.vtable.warm(f.ctx, &cache);
    cache.seal();
    r.device = .{ .seed = .{ .fill = fakeFill }, .d2d = fakeD2d, .peer = fake.peer };
    const rc = G.RequestContext{ .request = 9, .layout = &layout, .exchange = exch, .peer = undefined, .classes = &cache, .segments = &segs };
    const fold_id = specs[2].id;
    // Unplanned (class_of not called for this request) -> fail closed.
    try t.expectError(error.GpuNativeClassNotWarmed, f.vtable.node(f.ctx, &rc, fold_id, &.{ specs[0].id, specs[1].id }, 0));
    _ = try f.vtable.class_of(f.ctx, fold_id, &.{ leaf_key, leaf_key });
    try t.expectError(error.GpuNativeNodeChildCount, f.vtable.node(f.ctx, &rc, fold_id, &.{specs[0].id}, 0));
    const job = try f.vtable.node(f.ctx, &rc, fold_id, &.{ specs[0].id, specs[1].id }, 0);
    // Pipelined parities: the next request makes its node job while this
    // request's job has not run yet; this request's job must stay alive.
    const rc_pipe = G.RequestContext{ .request = 11, .layout = &layout, .exchange = exch, .peer = undefined, .classes = &cache, .segments = &segs };
    const early = try f.vtable.node(f.ctx, &rc_pipe, fold_id, &.{ specs[0].id, specs[1].id }, 0);
    try t.expectEqual(@as(usize, 2), r.heldJobs());
    early.vtable.abort(early.ctx); // settles; reclaimed by a later node()

    const w = try W.Worker.create(a, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 16 });
    var done = std.Thread.ResetEvent{};
    var result: anyerror!void = {};
    const Sink = struct {
        done: *std.Thread.ResetEvent,
        result: *anyerror!void,
        fn onDone(raw: *anyopaque, c: api.Completion) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.result.* = c.result;
            self.done.set();
        }
    };
    var sink = Sink{ .done = &done, .result = &result };
    while (true) {
        w.submit(job, .{ .ctx = &sink, .done = Sink.onDone }) catch |err| switch (err) {
            error.WorkerBusy => continue,
            else => return err,
        };
        break;
    }
    done.wait();
    w.destroy();
    try result;
    try t.expect(body.finished);
    // Seeds, outputs and checkpoint came from the children's slab regions.
    try t.expectEqualSlices(u32, want, body.got_seeds);
    try t.expectEqualSlices(u32, want_out[0..32], body.got_out[0..32]);
    try t.expectEqualSlices(u32, &want_cp, &body.got_cp);
    // The peer child was copied once (GPU 1 -> GPU 0 node-local memory).
    try t.expectEqual(@as(usize, 1), fake.counters.peer_copies);
    try t.expectEqual(c1.region.len * 4, fake.counters.peer_bytes);
    // Verdict words in the fold's request-slab entry.
    const sl = &layout.segments[0];
    for ([_]G.Check{ .seed_tape, .child_binding, .lookup_sum, .channel_order }) |c| try t.expectEqual(G.Verdict.accepted, seg_mem[0][try sl.statusWord(fold_id, c)]);
    r.end(9);
    try t.expectEqual(@as(usize, 1), r.heldJobs()); // the settled pipelined job

    // Negatives on the next request: a corrupted peer child's Merkle path and
    // a bad device channel latch are refused in the request slab's words
    // (publish refuses the request); an unknown child fails at plan time.
    for (layout.segments, seg_mem) |sg, m| @memset(m[sg.status_offset..][0..sg.status_words], G.Verdict.unset);
    const r1 = try layout.segments[1].encodedBuffer(segs[1], specs[1].id);
    r1.ptr[wire_words + L0.trees[1].paths] ^= 1;
    body.channel_status = 7;
    const rc2 = G.RequestContext{ .request = 10, .layout = &layout, .exchange = exch, .peer = undefined, .classes = &cache, .segments = &segs };
    try t.expectError(error.GpuNativeUnknownProof, f.vtable.node(f.ctx, &rc2, fold_id, &.{ specs[0].id, .{ .kind = .leaf, .ordinal = 9 } }, 0));
    const job2 = try f.vtable.node(f.ctx, &rc2, fold_id, &.{ specs[0].id, specs[1].id }, 0);
    try t.expectEqual(@as(usize, 1), r.heldJobs()); // settled job reclaimed, job2 held
    const w2 = try W.Worker.create(a, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 16 });
    done.reset();
    while (true) {
        w2.submit(job2, .{ .ctx = &sink, .done = Sink.onDone }) catch |err| switch (err) {
            error.WorkerBusy => continue,
            else => return err,
        };
        break;
    }
    done.wait();
    w2.destroy();
    try result; // the job itself completes; the verdict words refuse it
    const seed_word = seg_mem[0][try sl.statusWord(fold_id, .seed_tape)];
    try t.expectEqual(G.Check.seed_tape, G.Verdict.checkOf(seed_word).?);
    try t.expectEqual(G.Check.channel_order, G.Verdict.checkOf(seg_mem[0][try sl.statusWord(fold_id, .channel_order)]).?);
    // publish() refuses on the first non-accepted word (header written as the driver does).
    for (layout.segments, seg_mem) |*sg, m| {
        try sg.prefix(m, 10);
        m[G.header_completion_word] = G.Exchange.flagTag(1);
    }
    var first: G.Rejection = undefined;
    const mirrors = [2][]const u32{ seg_mem[0], seg_mem[1] };
    try t.expectError(error.GpuNativeProofRejected, G.publish(a, &layout, 10, G.Exchange.flagTag(1), &mirrors, &first));
    r.end(10);
}
